# analysis.py
from flask import Blueprint, render_template, session
from extensions import get_project_db, attack_reference
from collections import defaultdict

analysis_bp = Blueprint("analysis_bp", __name__)

def load_subnets():
    return list(get_project_db(session["project_db"]).subnets.find({}))

def load_devices():
    return list(get_project_db(session["project_db"]).devices.find({}))

def load_vulnerabilities():
    return list(get_project_db(session["project_db"]).vulnerabilities.find({}))

def load_techniques():
    return list(attack_reference.techniques.find({}))

def load_tactics():
    return list(attack_reference.tactics.find({}))

def load_technique_to_tactic():
    mappings = list(attack_reference.techniques_to_tactics.find({}))
    return {m["technique_id"]: m["tactic_id"] for m in mappings if "technique_id" in m and "tactic_id" in m}

@analysis_bp.route('/complex_attack_path')
def complex_attack_path():
    subnets = load_subnets()
    devices = load_devices()
    vulns = load_vulnerabilities()
    techniques = load_techniques()
    technique_map = {t["technique_id"]: t for t in techniques}
    tactics = load_tactics()
    tech2tactic = load_technique_to_tactic()
    tactic_map = {t["tactic_id"]: t for t in tactics}

    elements = []

    subnet_ids = {str(s["_id"]): s for s in subnets}
    device_ids = {str(d["_id"]): d for d in devices}

    # 1️⃣ Add subnet nodes (containers)
    for s in subnets:
        sid = str(s["_id"])
        cidr = s.get("cidr", "")
        zone = s.get("zone", "")
        elements.append({
            "data": {
                "id": sid,
                "label": s.get("label", sid),
                "CIDR": cidr,
                "Zone": zone
                },
            "classes": "subnet"
        })

    # 2️⃣ Map each device to the set of connected subnets
    device_subnets = {}
    for d in devices:
        subnets_used = {
            iface.get("subnet") for iface in d.get("interfaces", [])
            if iface.get("subnet") in subnet_ids
        }
        device_subnets[d["_id"]] = list(subnets_used)

    # 3️⃣ Add device nodes
    for d in devices:
        did = str(d["_id"])
        connected_subnets = device_subnets.get(did, [])

        node_data = {
            "id": did,
            "label": d.get("label", did)
        }

        # If only one subnet, nest device inside that subnet
        if len(connected_subnets) == 1:
            node_data["parent"] = connected_subnets[0]

        elements.append({
            "data": node_data,
            "classes": "device"
        })

    # 4️⃣ Add device → subnet edges
    for d in devices:
        did = str(d["_id"])
        for iface in d.get("interfaces", []):
            sid = iface.get("subnet")
            if sid and sid in subnet_ids:
                elements.append({
                    "data": {
                        "id": f"{did}_to_{sid}",
                        "source": did,
                        "target": sid
                    },
                    "classes": "device_subnet_edge"
                })

    # Vulnerability Nodes
    added_techniques = set()
    added_tactics = set()

    for v in vulns:
        vid = str(v["_id"])
        parent_device = v.get("parent_device_id", "")
        prob = v.get("prob", 0.0)
        elements.append({
            "data": {
                "id": vid,
                "label": vid,
                "desc": v.get("desc", vid),
                "prob": prob,
                "vuln_id": vid,
            },
            "classes": "vuln"
        })
        elements.append({
            "data": {
                "id": f"{vid}_to_{parent_device}",
                "source": vid,
                "target": parent_device,
                "prob": prob,
                "label": f"{prob: .2f}"
                },
            "classes": "vuln_edge"
        })

        # Techniques + Tactics
        technique_ids = v.get("attack_techniques", [])
        for tid in technique_ids:
        
            if tid not in added_techniques:
                tech_info = technique_map.get(tid, {})
                label = tech_info.get("technique_name", "")
                elements.append({
                    "data": {
                        "id": tid,
                        "label": label
                        },
                    "classes": "technique"
                })
                added_techniques.add(tid)

            elements.append({
                "data": {"id": f"{vid}_to_{tid}", "source": vid, "target": tid},
                "classes": "tech_edge"
            })

            tactic_id = tech2tactic.get(tid)
            if tactic_id and tactic_id not in added_tactics:
                label = tactic_map.get(tactic_id, {}).get("tactic_name", tactic_id)
                elements.append({
                    "data": {"id": tactic_id, "label": label},
                    "classes": "tactic"
                })
                added_tactics.add(tactic_id)

            if tactic_id:
                elements.append({
                    "data": {"id": f"{tid}_to_{tactic_id}", "source": tid, "target": tactic_id},
                    "classes": "tactic_edge"
                })

    return render_template("analysis_complex_path.html", elements=elements)
