# analysis.py
from flask import Blueprint, render_template, session
from extensions import get_project_db, attack_reference

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
    tactics = load_tactics()
    tech2tactic = load_technique_to_tactic()
    tactic_map = {t["tactic_id"]: t for t in tactics}

    elements = []
    subnet_ids = {str(s["_id"]): s for s in subnets}
    device_ids = {str(d["_id"]): d for d in devices}

    # Subnet Nodes
    for s in subnets:
        sid = str(s["_id"])
        elements.append({"data": {"id": sid, "label": s.get("label", sid)}, "classes": "subnet"})
        for connected_sid in s.get("connected_subnets", []):
            if connected_sid in subnet_ids:
                elements.append({
                    "data": {"id": f"{sid}_to_{connected_sid}", "source": sid, "target": connected_sid},
                    "classes": "subnet_edge"
                })

    # Device Nodes
    for d in devices:
        did = str(d["_id"])
        elements.append({
            "data": {
                "id": did,
                "label": d.get("label", did),
                "ip": d.get("ip_address", ""),
                "os": d.get("os", ""),
                "parent": d.get("parent_subnet", "")
            },
            "classes": "device"
        })
        elements.append({
            "data": {"id": f"{did}_to_{d.get('parent_subnet')}", "source": did, "target": d.get("parent_subnet")},
            "classes": "device_edge"
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
                "label": v.get("desc", vid),
                "prob": prob,
                "vuln_id": vid,
                "parent": parent_device
            },
            "classes": "vuln"
        })
        elements.append({
            "data": {"id": f"{vid}_to_{parent_device}", "source": vid, "target": parent_device},
            "classes": "vuln_edge"
        })

        # Techniques + Tactics
        technique_ids = v.get("attack_techniques", [])
        for tid in technique_ids:
            if tid not in added_techniques:
                elements.append({
                    "data": {"id": tid, "label": tid},
                    "classes": "technique"
                })
                added_techniques.add(tid)

            elements.append({
                "data": {"id": f"{vid}_to_{tid}", "source": vid, "target": tid},
                "classes": "tech_edge"
            })

            tactic_id = tech2tactic.get(tid)
            print(tech2tactic)
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
