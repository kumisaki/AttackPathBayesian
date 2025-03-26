# analysis.py
from flask import Blueprint, render_template
from extensions import mongo

analysis_bp = Blueprint("analysis_bp", __name__)

def load_subnets():
    subnets_cursor = mongo.db.subnets.find({})
    return list(subnets_cursor)

def load_devices():
    devices_cursor = mongo.db.devices.find({})
    return list(devices_cursor)

def load_vulnerabilities():
    vulns_cursor = mongo.db.vulnerabilities.find({})
    return list(vulns_cursor)

def load_techniques():
    return list(mongo.db.techniques.find({}))

def load_tactics():
    return list(mongo.db.tactics.find({}))

def load_technique_to_tactic():
    mappings = list(mongo.db.techniques_to_tactics.find({}))
    return {m["technique_id"]: m["tactic_id"] for m in mappings if "technique_id" in m and "tactic_id" in m}

@analysis_bp.route('/complex_attack_path')
def complex_attack_path():
    subnets = load_subnets()
    devices = load_devices()
    vulns   = load_vulnerabilities()
    techniques = load_techniques()
    tactics = load_tactics()
    tech2tactic = load_technique_to_tactic()
    tactic_map = {t["tactic_id"]: t for t in tactics}

    # Add technique nodes and edges from vulnerabilities
    added_techniques = set()
    added_tactics = set()

    elements = []
    subnet_ids = {str(s["_id"]): s for s in subnets}
    device_ids = {str(d["_id"]): d for d in devices}

    # Subnet Nodes
    for s in subnets:
        sid = str(s["_id"])
        label = s.get("label", sid)
        elements.append({
            "data": {"id": sid, "label": label},
            "classes": "subnet"
        })
        # Connect subnets
        for connected_sid in s.get("connected_subnets", []):
            if connected_sid in subnet_ids:  # ensure target exists
                elements.append({
                    "data": {"id": f"{sid}_to_{connected_sid}", "source": sid, "target": connected_sid},
                    "classes": "subnet_edge"
                })

    # Device Nodes
    for d in devices:
        did = str(d["_id"])
        label = d.get("label", did)
        parent_subnet = d.get("parent_subnet", "")
        elements.append({
            "data": {
                "id": did,
                "label": label,
                "ip": d.get("ip_address", ""),
                "os": d.get("os", ""),
                "parent": parent_subnet
            },
            "classes": "device"
        })
        # Edge (optional if you want visual link)
        elements.append({
            "data": {"id": f"{did}_to_{parent_subnet}", "source": did, "target": parent_subnet},
            "classes": "device_edge"
        })

    # Vulnerability Nodes
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
        # Edge (optional if you want visual link)
        elements.append({
            "data": {"id": f"{vid}_to_{parent_device}", "source": vid, "target": parent_device},
            "classes": "vuln_edge"
        })

    return render_template("analysis_complex_path.html", elements=elements)

