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

@analysis_bp.route('/complex_attack_path')
def complex_attack_path():
    """
    Build an interactive compound graph using Cytoscape.js with three layers:
      - Subnets (compound nodes)
      - Devices (rectangular nodes, children of subnets)
      - Vulnerabilities (circular nodes, children of devices)
    Data is loaded from the MongoDB collections: subnets, devices, vulnerabilities.
    """
    subnets = load_subnets()
    devices = load_devices()
    vulns   = load_vulnerabilities()

    elements = []

    # Process subnets
    for s in subnets:
        subnet_id = str(s["_id"])
        subnet_label = s.get("label", subnet_id)
        elements.append({
            "data": {"id": subnet_id, "label": subnet_label},
            "classes": "subnet"
        })
        for other in s.get("connected_subnets", []):
            edge_id = f"{subnet_id}_to_{other}"
            elements.append({
                "data": {"id": edge_id, "source": subnet_id, "target": other},
                "classes": "subnet_edge"
            })

    # Process devices
    for d in devices:
        device_id = str(d["_id"])
        device_label = d.get("label", device_id)
        device_ip = d.get("ip_address", "")
        device_os = d.get("os", "")
        parent_subnet = d.get("parent_subnet", None)
        elements.append({
            "data": {"id": device_id, "parent": parent_subnet, "label": device_label, "ip": device_ip, "os": device_os},
            "classes": "device"
        })

    # Process vulnerabilities
    for v in vulns:
        vuln_id = str(v["_id"])
        vuln_desc = v.get("desc", vuln_id)
        vuln_prob = v.get("prob", 0.0)
        parent_device = v.get("parent_device_id", None)
        elements.append({
            "data": {"id": vuln_id, "parent": parent_device, "label": vuln_desc, "prob": vuln_prob, "vuln_id": vuln_id},
            "classes": "vuln"
        })
        if parent_device:
            edge_id = f"{vuln_id}_to_{parent_device}"
            elements.append({
                "data": {"id": edge_id, "source": vuln_id, "target": parent_device},
                "classes": "vuln_edge"
            })

    return render_template("analysis_complex_path.html", elements=elements)
