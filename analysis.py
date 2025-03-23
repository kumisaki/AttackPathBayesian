# analysis.py
from flask import Blueprint, render_template, current_app
from extensions import mongo
import math

analysis_bp = Blueprint("analysis_bp", __name__)

@analysis_bp.route('/complex_attack_path')
def complex_attack_path():
    """
    Showing an interactive Cytoscape graph includes “subnet→device→vulnerability” three layer
    vulnerability is represented as circle、device is represented as triangle，subnet is surround the device triangle.
    """

    # example data
    subnets = [
        {
            "id": "subnet_public",
            "label": "Public (10.1.4.0/24)",
            "connected_subnets": ["subnet_private"],
            "devices": [
                {
                    "id": "device_webserver",
                    "label": "Web Server",
                    "ip_address": "10.1.4.10",
                    "os": "Ubuntu 18.04",
                    "vulnerabilities": [
                        {"vuln_id": "vuln_CVE_2019_0211", "desc": "Apache RCE", "prob": 0.8},
                        {"vuln_id": "vuln_CVE_2020_11947", "desc": "OpenSSL vuln", "prob": 0.5}
                    ]
                },
                {
                    "id": "device_honeypot",
                    "label": "Honeypot",
                    "ip_address": "10.1.4.9",
                    "os": "Kali Rolling",
                    "vulnerabilities": [
                        {"vuln_id": "vuln_Kali_Default", "desc": "Default root login", "prob": 0.6}
                    ]
                }
            ]
        },
        {
            "id": "subnet_private",
            "label": "Private (10.1.5.0/24)",
            "connected_subnets": ["subnet_public"],
            "devices": [
                {
                    "id": "device_dbserver",
                    "label": "DB Server",
                    "ip_address": "10.1.5.20",
                    "os": "Ubuntu 18.04",
                    "vulnerabilities": [
                        {"vuln_id": "vuln_CVE_2016_6662", "desc": "MySQL config vuln", "prob": 0.7}
                    ]
                },
                {
                    "id": "device_intranet",
                    "label": "Intranet App",
                    "ip_address": "10.1.5.11",
                    "os": "Windows 10",
                    "vulnerabilities": [
                        {"vuln_id": "vuln_SMBGhost", "desc": "SMB v3 RCE", "prob": 0.9},
                        {"vuln_id": "vuln_RDP_CVE_2020", "desc": "RDP exploit", "prob": 0.4}
                    ]
                }
            ]
        }
    ]

    # 2) construct Cytoscape elements: subnets, devices, vulnerabilities
    elements = []
    #   2.1) Subnet use compound parent or use individual node
    #        in this case：let "subnet_xxx" as parent, its devices as child node.
    #        compound node is not necessary, only draw subnet -> device edges.

    for sn in subnets:
        # subnet node
        elements.append({
            "data": {
                "id": sn["id"],
                "label": sn["label"],
            },
            "classes": "subnet"
        })
        # process connected_subnets => generate edge
        for nbr_id in sn.get("connected_subnets", []):
            # only generate on direction, or add a if to avoid repeat
            edge_id = f"{sn['id']}_to_{nbr_id}"
            elements.append({
                "data": {
                    "id": edge_id,
                    "source": sn["id"],
                    "target": nbr_id
                },
                "classes": "subnet_edge"
            })

        # 2.2) process devices
        for dev in sn["devices"]:
            dev_node_id = dev["id"]
            elements.append({
                "data": {
                    "id": dev_node_id,
                    "parent": sn["id"],   # compound node => parent = subnet
                    "label": dev["label"],
                    "ip": dev["ip_address"],
                    "os": dev["os"]
                },
                "classes": "device"
            })
            # 2.3) process vulnerability
            for vul in dev["vulnerabilities"]:
                vul_node_id = vul["vuln_id"]
                p = vul["prob"]
                elements.append({
                    "data": {
                        "id": vul_node_id,
                        "parent": dev_node_id,  # vulnerability在device内部
                        "label": vul["desc"],
                        "prob": p,
                        "vuln_id": vul["vuln_id"]
                    },
                    "classes": "vuln"
                })
                # edge also can be added: such as "vuln -> device compromised",
                # here shows directional edge between device-vulnerability (optional)
                edge_id = f"{vul_node_id}_to_{dev_node_id}"
                elements.append({
                    "data": {
                        "id": edge_id,
                        "source": vul_node_id,
                        "target": dev_node_id
                    },
                    "classes": "vuln_edge"
                })

    # 3) render template, and pass elements to front end
    return render_template('analysis_complex_path.html', elements=elements)
