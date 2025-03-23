# analysis.py
from flask import Blueprint, render_template, current_app
from extensions import mongo
import math

analysis_bp = Blueprint("analysis_bp", __name__)

@analysis_bp.route('/complex_attack_path')
def complex_attack_path():
    """
    展示一个包含“子网→设备→漏洞”三层结构的交互式 Cytoscape 图。
    漏洞为圆形节点、设备为矩形节点、子网可作为更外层compound或普通节点。
    """

    # 1) 从数据库中查询或构造子网/设备/漏洞数据（这里演示手动构造）
    #   假设有两个子网: Public Subnet, Private Subnet
    #   每个子网下有若干设备; 每个设备包含若干漏洞(各自概率).
    #   真实项目中, 你可能实际: subnets = list(mongo.db.subnets.find()), ...
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

    # 2) 组装 Cytoscape elements: subnets, devices, vulnerabilities
    elements = []
    #   2.1) Subnet 用 compound parent or 用独立节点
    #        这里演示：让 "subnet_xxx" 作为 parent, 其 devices 作为 child node.
    #        也可不做 compound node, 只画 subnet -> device edges.

    for sn in subnets:
        # subnet node
        elements.append({
            "data": {
                "id": sn["id"],
                "label": sn["label"],
            },
            "classes": "subnet"
        })
        # 处理 connected_subnets => 画个 edge
        for nbr_id in sn.get("connected_subnets", []):
            # 只画单向, 或者加判断避免重复
            edge_id = f"{sn['id']}_to_{nbr_id}"
            elements.append({
                "data": {
                    "id": edge_id,
                    "source": sn["id"],
                    "target": nbr_id
                },
                "classes": "subnet_edge"
            })

        # 2.2) 处理 devices
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
            # 2.3) 处理漏洞 vulnerability
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
                # 也可添加 edge: "vuln -> device compromised" 之类,
                # 这里演示 device-漏洞 间的有向边 (可选)
                edge_id = f"{vul_node_id}_to_{dev_node_id}"
                elements.append({
                    "data": {
                        "id": edge_id,
                        "source": vul_node_id,
                        "target": dev_node_id
                    },
                    "classes": "vuln_edge"
                })

    # 3) 渲染模板, 并将 elements 传给前端
    return render_template('analysis_complex_path.html', elements=elements)
