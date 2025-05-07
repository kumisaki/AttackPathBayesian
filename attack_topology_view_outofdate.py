from flask import Blueprint, render_template, jsonify, session
from collections import defaultdict
from extensions import get_project_db

attack_topology_bp = Blueprint("attack_topology_bp", __name__)

@attack_topology_bp.route("/attack_topology_graph_page")
def attack_topology_graph_page():
    return render_template("attack_topology_graph.html")

@attack_topology_bp.route("/attack_topology_graph_data")
def attack_topology_graph_data():
    db = get_project_db(session.get("project_db"))
    devices = list(db.devices.find({}))
    firewall_rules = list(db.firewall_rules.find({}))

    from analysis import _bn_cache, _project_db
    model = _bn_cache.get(_project_db())

    elements = []
    device_map = {str(d["_id"]): d for d in devices}

    # Step 1: 遍历贝叶斯图中所有传播路径 deviceA → technique → deviceB
    devlink_techs = defaultdict(set)
    for src, tgt in model.edges:
        if src.startswith("compromised:") and tgt.startswith("technique:"):
            devA = src.split(":", 1)[1]
            tech = tgt.split(":", 1)[1]

            for tgt2 in model.successors(tgt):
                if tgt2.startswith("compromised:"):
                    devB = tgt2.split(":", 1)[1]
                    devlink_techs[(devA, devB)].add(tech)

    # Step 2: 加入 device 节点
    for d in devices:
        did = str(d["_id"])
        elements.append({
            "data": {"id": did, "label": d.get("label", did)},
            "classes": "device"
        })

    # Step 3: 加入拓扑边（基于 firewall_rules），附加攻击方法 label
    for rule in firewall_rules:
        src = rule.get("outbound")
        tgt = rule.get("inbound")
        if src in device_map and tgt in device_map:
            label = ", ".join(sorted(devlink_techs.get((src, tgt), [])))
            elements.append({
                "data": {
                    "id": f"{src}_to_{tgt}",
                    "source": src,
                    "target": tgt,
                    "label": label
                },
                "classes": "device_edge"
            })

    return jsonify({"elements": elements})
