# analysis.py
from flask import Blueprint, render_template, session, request, jsonify
from extensions import get_project_db, attack_reference
from collections import defaultdict
from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination

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

@analysis_bp.route('/analysis_topology_graph_page')
def analysis_topology_graph_page():
    return render_template("analysis_topology_graph.html")

@analysis_bp.route('/analysis_topology_graph')
def analysis_topology_graph():
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

    # 1️ Add subnet nodes (containers)
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

    # 2️ Map each device to the set of connected subnets
    device_subnets = {}
    device_connected_to = {}
    for d in devices:
        subnets_used = set()
        for iface in d.get("interfaces", []):
            if iface.get("interface_type") == "TCP/IP":
                if iface.get("subnet") in subnet_ids:
                    subnets_used.add(iface["subnet"])
            else:
                target_id = iface.get("connected_to")
                if target_id and target_id in device_ids:
                    # Don't use inferred subnet anymore
                    device_connected_to[d["_id"]] = target_id
        device_subnets[d["_id"]] = list(subnets_used)

    # 3️ Add device nodes
    for d in devices:
        did = str(d["_id"])
        connected_subnets = device_subnets.get(did, [])
        node_data = {
            "id": did,
            "label": d.get("label", did)
        }

        if len(connected_subnets) == 1 and did not in device_connected_to:
            node_data["parent"] = connected_subnets[0]  # only if not a No-TCP/IP dependent

        elements.append({
            "data": node_data,
            "classes": "device"
        })

    # 4 Add device->device (No-TCP/IP to TCP/IP)
    for child_id, parent_id in device_connected_to.items():
        if parent_id in device_ids:
            elements.append({
                "data": {
                    "id": f"{child_id}_to_{parent_id}",
                    "source": child_id,
                    "target": parent_id
                },
                "classes": "connection"
            })

    # 4 Add device → subnet edges
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

    return jsonify({"elements": elements})

@analysis_bp.route('/bayesian_attack_graph_page')
def bayesian_attack_graph_page():
    return render_template("bayesian_attack_graph.html")

@analysis_bp.route('/bayesian_attack_graph')
def bayesian_attack_graph():
    global bn_model_cache

    devices = load_devices()
    vulns = load_vulnerabilities()

    # 设备 → 技术 映射
    vulnerability_map = defaultdict(list)
    for v in vulns:
        dev_id = v.get("parent_device_id")
        if dev_id:
            for tid in v.get("attack_techniques", []):
                vulnerability_map[dev_id].append({"tech_id": tid})

    # 构建 subnet → device 映射
    subnet_map = defaultdict(list)
    for d in devices:
        did = d["_id"]
        for iface in d.get("interfaces", []):
            if subnet := iface.get("subnet"):
                subnet_map[subnet].append(did)

    # 拓扑结构（连接关系 + 同 subnet）
    topology = defaultdict(set)
    for d in devices:
        did = d["_id"]
        for iface in d.get("interfaces", []):
            if target := iface.get("connected_to"):
                topology[did].add(target)

    for device_ids in subnet_map.values():
        for i in range(len(device_ids)):
            for j in range(len(device_ids)):
                if i != j:
                    topology[device_ids[i]].add(device_ids[j])

    # ✅ 使用临时图防止循环
    import networkx as nx
    G_temp = nx.DiGraph()
    final_edges = []

    for d in devices:
        did = d["_id"]
        for vuln in vulnerability_map.get(did, []):
            tid = vuln["tech_id"]
            edge_1 = (f"compromised:{did}", f"technique:{tid}")

            G_temp.add_edge(*edge_1)
            if not nx.is_directed_acyclic_graph(G_temp):
                G_temp.remove_edge(*edge_1)
            else:
                final_edges.append(edge_1)

            for target_id in topology.get(did, []):
                edge_2 = (f"technique:{tid}", f"compromised:{target_id}")
                G_temp.add_edge(*edge_2)
                if not nx.is_directed_acyclic_graph(G_temp):
                    G_temp.remove_edge(*edge_2)
                else:
                    final_edges.append(edge_2)

    # 建立贝叶斯网络
    from pgmpy.models import DiscreteBayesianNetwork
    from pgmpy.factors.discrete import TabularCPD

    model = DiscreteBayesianNetwork(final_edges)

    for node in model.nodes:
        parents = list(model.get_parents(node))
        if not parents:
            cpd = TabularCPD(node, 2, [[0.05], [0.95]])
        else:
            card = [2] * len(parents)
            prob_true = [0.7] * (2 ** len(parents))
            prob_false = [0.3] * (2 ** len(parents))
            cpd = TabularCPD(node, 2, [prob_true, prob_false], evidence=parents, evidence_card=card)
        model.add_cpds(cpd)

    model.check_model()
    bn_model_cache = model

    # Collect edge probabilities for front-end
    edge_prob_map = {}
    for edge in model.edges:
        parent, child = edge
        try:
            cpd = model.get_cpds(child)
            if parent in cpd.variables:
                idx = cpd.variables.index(parent)
                prob = cpd.get_values()[0]  # Prob(true)
                edge_prob_map[edge] = round(prob[0], 3) if isinstance(prob, list) else round(float(prob), 3)
        except:
            edge_prob_map[edge] = 0.7  # fallback

    session["attack_graph"] = {
        "nodes": list(model.nodes),
        "edges": list(model.edges)
    }

    return jsonify({
        "nodes": list(model.nodes),
        "edges": list(model.edges),
        "edge_probs": {f"{src}→{tgt}": prob for (src, tgt), prob in edge_prob_map.items()}
    })

@analysis_bp.route('/infer_probability')
def infer_probability():
    global bn_model_cache
    if not bn_model_cache:
        return jsonify({"error": "Model not ready"}), 400
    node = request.args.get("observe")
    if not node:
        return jsonify({"error": "Missing observe param"}), 400

    try:
        infer = VariableElimination(bn_model_cache)
        evidence = {node: 1}  # observed as true
        result = {}
        for n in bn_model_cache.nodes:
            q = infer.query(variables=[n], evidence=evidence, show_progress=False)
            prob = q.values[1] if hasattr(q, 'values') else 0
            result[n] = float(round(prob, 3))
        return jsonify({
        "probabilities": result,
        "highlight": sorted((k for k, v in result.items() if v > 0.5), key=lambda x: -result[x])
    })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
