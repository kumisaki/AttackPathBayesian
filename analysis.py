# analysis.py
from flask import Blueprint, render_template, session, request, jsonify
from extensions import get_project_db, attack_reference
from collections import defaultdict
from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination

analysis_bp = Blueprint("analysis_bp", __name__)

bn_model_cache = None

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

@analysis_bp.route("/analysis_topology_graph")
def analysis_topology_graph():
    from collections import defaultdict
    import html

    # Load all raw data
    subnets = load_subnets()
    devices = load_devices()
    vulns = load_vulnerabilities()
    techniques = load_techniques()
    tactics = load_tactics()
    tech2tactic = load_technique_to_tactic()

    # Index for lookup
    subnet_ids = {str(s["_id"]): s for s in subnets}
    device_ids = {str(d["_id"]): d for d in devices}
    technique_map = {t["technique_id"]: t for t in techniques}
    tactic_map = {t["tactic_id"]: t for t in tactics}

    elements = []
    device_subnets = {}         # device_id → list of connected subnets
    device_connected_to = {}    # non-TCP device → TCP device
    device_rank_map = {}        # device_id → rank

    # Analyze device ranks & connections in single loop
    for d in devices:
        did = str(d["_id"])
        subnets_used = set()
        for iface in d.get("interfaces", []):
            if iface.get("interface_type") == "TCP/IP" and iface.get("subnet") in subnet_ids:
                subnets_used.add(iface["subnet"])
            elif iface.get("connected_to") in device_ids:
                device_connected_to[did] = iface["connected_to"]
        device_subnets[did] = list(subnets_used)

        if len(subnets_used) >= 2:
            device_rank_map[did] = 1  # gateway
        elif did in device_connected_to:
            device_rank_map[did] = 3  # non-TCP/IP
        else:
            device_rank_map[did] = 2  # regular

    # Collect all used ranks from all node types
    used_ranks = set(device_rank_map.values()) | {2, 4, 5, 6}

    # Add dynamic container nodes for ranks
    for r in sorted(used_ranks):
        elements.append({
            "data": {
                "id": f"rank_layer_{r}",
                "label": f"Layer {r}"
            },
            "classes": "rank_container"
        })

    # Add subnets
    for s in sorted(subnets, key=lambda x: x.get("label", "")):
        sid = str(s["_id"])
        elements.append({
            "data": {
                "id": sid,
                "label": s.get("label", sid),
                "CIDR": s.get("cidr", ""),
                "Zone": s.get("zone", ""),
                "parent": "rank_layer_2"
            },
            "classes": "subnet"
        })

    # Add devices
    for d in sorted(devices, key=lambda x: x.get("label", "")):
        did = str(d["_id"])
        rank = device_rank_map.get(did, 10)
        connected_subnets = device_subnets.get(did, [])
        parent_id = f"rank_layer_{rank}"

        # For regular devices with exactly one subnet and no TCP parent
        if rank == 2 and len(connected_subnets) == 1 and did not in device_connected_to:
            parent_id = connected_subnets[0]

        elements.append({
            "data": {
                "id": did,
                "label": d.get("label", did),
                "parent": parent_id
            },
            "classes": "device"
        })

    # Add device-to-device (non-TCP/IP)
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

    # Add device-to-subnet edges
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

    # Add vulnerabilities
    for v in sorted(vulns, key=lambda x: x.get("vuln_id", "")):
        vid = str(v["_id"])
        parent_device = v.get("parent_device_id", "")
        prob = v.get("prob", 0.0)
        elements.append({
            "data": {
                "id": vid,
                "label": html.escape(vid),
                "desc": html.escape(v.get("desc", "")),
                "prob": prob,
                "vuln_id": vid,
                "parent": "rank_layer_4"
            },
            "classes": "vuln"
        })
        elements.append({
            "data": {
                "id": f"{vid}_to_{parent_device}",
                "source": vid,
                "target": parent_device,
                "label": f"{prob:.2f}",
                "prob": prob
            },
            "classes": "vuln_edge"
        })

    # Collect technique and tactic IDs
    used_techniques = set()
    used_tactics = set()
    for v in vulns:
        for tid in v.get("attack_techniques", []):
            used_techniques.add(tid)
            tactic_id = tech2tactic.get(tid)
            if tactic_id:
                used_tactics.add(tactic_id)

            elements.append({
                "data": {"id": f"{v['_id']}_to_{tid}", "source": str(v["_id"]), "target": tid},
                "classes": "tech_edge"
            })
            if tactic_id:
                elements.append({
                    "data": {"id": f"{tid}_to_{tactic_id}", "source": tid, "target": tactic_id},
                    "classes": "tactic_edge"
                })

    # Add technique nodes (sorted)
    for tid in sorted(used_techniques, key=lambda x: technique_map.get(x, {}).get("technique_name", x)):
        elements.append({
            "data": {
                "id": tid,
                "label": technique_map.get(tid, {}).get("technique_name", tid),
                "parent": "rank_layer_5"
            },
            "classes": "technique"
        })

    # Add tactic nodes (sorted)
    for tactic_id in sorted(used_tactics, key=lambda x: tactic_map.get(x, {}).get("tactic_name", x)):
        elements.append({
            "data": {
                "id": tactic_id,
                "label": tactic_map.get(tactic_id, {}).get("tactic_name", tactic_id),
                "parent": "rank_layer_6"
            },
            "classes": "tactic"
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

    # Use temporary graph to avoid circuit
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

    # construct Bayesian network
    from pgmpy.models import DiscreteBayesianNetwork
    from pgmpy.factors.discrete import TabularCPD
    from utils.estimat_probabilities import estimate_parent_influence, compute_structural_probability

    model = DiscreteBayesianNetwork(final_edges)

    for node in model.nodes:
     # ---------------- Enhanced CPD Construction ---------------- #
        technique_to_tactic_map = load_technique_to_tactic()

        technique_score_map = {}
        for v in vulns:
            for tid in v.get("attack_techniques", []):
                cvss = float(v.get("cvss", 5.0))
                epss = float(v.get("epss", 0.0))
                score = min(1.0, (cvss / 10.0) * (0.5 + epss))
                technique_score_map[tid] = max(technique_score_map.get(tid, 0), score)

        def estimate_parent_influence(pid, ptype, siblings, vulnerabilities, score_map, tactic_map):
            if ptype == "device":
                vulns = [v for v in vulnerabilities if v.get("parent_device_id") == pid]
                tacs = set()
                for v in vulns:
                    for tid in v.get("attack_techniques", []):
                        tacs.add(tactic_map.get(tid))
                base_score = 0.6 + 0.1 * len(vulns)
            else:
                base_score = score_map.get(pid, 0.5)
                tacs = {tactic_map.get(pid)}

            overlap = 0
            for sib in siblings:
                if tacs & sib["tactics"]:
                    overlap += 1

            adjust = 0.15 * (len(siblings) - overlap) - 0.1 * overlap
            return min(1.0, max(0.05, base_score + adjust))

        for node in model.nodes:
            parents = list(model.get_parents(node))
            if not parents:
                if node.startswith("compromised:"):
                    dev_id = node.split(":")[1]
                    vulns_for_dev = [v for v in vulns if v.get("parent_device_id") == dev_id]
                    if vulns_for_dev:
                        probs = []
                        for v in vulns_for_dev:
                            cvss = float(v.get("cvss", 5.0))
                            epss = float(v.get("epss", 0.0))
                            p = min(1.0, (cvss / 10.0) * (0.5 + epss))
                            probs.append(p)
                        base_prob = max(probs)
                    else:
                        base_prob = 0.05
                else:
                    base_prob = 0.05
                cpd = TabularCPD(node, 2, [[base_prob], [1 - base_prob]])
                model.add_cpds(cpd)
            else:
                prob_true = []
                prob_false = []
                for i in range(2 ** len(parents)):
                    bits = list(map(int, format(i, f"0{len(parents)}b")))
                    parent_info = []
                    for j, p in enumerate(parents):
                        pid = p.split(":")[1]
                        ptype = "device" if p.startswith("compromised:") else "technique"
                        tacs = set()
                        if ptype == "device":
                            vulns = [v for v in load_vulnerabilities() if v.get("parent_device_id") == pid]
                            for v in vulns:
                                for tid in v.get("attack_techniques", []):
                                    tacs.add(technique_to_tactic_map.get(tid))
                        else:
                            tacs.add(technique_to_tactic_map.get(pid))
                        parent_info.append({"id": pid, "type": ptype, "tactics": tacs})

                    active_prob = 0.0
                    for j, bit in enumerate(bits):
                        if bit == 1:
                            p = parents[j]
                            pid = p.split(":")[1]
                            ptype = "device" if p.startswith("compromised:") else "technique"
                            prob = estimate_parent_influence(pid, ptype, parent_info[:j] + parent_info[j+1:], load_vulnerabilities(), technique_score_map, technique_to_tactic_map)
                            active_prob = max(active_prob, prob)

                    prob_true.append(active_prob)
                    prob_false.append(1 - active_prob)

                cpd = TabularCPD(
                    node, 2,
                    [prob_true, prob_false],
                    evidence=parents,
                    evidence_card=[2] * len(parents)
                )
                model.add_cpds(cpd)
        # ---------------------------------------------------------- #


    model.check_model()
    bn_model_cache = model

    # Collect edge probabilities for front-end
    edge_prob_map = {}
    for edge in model.edges:
        parent, child = edge
    from utils.estimat_probabilities import compute_structural_probability

    for edge in model.edges:
        parent, child = edge
        try:
            cpd = model.get_cpds(child)
            if parent in cpd.variables:
                idx = cpd.variables.index(parent)
                # 找出 CPD 中 parent=1 时的概率
                parent_idx = cpd.variables.index(parent)
                prob_array = cpd.values[0]
                if isinstance(prob_array, (list, tuple)):
                    edge_prob_map[edge] = round(prob_array[0], 3)
                else:
                    edge_prob_map[edge] = round(float(prob_array), 3)
        except:
            edge_prob_map[edge] = compute_structural_probability(
                parents=[parent],
                node=child,
                technique_score_map=technique_score_map,
                technique_to_tactic_map=technique_to_tactic_map,
                vulnerabilities=vulns
            )

    session["attack_graph"] = {
        "nodes": list(model.nodes),
        "edges": list(model.edges)
    }

    return jsonify({
        "nodes": list(model.nodes),
        "edges": list(model.edges),
        "edge_probs": {f"{src}→{tgt}": prob for (src, tgt), prob in edge_prob_map.items()}
    })

@analysis_bp.route('/node_search')
def node_search():
    q = request.args.get('q', '').lower()
    attack_graph = session.get('attack_graph', {})
    nodes = attack_graph.get('nodes', [])
    matched = [n for n in nodes if q in n.lower()]
    return jsonify(matched)


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
        evidence = {node: 1}
        result = {}
        for n in bn_model_cache.nodes:
            if n == node:
                continue
            q = infer.query(variables=[n], evidence=evidence, show_progress=False)
            prob = q.values[1] if hasattr(q, 'values') else 0
            result[n] = float(round(prob, 3))

        return jsonify({
            "probabilities": result,
            "highlight": sorted((k for k, v in result.items() if v > 0.5), key=lambda x: -result[x])
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# 在 analysis.py 中添加
def round_nested_values(data, precision=4):
    if isinstance(data, list):
        return [round_nested_values(item, precision) for item in data]
    else:
        try:
            return round(float(data), precision)
        except Exception:
            return data  # fallback: in case it's a string or something unexpected



@analysis_bp.route("/get_cpd/<node_id>")
def get_cpd(node_id):
    global bn_model_cache
    if not bn_model_cache:
        return jsonify({"error": "Model not loaded"}), 400

    try:
        cpd = bn_model_cache.get_cpds(node_id)
        raw_values = cpd.values.tolist()
        print(cpd, raw_values)
        # ✅ 使用递归处理所有嵌套浮点数
        values = round_nested_values(raw_values)

        response = {
            "variable": str(cpd.variable),
            "variables": [str(v) for v in cpd.variables],
            "cardinality": [int(c) for c in cpd.cardinality],
            "values": values
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500





