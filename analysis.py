from __future__ import annotations

from collections import defaultdict
from html import escape as _esc
from typing import Any, Dict, List

import networkx as nx
from flask import Blueprint, jsonify, render_template, request, session
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination
from pgmpy.models import DiscreteBayesianNetwork
import numpy as np

from extensions import attack_reference, get_project_db
from utils.estimat_probabilities import (
    compute_structural_probability,
    estimate_parent_influence,
)

analysis_bp = Blueprint("analysis_bp", __name__)

# ---------------------------------------------------------------------------
# In-memory cache (per worker).  For multi-worker deployments, back it with
# Redis or disk if necessary.
# ---------------------------------------------------------------------------
_bn_cache: dict[str, DiscreteBayesianNetwork] = {}

# ---------------------------------------------------------------------------
# Mongo helpers
# ---------------------------------------------------------------------------
def _project_db() -> str:
    db = session.get("project_db")
    if not db:
        raise KeyError("project_db missing from session")
    return db


def load_subnets() -> List[Dict[str, Any]]:
    return list(get_project_db(_project_db()).subnets.find({}))


def load_devices() -> List[Dict[str, Any]]:
    return list(get_project_db(_project_db()).devices.find({}))

def load_firewall_rules() -> List[Dict[str, Any]]:
    return list(get_project_db(_project_db()).firewall_rules.find({}))

def load_vulnerabilities() -> List[Dict[str, Any]]:
    return list(get_project_db(_project_db()).vulnerabilities.find({}))

def load_techniques() -> List[Dict[str, Any]]:
    return list(attack_reference.techniques.find({}))

def load_tactics() -> List[Dict[str, Any]]:
    return list(attack_reference.tactics.find({}))

def load_technique_to_tactic() -> Dict[str, str]:
    mappings = attack_reference.techniques_to_tactics.find({})
    return {m["technique_id"]: m["tactic_id"] for m in mappings}

def load_tactic_chain() -> List[Dict[str, Any]]:
    return list(attack_reference.tactic_chain.find({}))


# ---------------------------------------------------------------------------
# Topology visualisation routes
# ---------------------------------------------------------------------------
@analysis_bp.route("/analysis_topology_graph_page")
def analysis_topology_graph_page():
    return render_template("analysis_topology_graph.html")


@analysis_bp.route("/analysis_topology_graph")
def analysis_topology_graph():
    # --- Load once ----------------------------------------------------------
    subnets = load_subnets()
    devices = load_devices()
    vulns = load_vulnerabilities()
    techniques = load_techniques()
    tactics = load_tactics()
    tech2tactic = load_technique_to_tactic()

    # --- Indexes ------------------------------------------------------------
    subnet_ids = {str(s["_id"]): s for s in subnets}
    device_ids = {str(d["_id"]): d for d in devices}
    technique_map = {t["technique_id"]: t for t in techniques}
    tactic_map = {t["tactic_id"]: t for t in tactics}

    elements: List[Dict[str, Any]] = []
    device_subnets: dict[str, list[str]] = {}
    device_connected_to: dict[str, str] = {}
    device_rank_map: dict[str, int] = {}

    # --- Determine device ranks & links ------------------------------------
    for d in devices:
        did = str(d["_id"])
        used: set[str] = set()
        for iface in d.get("interfaces", []):
            if (
                iface.get("interface_type") == "TCP/IP"
                and iface.get("subnet") in subnet_ids
            ):
                used.add(iface["subnet"])
            elif iface.get("connected_to") in device_ids:
                device_connected_to[did] = iface["connected_to"]
        device_subnets[did] = list(used)

        if len(used) >= 2:
            device_rank_map[did] = 1  # gateway
        elif did in device_connected_to:
            device_rank_map[did] = 3  # non-TCP/IP leaf
        else:
            device_rank_map[did] = 2  # normal device

    used_ranks = set(device_rank_map.values()) | {2, 4, 5, 6}

    for r in sorted(used_ranks):
        elements.append(
            {"data": {"id": f"rank_layer_{r}", "label": f"Layer {r}"}, "classes": "rank_container"}
        )

    # --- Subnets ------------------------------------------------------------
    for s in sorted(subnets, key=lambda x: x.get("label", "")):
        sid = str(s["_id"])
        elements.append(
            {
                "data": {
                    "id": sid,
                    "label": _esc(s.get("label", sid)),
                    "CIDR": s.get("cidr", ""),
                    "Zone": s.get("zone", ""),
                    "parent": "rank_layer_2",
                },
                "classes": "subnet",
            }
        )

    # --- Devices ------------------------------------------------------------
    for d in sorted(devices, key=lambda x: x.get("label", "")):
        did = str(d["_id"])
        rank = device_rank_map.get(did, 10)
        parent_id = (
            device_subnets[did][0]
            if rank == 2 and len(device_subnets[did]) == 1 and did not in device_connected_to
            else f"rank_layer_{rank}"
        )

        elements.append(
            {
                "data": {"id": did, "label": _esc(d.get("label", did)), "parent": parent_id},
                "classes": "device",
            }
        )

    # --- Device↔device edges -------------------------------------------------
    for child_id, parent_id in device_connected_to.items():
        elements.append(
            {
                "data": {"id": f"{child_id}_to_{parent_id}", "source": child_id, "target": parent_id},
                "classes": "connection",
            }
        )

    # --- Device↔subnet edges -------------------------------------------------
    for d in devices:
        did = str(d["_id"])
        for iface in d.get("interfaces", []):
            sid = iface.get("subnet")
            if sid and sid in subnet_ids:
                elements.append(
                    {
                        "data": {"id": f"{did}_to_{sid}", "source": did, "target": sid},
                        "classes": "device_subnet_edge",
                    }
                )

    # --- Vulnerabilities ----------------------------------------------------
    for v in sorted(vulns, key=lambda x: x.get("vuln_id", "")):
        vid = str(v["_id"])
        parent_dev = v.get("parent_device_id", "")
        prob = float(v.get("prob", 0.0))
        elements.extend(
            [
                {
                    "data": {
                        "id": vid,
                        "label": _esc(vid),
                        "desc": _esc(v.get("desc", "")),
                        "prob": prob,
                        "vuln_id": vid,
                        "parent": "rank_layer_4",
                    },
                    "classes": "vuln",
                },
                {
                    "data": {
                        "id": f"{vid}_to_{parent_dev}",
                        "source": vid,
                        "target": parent_dev,
                        "label": f"{prob:.2f}",
                        "prob": prob,
                    },
                    "classes": "vuln_edge",
                },
            ]
        )

    # --- Techniques & tactics ----------------------------------------------
    used_techniques: set[str] = set()
    used_tactics: set[str] = set()

    for v in vulns:
        for tid in v.get("attack_techniques", []):
            used_techniques.add(tid)
            if (tac := tech2tactic.get(tid)):
                used_tactics.add(tac)

            elements.append(
                {
                    "data": {"id": f"{v['_id']}_to_{tid}", "source": str(v["_id"]), "target": tid},
                    "classes": "tech_edge",
                }
            )
            if tac:
                elements.append(
                    {
                        "data": {"id": f"{tid}_to_{tac}", "source": tid, "target": tac},
                        "classes": "tactic_edge",
                    }
                )

    for tid in sorted(used_techniques, key=lambda x: technique_map.get(x, {}).get("technique_name", x)):
        elements.append(
            {
                "data": {
                    "id": tid,
                    "label": _esc(technique_map.get(tid, {}).get("technique_name", tid)),
                    "parent": "rank_layer_5",
                },
                "classes": "technique",
            }
        )

    for tac in sorted(used_tactics, key=lambda x: tactic_map.get(x, {}).get("tactic_name", x)):
        elements.append(
            {
                "data": {
                    "id": tac,
                    "label": _esc(tactic_map.get(tac, {}).get("tactic_name", tac)),
                    "parent": "rank_layer_6",
                },
                "classes": "tactic",
            }
        )

    return jsonify({"elements": elements})


# ---------------------------------------------------------------------------
# Bayesian attack graph routes
# ---------------------------------------------------------------------------
@analysis_bp.route("/bayesian_attack_graph_page")
def bayesian_attack_graph_page():
    return render_template("bayesian_attack_graph.html")

@analysis_bp.route("/clear_attack_graph_cache")
def clear_attack_graph_cache():
    _bn_cache.clear()
    return "Attack graph cache cleared.", 200

@analysis_bp.route("/bayesian_attack_graph")
def bayesian_attack_graph():
    project = _project_db()
    # if project not in _bn_cache:
    #     _bn_cache[project] = _build_bayesian_model()
    _bn_cache[project] = _build_bayesian_model()
    model = _bn_cache[project]
    print(model)
    # 计算每条边的传播概率
    edge_prob_map: dict[tuple[str, str], float] = {}
    for parent, child in model.edges:
        try:
            cpd = model.get_cpds(child)
            if parent not in cpd.variables:
                edge_prob_map[(parent, child)] = 0.0
                continue
            reduced = cpd.reduce([(parent, 1)], inplace=False)
            true_state_index = list(reduced.state_names[child]).index(1)
            prob_true = float(np.asarray(reduced.values[true_state_index]).mean())
            edge_prob_map[(parent, child)] = round(prob_true, 3)
        except Exception:
            edge_prob_map[(parent, child)] = 0.0

    # 保存 graph 结构到 session
    session["attack_graph"] = {"nodes": list(model.nodes), "edges": list(model.edges)}

    devices = load_devices()
    techniques = load_techniques()

    device_map = {str(d["_id"]): d.get("label", str(d["_id"])) for d in devices}
    technique_map = {t["technique_id"]: t.get("technique_name", t["technique_id"]) for t in techniques}

    node_info = []
    for n in model.nodes:
        label = n.split(":", 1)[1]
        if n.startswith("compromised:"):
            label = device_map.get(label, label)
        elif n.startswith("technique:"):
            label = technique_map.get(label, label)
        node_info.append({"id": n, "label": label})

    return jsonify({
        "nodes": node_info,
        "edges": list(model.edges),
        "edge_probs": {f"{src}→{tgt}": p for (src, tgt), p in edge_prob_map.items()},
    })

def _build_bayesian_model() -> DiscreteBayesianNetwork:
    devices = load_devices()
    vulns = load_vulnerabilities()
    firewall_rules = load_firewall_rules()
    tech2tactic = load_technique_to_tactic()
    tactics_chain = load_tactic_chain()
    tactics_order = _build_tactic_order(tactics_chain)

    device_ids = {str(d["_id"]) for d in devices}
    device_info = {str(d["_id"]): d for d in devices}

    # Build topology from firewall rules
    topology: dict[str, set[str]] = defaultdict(set)
    for rule in firewall_rules:
        src = rule.get("outbound")
        tgt = rule.get("inbound")
        if src in device_ids and tgt in device_ids:
            topology[src].add(tgt)

    # Build device -> techniques mapping
    device_techniques: dict[str, set[str]] = defaultdict(set)
    for v in vulns:
        dev = v.get("parent_device_id")
        if dev:
            for tid in v.get("attack_techniques", []):
                device_techniques[dev].add(tid)

    G_tmp = nx.DiGraph()
    edges = []

    active_devices = set()
    activated_techniques = defaultdict(set)

    # Step 1: Initial Access → compromised:device
    for dev, techs in device_techniques.items():
        for tid in techs:
            tactic = tech2tactic.get(tid)
            if tactic and tactic in {"TA0001", "TA0108"}:  # Enterprise or ICS Initial Access
                edge = (f"technique:{tid}", f"compromised:{dev}")
                G_tmp.add_edge(*edge)
                if nx.is_directed_acyclic_graph(G_tmp):
                    edges.append(edge)
                    active_devices.add(dev)
                    activated_techniques[dev].add(tid)
                else:
                    G_tmp.remove_edge(*edge)

    # Step 2: Recursively expand
    queue = list(active_devices)
    while queue:
        dev = queue.pop(0)

        # Step 2.1: compromised:device ➔ techniques (activation)
        for tid in device_techniques.get(dev, []):
            edge = (f"compromised:{dev}", f"technique:{tid}")
            G_tmp.add_edge(*edge)
            if nx.is_directed_acyclic_graph(G_tmp):
                edges.append(edge)
                activated_techniques[dev].add(tid)
            else:
                G_tmp.remove_edge(*edge)

        current_techs = activated_techniques[dev]

        # Step 2.2: techniques ➔ techniques (internal progression)
        for tid1 in current_techs:
            tactic1 = tech2tactic.get(tid1)
            for tid2 in device_techniques.get(dev, []):
                tactic2 = tech2tactic.get(tid2)
                if tactic1 and tactic2 and _tactic_can_progress(tactic1, tactic2, tactics_order):
                    edge = (f"technique:{tid1}", f"technique:{tid2}")
                    G_tmp.add_edge(*edge)
                    if nx.is_directed_acyclic_graph(G_tmp):
                        edges.append(edge)
                    else:
                        G_tmp.remove_edge(*edge)

        # Step 2.3: lateral movement (technique ➔ compromised:other_device)
        for tid in current_techs:
            tactic = tech2tactic.get(tid)
            if tactic and _tactic_can_move(tactic, tactics_order):
                for neighbor_dev in topology.get(dev, []):
                    if neighbor_dev not in active_devices:
                        edge = (f"technique:{tid}", f"compromised:{neighbor_dev}")
                        G_tmp.add_edge(*edge)
                        if nx.is_directed_acyclic_graph(G_tmp):
                            edges.append(edge)
                            active_devices.add(neighbor_dev)
                            queue.append(neighbor_dev)
                        else:
                            G_tmp.remove_edge(*edge)

        # Step 2.4: router infection spread (compromised:router ➔ compromised:neighbor_device)
        if _is_router(device_info.get(dev)):
            for neighbor_dev in topology.get(dev, []):
                if neighbor_dev not in active_devices:
                    edge = (f"compromised:{dev}", f"compromised:{neighbor_dev}")
                    G_tmp.add_edge(*edge)
                    if nx.is_directed_acyclic_graph(G_tmp):
                        edges.append(edge)
                        active_devices.add(neighbor_dev)
                        queue.append(neighbor_dev)
                    else:
                        G_tmp.remove_edge(*edge)

    # Step 3: Build final Bayesian Network
    model = DiscreteBayesianNetwork(edges)

    # --- Add CPDs ---
    device_vuln_map = _device_vuln_index(vulns)
    tech_score_map = _build_tech_score_map(vulns)

    for node in model.nodes:
        parents = list(model.get_parents(node))
        if not parents:
            base = _root_probability(node, vulns)
            model.add_cpds(TabularCPD(node, 2, [[1 - base], [base]]))
            continue

        prob_true, prob_false = [], []
        p_count = len(parents)

        for i in range(2**p_count):
            bits = list(map(int, format(i, f"0{p_count}b")))
            active = [(parents[j], bits[j]) for j in range(p_count) if bits[j] == 1]
            active_info = [(p.split(":", 1)[1], "device" if p.startswith("compromised:") else "technique") for p, _ in active]

            p_active = estimate_parent_influence(
                parent_info=active_info,
                device_vulns=device_vuln_map,
                technique_score_map=tech_score_map,
                technique_to_tactic_map=tech2tactic,
            )
            prob_true.append(p_active)
            prob_false.append(1 - p_active)

        model.add_cpds(
            TabularCPD(
                node, 2, [prob_false, prob_true], evidence=parents, evidence_card=[2] * p_count
            )
        )

    model.check_model()
    return model




# --------------- 辅助函数 ----------------

def _build_tactic_order(tactic_chain_data):
    order_map = defaultdict(list)
    for item in tactic_chain_data:
        curr = item["tactic"]
        nxt = item["next"]
        if isinstance(nxt, str):
            nxt = eval(nxt)  # 只在是字符串时才 eval
        for n in nxt:
            order_map[curr].append(n)
    return order_map

def _tactic_can_progress(tac_from, tac_to, order_map):
    if tac_from in order_map:
        return tac_to in order_map[tac_from]
    return False

def _tactic_can_move(tactic_id: str, tactic_order_map: dict) -> bool:
    """判断一个tactic是否可以向后扩展（横向移动）"""
    return bool(tactic_order_map.get(tactic_id))

def _is_router(device: dict) -> bool:
    """判断一个设备是不是Router型"""
    if not device:
        return False
    interfaces = device.get("interfaces", [])
    subnets = {iface.get("subnet") for iface in interfaces if iface.get("subnet")}
    return len(subnets) >= 2 or device.get("device_type", "").lower() in {"router", "gateway", "firewall"}


def _build_tech_score_map(vulns):
    score = {}
    for v in vulns:
        for tid in v.get("attack_techniques", []):
            cvss = float(v.get("cvss", 5.0))
            epss = float(v.get("epss", 0.0))
            score[tid] = max(score.get(tid, 0.0), min(1.0, (cvss/10.0)*(0.5+epss)))
    return score



# ---------------------------------------------------------------------------
# Inference utilities
# ---------------------------------------------------------------------------
@analysis_bp.route("/node_search")
def node_search():
    q = request.args.get("q", "").lower()
    graph = session.get("attack_graph", {})
    return jsonify([n for n in graph.get("nodes", []) if q in n.lower()])


@analysis_bp.route("/infer_probability")
def infer_probability():
    project = _project_db()
    model = _bn_cache.get(project)
    if not model:
        return jsonify({"error": "Model not ready"}), 400

    node = request.args.get("observe")
    if not node:
        return jsonify({"error": "Missing observe param"}), 400

    try:
        infer = VariableElimination(model)
        evidence = {node: 1}

        result: dict[str, float] = {}

        # posterior for all other nodes
        for n in model.nodes:
            if n == node:
                continue
            q = infer.query(variables=[n], evidence=evidence, show_progress=False)
            result[n] = round(float(q.values[1]), 3)

        # add the observed node itself with probability 1.0
        result[node] = 1.0

        highlight = sorted(
            (k for k, v in result.items() if v > 0.5),
            key=lambda x: -result[x]
        )
        return jsonify({"probabilities": result, "highlight": highlight})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@analysis_bp.route("/get_cpd/<node_id>")
def get_cpd(node_id: str):
    model = _bn_cache.get(_project_db())
    if not model:
        return jsonify({"error": "Model not loaded"}), 400

    try:
        cpd = model.get_cpds(node_id)
        return jsonify(
            {
                "variable": str(cpd.variable),
                "variables": [str(v) for v in cpd.variables],
                "cardinality": [int(c) for c in cpd.cardinality],
                "values": _round_nested(cpd.values.tolist()),
            }
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _round_nested(data: Any, precision: int = 4):
    if isinstance(data, list):
        return [_round_nested(i, precision) for i in data]
    try:
        return round(float(data), precision)
    except Exception:
        return data


def _device_vuln_index(vulns: list[dict]) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = defaultdict(list)
    for v in vulns:
        dev = v.get("parent_device_id")
        if dev:
            idx[dev].append(v)
    return idx


def _root_probability(node: str, vulns: list[dict]) -> float:
    if node.startswith("compromised:"):
        dev = node.split(":", 1)[1]
        scores = [
            min(1.0, (float(v.get("cvss", 5.0)) / 10.0) * (0.5 + float(v.get("epss", 0.0))))
            for v in vulns
            if v.get("parent_device_id") == dev
        ]
        return max(scores) if scores else 0.05
    return 0.05

