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


def load_vulnerabilities() -> List[Dict[str, Any]]:
    return list(get_project_db(_project_db()).vulnerabilities.find({}))


def load_techniques() -> List[Dict[str, Any]]:
    return list(attack_reference.techniques.find({}))


def load_tactics() -> List[Dict[str, Any]]:
    return list(attack_reference.tactics.find({}))


def load_technique_to_tactic() -> Dict[str, str]:
    mappings = attack_reference.techniques_to_tactics.find({})
    return {m["technique_id"]: m["tactic_id"] for m in mappings}


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


@analysis_bp.route("/bayesian_attack_graph")
def bayesian_attack_graph():
    project = _project_db()
    if project not in _bn_cache:
        _bn_cache[project] = _build_bayesian_model()

    model = _bn_cache[project]

    # ------------------------------------------------------------
    edge_prob_map: dict[tuple[str, str], float] = {}

    for parent, child in model.edges:
        cpd = model.get_cpds(child)

        # If the parent variable is not in this CPD (shouldn’t happen), default to 0
        if parent not in cpd.variables:
            edge_prob_map[(parent, child)] = 0.0
            continue

        # Reduce the CPD by fixing parent = 1 (True)
        reduced = cpd.reduce([(parent, 1)], inplace=False)

        # Index of the “True” state for the child variable
        true_state_index = list(reduced.state_names[child]).index(1)

        # reduced.values[true_state_index] may still be an N-D array because
        # other parents were not fixed; we marginalise over the remaining axes
        prob_true = float(np.asarray(reduced.values[true_state_index]).mean())

        edge_prob_map[(parent, child)] = round(prob_true, 3)
    # ------------------------------------------------------------

    session["attack_graph"] = {"nodes": list(model.nodes), "edges": list(model.edges)}

    return jsonify(
        {
            "nodes": list(model.nodes),
            "edges": list(model.edges),
            "edge_probs": {f"{src}→{tgt}": p for (src, tgt), p in edge_prob_map.items()},
        }
    )


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


def _build_bayesian_model() -> DiscreteBayesianNetwork:
    devices = load_devices()
    vulns = load_vulnerabilities()

    # device → techniques
    vulnerability_map: dict[str, list[str]] = defaultdict(list)
    for v in vulns:
        dev = v.get("parent_device_id")
        if not dev:
            continue
        for tid in v.get("attack_techniques", []):
            vulnerability_map[dev].append(tid)

    # subnet → devices
    subnet_map: dict[str, list[str]] = defaultdict(list)
    for d in devices:
        did = d["_id"]
        for iface in d.get("interfaces", []):
            if subnet := iface.get("subnet"):
                subnet_map[subnet].append(did)

    # topology edges (direct + same-subnet)
    topology: dict[str, set[str]] = defaultdict(set)
    for d in devices:
        did = d["_id"]
        for iface in d.get("interfaces", []):
            if tgt := iface.get("connected_to"):
                topology[did].add(tgt)

    for devs in subnet_map.values():
        for i, src in enumerate(devs):
            for tgt in devs[i + 1 :]:
                topology[src].add(tgt)
                topology[tgt].add(src)

    # build DAG
    G_tmp = nx.DiGraph()
    edges: list[tuple[str, str]] = []

    for src, techs in vulnerability_map.items():
        for tid in techs:
            e1 = (f"compromised:{src}", f"technique:{tid}")
            G_tmp.add_edge(*e1)
            if nx.is_directed_acyclic_graph(G_tmp):
                edges.append(e1)
            else:
                G_tmp.remove_edge(*e1)

            for tgt in topology[src]:
                e2 = (f"technique:{tid}", f"compromised:{tgt}")
                G_tmp.add_edge(*e2)
                if nx.is_directed_acyclic_graph(G_tmp):
                    edges.append(e2)
                else:
                    G_tmp.remove_edge(*e2)

    model = DiscreteBayesianNetwork(edges)

    # CPDs
    tech2tactic = load_technique_to_tactic()
    device_vuln_map = _device_vuln_index(vulns)

    # technique score map
    tech_score: dict[str, float] = {}
    for v in vulns:
        for tid in v.get("attack_techniques", []):
            cvss = float(v.get("cvss", 5.0))
            epss = float(v.get("epss", 0.0))
            tech_score[tid] = max(
                tech_score.get(tid, 0.0), min(1.0, (cvss / 10.0) * (0.5 + epss))
            )

    for node in model.nodes:
        parents = list(model.get_parents(node))
        if not parents:
            base = _root_probability(node, vulns)
            model.add_cpds(TabularCPD(node, 2, [[1 - base], [base]]))
            continue

        parent_tuples = [
            (p.split(":", 1)[1], "device" if p.startswith("compromised:") else "technique")
            for p in parents
        ]
        prob_true: list[float] = []
        prob_false: list[float] = []
        p_count = len(parents)

        for i in range(2**p_count):
            bits = list(map(int, format(i, f"0{p_count}b")))
            active = [pt for bit, pt in zip(bits, parent_tuples) if bit == 1]

            p_active = estimate_parent_influence(
                parent_info=active,
                device_vulns=device_vuln_map,
                technique_score_map=tech_score,
                technique_to_tactic_map=tech2tactic,
            )
            prob_true.append(p_active)
            prob_false.append(1 - p_active)

        model.add_cpds(
            TabularCPD(
                node,
                2,
                [prob_false, prob_true],  # state-0, state-1
                evidence=parents,
                evidence_card=[2] * p_count,
            )
        )

    model.check_model()
    return model
