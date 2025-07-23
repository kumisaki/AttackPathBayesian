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

from numpy import mean

from extensions import attack_reference, get_project_db

from utils.estimat_probabilities import compute_structural_probability, estimate_parent_influence

from data_access import (
    get_devices, get_subnets, get_vulnerabilities, get_techniques, get_tactics, get_technique_to_tactic_map, get_tactic_chain, get_firewall_rules, get_technique_map, get_tactic_map, get_device_map
)

analysis_bp = Blueprint('analysis_bp', __name__)

_bn_cache: dict[str, DiscreteBayesianNetwork] = {}

def _project_db() -> str:
    db = session.get('project_db')
    if not db:
        raise KeyError('project_db missing from session')
    return db

@analysis_bp.route('/analysis_topology_graph_page')
def analysis_topology_graph_page():
    return render_template('analysis_topology_graph.html')

@analysis_bp.route('/analysis_topology_graph')
def analysis_topology_graph():
    subnets = get_subnets()
    devices = get_devices()
    vulns = get_vulnerabilities()
    techniques = get_techniques()
    tactics = get_tactics()
    tech2tactic = get_technique_to_tactic_map()
    subnet_ids = {str(s['_id']): s for s in subnets}
    device_ids = {str(d['_id']): d for d in devices}
    technique_map = get_technique_map()
    tactic_map = get_tactic_map()
    elements: List[Dict[str, Any]] = []
    device_subnets: dict[str, list[str]] = {}
    device_connected_to: dict[str, str] = {}
    device_rank_map: dict[str, int] = {}
    for d in devices:
        did = str(d['_id'])
        used: set[str] = set()
        for iface in d.get('interfaces', []):
            if iface.get('interface_type') == 'TCP/IP' and iface.get('subnet') in subnet_ids:
                used.add(iface['subnet'])
            elif iface.get('connected_to') in device_ids:
                device_connected_to[did] = iface['connected_to']
        device_subnets[did] = list(used)
        if len(used) >= 2:
            device_rank_map[did] = 1
        elif did in device_connected_to:
            device_rank_map[did] = 3
        else:
            device_rank_map[did] = 2
    used_ranks = set(device_rank_map.values()) | {2, 4, 5, 6}
    for r in sorted(used_ranks):
        elements.append({'data': {'id': f'rank_layer_{r}', 'label': f'Layer {r}'}, 'classes': 'rank_container'})
    for s in sorted(subnets, key=lambda x: x.get('label', '')):
        sid = str(s['_id'])
        elements.append({'data': {'id': sid, 'label': _esc(s.get('label', sid)), 'CIDR': s.get('cidr', ''), 'Zone': s.get('zone', ''), 'parent': 'rank_layer_2'}, 'classes': 'subnet'})
    for d in sorted(devices, key=lambda x: x.get('label', '')):
        did = str(d['_id'])
        rank = device_rank_map.get(did, 10)
        parent_id = device_subnets[did][0] if rank == 2 and len(device_subnets[did]) == 1 and (did not in device_connected_to) else f'rank_layer_{rank}'
        elements.append({'data': {'id': did, 'label': _esc(d.get('label', did)), 'parent': parent_id}, 'classes': 'device'})
    for child_id, parent_id in device_connected_to.items():
        elements.append({'data': {'id': f'{child_id}_to_{parent_id}', 'source': child_id, 'target': parent_id}, 'classes': 'connection'})
    for d in devices:
        did = str(d['_id'])
        for iface in d.get('interfaces', []):
            sid = iface.get('subnet')
            if sid and sid in subnet_ids:
                elements.append({'data': {'id': f'{did}_to_{sid}', 'source': did, 'target': sid}, 'classes': 'device_subnet_edge'})
    for v in sorted(vulns, key=lambda x: x.get('vuln_id', '')):
        vid = str(v['_id'])
        parent_dev = v.get('parent_device_id', '')
        prob = float(v.get('prob', 0.0))
        elements.extend([{'data': {'id': vid, 'label': _esc(vid), 'desc': _esc(v.get('desc', '')), 'prob': prob, 'vuln_id': vid, 'parent': 'rank_layer_4'}, 'classes': 'vuln'}, {'data': {'id': f'{vid}_to_{parent_dev}', 'source': vid, 'target': parent_dev, 'label': f'{prob:.2f}', 'prob': prob}, 'classes': 'vuln_edge'}])
    used_techniques: set[str] = set()
    used_tactics: set[str] = set()
    for v in vulns:
        for tid in v.get('attack_techniques', []):
            used_techniques.add(tid)
            if (tac := tech2tactic.get(tid)):
                used_tactics.add(tac)
            elements.append({'data': {'id': f"{v['_id']}_to_{tid}", 'source': str(v['_id']), 'target': tid}, 'classes': 'tech_edge'})
            if tac:
                elements.append({'data': {'id': f'{tid}_to_{tac}', 'source': tid, 'target': tac}, 'classes': 'tactic_edge'})
    for tid in sorted(used_techniques, key=lambda x: technique_map.get(x, {}).get('technique_name', x)):
        elements.append({'data': {'id': tid, 'label': _esc(technique_map.get(tid, {}).get('technique_name', tid)), 'parent': 'rank_layer_5'}, 'classes': 'technique'})
    for tac in sorted(used_tactics, key=lambda x: tactic_map.get(x, {}).get('tactic_name', x)):
        elements.append({'data': {'id': tac, 'label': _esc(tactic_map.get(tac, {}).get('tactic_name', tac)), 'parent': 'rank_layer_6'}, 'classes': 'tactic'})
    return jsonify({'elements': elements})

@analysis_bp.route('/bayesian_attack_graph_page')
def bayesian_attack_graph_page():
    return render_template('bayesian_attack_graph.html')

@analysis_bp.route('/clear_attack_graph_cache')
def clear_attack_graph_cache():
    _bn_cache.clear()
    return ('Attack graph cache cleared.', 200)

@analysis_bp.route('/bayesian_attack_graph')
def bayesian_attack_graph():
    project = _project_db()
    _bn_cache[project] = _build_bayesian_model()
    model = _bn_cache[project]
    print(model)
    posterior = session.get('inference_result', {})
    edge_prob_map = {}
    for parent, child in model.edges:
        prob = posterior.get(child, 0.0)
        edge_prob_map[parent, child] = round(prob, 3)
    session['attack_graph'] = {'nodes': list(model.nodes), 'edges': list(model.edges)}
    devices = get_devices()
    techniques = get_techniques()
    device_map = get_device_map()
    technique_map = get_technique_map()
    node_info = []
    for n in model.nodes:
        label = n.split(':', 1)[1]
        if n.startswith('compromised:'):
            dev = device_map.get(label, {})
            node_info.append({
                'id': n,
                'label': dev.get('label', label),
                'device_type': dev.get('device_type', ''),
            })
        elif n.startswith('technique:'):
            tech = technique_map.get(label, {})
            node_info.append({
                'id': n,
                'label': tech.get('technique_name', label),
                'description': tech.get('technique_description', ''),
            })
        else:
            node_info.append({'id': n, 'label': label})
    tech2tactic = get_technique_to_tactic_map()
    tactics_chain = get_tactic_chain()
    tactics_order = _build_tactic_order(tactics_chain)
    paths = top_k_paths_by_cpd_strength(model=_bn_cache[project], start_node='technique:T1566.001', k=5, technique_to_tactic=tech2tactic, tactic_order=tactics_order)
    print('Total static paths found:', len(paths))
    for path, prob in paths:
        print(' → '.join(path), f'| P={prob:.4f}')

    # import pprint; pprint.pprint({
    # 'nodes': node_info,
    # 'edges': list(model.edges),
    # 'edge_probs': {f'{src}→{tgt}': p for (src, tgt), p in edge_prob_map.items()},
    # 'initial_paths': paths
    # })
    # breakpoint()
    return jsonify({'nodes': node_info, 'edges': list(model.edges), 'edge_probs': {f'{src}→{tgt}': p for (src, tgt), p in edge_prob_map.items()}, 'initial_paths': paths})

def _build_bayesian_model() -> DiscreteBayesianNetwork:
    devices = get_devices()
    vulns = get_vulnerabilities()
    firewall_rules = get_firewall_rules()
    tech2tactic = get_technique_to_tactic_map()
    tactics_chain = get_tactic_chain()
    tactics_order = _build_tactic_order(tactics_chain)
    device_ids = {str(d['_id']) for d in devices}
    device_info = {str(d['_id']): d for d in devices}
    topology: dict[str, set[str]] = defaultdict(set)
    for rule in firewall_rules:
        src = rule.get('outbound')
        tgt = rule.get('inbound')
        if src in device_ids and tgt in device_ids:
            topology[src].add(tgt)
    device_techniques: dict[str, set[str]] = defaultdict(set)
    for v in vulns:
        dev = v.get('parent_device_id')
        if dev:
            for tid in v.get('attack_techniques', []):
                device_techniques[dev].add(tid)
    G_tmp = nx.DiGraph()
    edges = []
    active_devices = set()
    activated_techniques = defaultdict(set)
    for dev, techs in device_techniques.items():
        for tid in techs:
            tactic = tech2tactic.get(tid)
            if tactic and tactic in {'TA0001', 'TA0108'}:
                edge = (f'technique:{tid}', f'compromised:{dev}')
                G_tmp.add_edge(*edge)
                if nx.is_directed_acyclic_graph(G_tmp):
                    edges.append(edge)
                    active_devices.add(dev)
                    activated_techniques[dev].add(tid)
                else:
                    G_tmp.remove_edge(*edge)
    queue = list(active_devices)
    while queue:
        dev = queue.pop(0)
        for tid in device_techniques.get(dev, []):
            edge = (f'compromised:{dev}', f'technique:{tid}')
            G_tmp.add_edge(*edge)
            if nx.is_directed_acyclic_graph(G_tmp):
                edges.append(edge)
                activated_techniques[dev].add(tid)
            else:
                G_tmp.remove_edge(*edge)
        current_techs = activated_techniques[dev]
        for tid1 in current_techs:
            tactic1 = tech2tactic.get(tid1)
            for tid2 in device_techniques.get(dev, []):
                tactic2 = tech2tactic.get(tid2)
                if tactic1 and tactic2 and _tactic_can_progress(tactic1, tactic2, tactics_order):
                    edge = (f'technique:{tid1}', f'technique:{tid2}')
                    G_tmp.add_edge(*edge)
                    if nx.is_directed_acyclic_graph(G_tmp):
                        edges.append(edge)
                    else:
                        G_tmp.remove_edge(*edge)
        for tid in current_techs:
            tactic = tech2tactic.get(tid)
            if tactic and _tactic_can_move(tactic, tactics_order):
                for neighbor_dev in topology.get(dev, []):
                    if neighbor_dev not in active_devices:
                        edge = (f'technique:{tid}', f'compromised:{neighbor_dev}')
                        G_tmp.add_edge(*edge)
                        if nx.is_directed_acyclic_graph(G_tmp):
                            edges.append(edge)
                            active_devices.add(neighbor_dev)
                            queue.append(neighbor_dev)
                        else:
                            G_tmp.remove_edge(*edge)
        if _is_router(device_info.get(dev)):
            for neighbor_dev in topology.get(dev, []):
                if neighbor_dev not in active_devices:
                    edge = (f'compromised:{dev}', f'compromised:{neighbor_dev}')
                    G_tmp.add_edge(*edge)
                    if nx.is_directed_acyclic_graph(G_tmp):
                        edges.append(edge)
                        active_devices.add(neighbor_dev)
                        queue.append(neighbor_dev)
                    else:
                        G_tmp.remove_edge(*edge)
    model = DiscreteBayesianNetwork(edges)
    device_vuln_map = _device_vuln_index(vulns)
    tech_score_map = _build_tech_score_map(vulns)
    for node in model.nodes:
        parents = list(model.get_parents(node))
        if not parents:
            base = _root_probability(node, vulns)
            model.add_cpds(TabularCPD(node, 2, [[1 - base], [base]]))
            continue
        prob_true, prob_false = ([], [])
        p_count = len(parents)
        for i in range(2 ** p_count):
            bits = list(map(int, format(i, f'0{p_count}b')))
            active = [(parents[j], bits[j]) for j in range(p_count) if bits[j] == 1]
            active_info = [(p.split(':', 1)[1], 'device' if p.startswith('compromised:') else 'technique') for p, _ in active]
            p_active = estimate_parent_influence(parent_info=active_info, device_vulns=device_vuln_map, technique_score_map=tech_score_map, technique_to_tactic_map=tech2tactic, future_children=[tgt for src, tgt in model.edges if src == node and tgt.startswith('technique:')], tactic_order=tactics_order)
            prob_true.append(p_active)
            prob_false.append(1 - p_active)
        model.add_cpds(TabularCPD(node, 2, [prob_false, prob_true], evidence=parents, evidence_card=[2] * p_count))
    model.check_model()
    return model

def _build_tactic_order(tactic_chain_data):
    order_map = defaultdict(list)
    for item in tactic_chain_data:
        curr = item['tactic']
        nxt = item['next']
        if isinstance(nxt, str):
            nxt = eval(nxt)
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
    interfaces = device.get('interfaces', [])
    subnets = {iface.get('subnet') for iface in interfaces if iface.get('subnet')}
    return len(subnets) >= 2 or device.get('device_type', '').lower() in {'router', 'gateway', 'firewall'}

def _build_tech_score_map(vulns):
    score = {}
    for v in vulns:
        for tid in v.get('attack_techniques', []):
            cvss = float(v.get('cvss', 5.0))
            epss = float(v.get('epss', 0.0))
            score[tid] = max(score.get(tid, 0.0), min(1.0, cvss / 10.0 * (0.5 + epss)))
    return score

@analysis_bp.route('/node_search')
def node_search():
    q = request.args.get('q', '').lower()
    graph = session.get('attack_graph', {})
    return jsonify([n for n in graph.get('nodes', []) if q in n.lower()])

@analysis_bp.route('/infer_probability')
def infer_probability():
    project = _project_db()
    model = _bn_cache.get(project)
    if not model:
        return (jsonify({'error': 'Model not ready'}), 400)
    node = request.args.get('observe')
    if not node:
        return (jsonify({'error': 'Missing observe param'}), 400)
    try:
        infer = VariableElimination(model)
        evidence = {node: 1}
        result: dict[str, float] = {}
        for n in model.nodes:
            if n == node:
                continue
            q = infer.query(variables=[n], evidence=evidence, show_progress=False)
            result[n] = round(float(q.values[1]), 3)
        result[node] = 1.0
        highlight = sorted((k for k, v in result.items() if v > 0.5), key=lambda x: -result[x])
        techniques = get_techniques()
        tactics = get_tactics()
        devices = get_devices()
        tech2tactic = {t['technique_id']: t.get('tactic_id') for t in techniques}
        tactic_order_index = build_tactic_order_index(tactics)
        device_map = {f"compromised:{str(d['_id'])}": d.get('label', str(d['_id'])) for d in devices}
        tech_map = {f"technique:{t['technique_id']}": t.get('technique_name', t['technique_id']) for t in techniques}
        id_to_label = {**device_map, **tech_map}
        paths = top_k_paths(    
            model=model,
            posterior=result,
            start_node=node,
            technique_to_tactic=tech2tactic,
            tactic_order_index=tactic_order_index,
            k=20  # or however many paths you want
        )
        
        def _last_tactic_rank(path: list[str]) -> int:
            for node in reversed(path):
                if node.startswith('technique:'):
                    tid = node.split(':', 1)[1]
                    tac = tech2tactic.get(tid)
                    if tac:
                        return tactic_order_index.get(tac, -1)
            return -1
        paths.sort(key=lambda p: p[1], reverse=True)
        top_paths_pretty = []
        top_paths_pretty = []
        for path, prob in paths:
            label_path = [id_to_label.get(n, n) for n in path]
            top_paths_pretty.append({'path': label_path, 'prob': prob})
        session['inference_result'] = result
        devices = get_devices()
        device_ids = [f"compromised:{str(d['_id'])}" for d in devices]
        N = len(device_ids)
        weighted_probs = []
        total_weight = 0.0
        total_beta = 0.0
        for d in devices:
            cid = f"compromised:{str(d['_id'])}"
            P_d = result.get(cid, 0.0)
            C_d = float(d.get('weight', 5.0))
            beta_d = float(d.get('beta', 0.2))
            weighted_probs.append(P_d * C_d)
            total_weight += C_d
            total_beta += beta_d
        if total_weight > 0:
            Rg = sum(weighted_probs) / total_weight * (1 + total_beta / N)
        else:
            Rg = 0.0
        return jsonify({'probabilities': result, 'highlight': highlight, 'labels': id_to_label, 'top_paths': top_paths_pretty, 'risk_prob': Rg})
    except Exception as exc:
        return (jsonify({'error': str(exc)}), 500)

@analysis_bp.route('/get_cpd/<node_id>')
def get_cpd(node_id: str):
    model = _bn_cache.get(_project_db())
    if not model:
        return (jsonify({'error': 'Model not loaded'}), 400)
    try:
        cpd = model.get_cpds(node_id)
        return jsonify({'variable': str(cpd.variable), 'variables': [str(v) for v in cpd.variables], 'cardinality': [int(c) for c in cpd.cardinality], 'values': _round_nested(cpd.values.tolist())})
    except Exception as exc:
        return (jsonify({'error': str(exc)}), 500)

def _round_nested(data: Any, precision: int=4):
    if isinstance(data, list):
        return [_round_nested(i, precision) for i in data]
    try:
        return round(float(data), precision)
    except Exception:
        return data

def _device_vuln_index(vulns: list[dict]) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = defaultdict(list)
    for v in vulns:
        dev = v.get('parent_device_id')
        if dev:
            idx[dev].append(v)
    return idx

def _root_probability(node: str, vulns: list[dict]) -> float:
    if node.startswith('compromised:'):
        dev = node.split(':', 1)[1]
        scores = [min(1.0, float(v.get('cvss', 5.0)) / 10.0 * (0.5 + float(v.get('epss', 0.0)))) for v in vulns if v.get('parent_device_id') == dev]
        return max(scores) if scores else 0.05
    return 0.05

    def _is_lateral_tech(tid: str) -> bool:
        tactic = technique_to_tactic.get(tid)
        return tactic in lateral_tactics

    def _is_leaf(node: str, model: DiscreteBayesianNetwork) -> bool:
        return all((not (s.startswith('technique:') or s.startswith('compromised:')) for s in model.successors(node)))

    def _is_valid_structure(path: list[str]) -> bool:
        return len(path) >= 2 and path[1].startswith('compromised:') and _is_leaf(path[-1])

    def is_valid_tactic_sequence(path: list[str]) -> bool:
        prev_tactic = None
        for i, n in enumerate(path):
            if not n.startswith('technique:'):
                continue
            tid = n.split(':', 1)[1]
            tac = technique_to_tactic.get(tid)
            if not tac:
                continue
            if prev_tactic is None:
                prev_tactic = tac
                continue
            if tac == prev_tactic:
                continue
            if tactic_order_index.get(tac, -1) < tactic_order_index.get(prev_tactic, -1):
                prev_tid = path[i - 1].split(':', 1)[1]
                if not _is_lateral_tech(prev_tid):
                    return False
            prev_tactic = tac
        return True
    tech2tactic = get_technique_to_tactic_map()
    ics_tactics = {'TA0108', 'TA0109', 'TA0110', 'TA0111', 'TA0112', 'TA0113', 'TA0114', 'TA0115', 'TA0116', 'TA0117', 'TA0118', 'TA0119'}
    for node in model.nodes:
        if node.startswith('technique:'):
            tid = node.split(':', 1)[1]
            tactic = tech2tactic.get(tid)
            if tactic in ics_tactics:
                print(node)

    def _max_tactic_rank(path: list[str]) -> int:
        ranks = [tactic_order_index.get(technique_to_tactic.get(n.split(':', 1)[1]), -1) for n in path if n.startswith('technique:')]
        return max(ranks) if ranks else -1
    paths = []

    def dfs(node, path, prob):
        path = path + [node]
        prob = prob * posterior.get(node, 0.01)
        if len(path) >= 2 and path[1].startswith('compromised:') and is_valid_tactic_sequence(path):
            if node.startswith('technique:') or _is_leaf(node, model):
                paths.append({'path': path, 'prob': round(prob, 4)})
        for neighbor in model.successors(node):
            if neighbor not in path:
                dfs(neighbor, path, prob)
    dfs(start_node, [], 1.0)
    return paths

    def _is_lateral_tech(tid: str) -> bool:
        tactic = technique_to_tactic.get(tid)
        return tactic in lateral_tactics

    def is_valid_tactic_sequence_with_lateral(path: list[str]) -> bool:
        prev_tactic = None
        for i, n in enumerate(path):
            if not n.startswith('technique:'):
                continue
            tid = n.split(':', 1)[1]
            tac = technique_to_tactic.get(tid)
            if not tac:
                continue
            if prev_tactic is None:
                prev_tactic = tac
                continue
            if tac == prev_tactic:
                continue
            if tactic_order_index.get(tac, -1) < tactic_order_index.get(prev_tactic, -1):
                prev_tid = path[i - 1].split(':', 1)[1]
                if not _is_lateral_tech(prev_tid):
                    return False
            prev_tactic = tac
        return True

    def _is_leaf(node: str) -> bool:
        return len(list(G.successors(node))) == 0

    def _is_valid_structure(path: list[str]) -> bool:
        return len(path) >= 2 and path[1].startswith('compromised:') and _is_leaf(path[-1])
    G = nx.DiGraph()
    G.add_edges_from(model.edges)
    all_paths = []

    def dfs(node, path, prob):
        path = path + [node]
        prob = prob * posterior.get(node, 0.01)
        successors = list(G.successors(node))
        if not successors:
            if _is_valid_structure(path) and is_valid_tactic_sequence_with_lateral(path):
                all_paths.append((path, round(prob, 4)))
        else:
            for neighbor in successors:
                if neighbor not in path:
                    dfs(neighbor, path, prob)
    dfs(start_node, [], 1.0)
    return all_paths

    def _is_lateral_tech(tid: str) -> bool:
        tactic = technique_to_tactic.get(tid)
        return tactic in lateral_tactics

    def is_valid_tactic_sequence_with_lateral(path: list[str]) -> bool:
        prev_tactic = None
        for i, n in enumerate(path):
            if not n.startswith('technique:'):
                continue
            tid = n.split(':', 1)[1]
            tac = technique_to_tactic.get(tid)
            if not tac:
                continue
            if prev_tactic is None:
                prev_tactic = tac
                continue
            if tac == prev_tactic:
                continue
            if tactic_order_index.get(tac, -1) < tactic_order_index.get(prev_tactic, -1):
                prev_tid = path[i - 1].split(':', 1)[1]
                if not _is_lateral_tech(prev_tid):
                    return False
            prev_tactic = tac
        return True

    def _tactic_rank(tac: str | None) -> int:
        return tactic_order_index.get(tac, -1) if tac else -1
    G = nx.DiGraph()
    G.add_edges_from(model.edges)
    all_paths = []

    def dfs(node, path, prob):
        path = path + [node]
        prob = prob * posterior.get(node, 0.01)
        successors = list(G.successors(node))
        if not successors:
            if is_valid_tactic_sequence_with_lateral(path):
                last_tac = next((technique_to_tactic.get(n.split(':', 1)[1]) for n in reversed(path) if n.startswith('technique:')), None)
                all_paths.append((path, prob, last_tac))
        else:
            for neighbor in successors:
                if neighbor not in path:
                    dfs(neighbor, path, prob)
    dfs(start_node, [], 1.0)
    all_paths.sort(key=lambda x: (_tactic_rank(x[2]), x[1]), reverse=True)
    return [(p, round(prob, 4)) for p, prob, _ in all_paths[:k]]

def _is_valid_structure(path: list[str], G: nx.DiGraph) -> bool:
    return len(path) >= 2 and path[1].startswith('compromised:') and (not list(G.successors(path[-1])))

def build_tactic_order_index(tactics: list[dict]) -> dict[str, int]:
    """
    Construct a combined tactic order index for Enterprise and ICS.
    Manually set the order based on the official ATT&CK framework.
    """
    enterprise_order = ['TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0010', 'TA0011']
    ics_order = ['TA0108', 'TA0110', 'TA0111', 'TA0112', 'TA0113', 'TA0114', 'TA0115', 'TA0116', 'TA0117', 'TA0118', 'TA0119']
    index_map = {}
    for i, tid in enumerate(enterprise_order):
        index_map[tid] = i
    offset = len(enterprise_order)
    for i, tid in enumerate(ics_order):
        index_map[tid] = i + offset
    return index_map

def _tactic_is_forward_only(tactics: list[str], tactic_order_index: dict[str, int]) -> bool:
    indices = [tactic_order_index.get(t, -1) for t in tactics if t in tactic_order_index]
    return all((i2 >= i1 for i1, i2 in zip(indices, indices[1:])))

def _is_lateral_tech(tid: str, tactic_map: dict[str, str]) -> bool:
    tactic = tactic_map.get(tid)
    return tactic in {'TA0008', 'TA0109'}

def is_valid_tactic_sequence_with_lateral(path, tactic_map, tactic_index, lateral_tactics):
    prev_tactic = None
    for i, n in enumerate(path):
        if not n.startswith('technique:'):
            continue
        tid = n.split(':', 1)[1]
        tac = tactic_map.get(tid)
        if not tac:
            continue
        if prev_tactic is None:
            prev_tactic = tac
            continue
        if tac == prev_tactic:
            continue
        if tactic_index.get(tac, -1) < tactic_index.get(prev_tactic, -1):
            if not tactic_map.get(path[i - 1].split(':', 1)[1]) in lateral_tactics:
                return False
        prev_tactic = tac
    return True

def top_k_paths_by_cpd_strength(model: DiscreteBayesianNetwork, start_node: str, k: int=5, technique_to_tactic: dict[str, str]=None, tactic_order: dict[str, list[str]]=None) -> list[tuple[list[str], float]]:
    import networkx as nx
    G = nx.DiGraph()
    G.add_edges_from(model.edges)

    def get_edge_prob(parent: str, child: str) -> float:
        try:
            cpd = model.get_cpds(child)
            if parent not in cpd.variables:
                return 0.01
            reduced = cpd.reduce([(parent, 1)], inplace=False)
            idx = list(reduced.state_names[child]).index(1)
            return float(mean(reduced.values[idx]))
        except:
            return 0.01

    def _get_tactic(nid: str) -> str | None:
        if technique_to_tactic and nid.startswith('technique:'):
            return technique_to_tactic.get(nid.split(':', 1)[1])
        return None

    def _is_progressive(path: list[str]) -> bool:
        if not (technique_to_tactic and tactic_order):
            return True
        tactics = [_get_tactic(n) for n in path if _get_tactic(n)]
        for i in range(len(tactics) - 1):
            if tactics[i + 1] not in tactic_order.get(tactics[i], []):
                return False
        return True
    all_paths = []

    def dfs(node, path, total_prob):
        path = path + [node]
        successors = list(G.successors(node))
        if not successors:
            if _is_progressive(path):
                all_paths.append((path, total_prob))
        else:
            for neighbor in successors:
                if neighbor not in path:
                    edge_p = get_edge_prob(node, neighbor)
                    dfs(neighbor, path, total_prob * edge_p)
    dfs(start_node, [], 1.0)
    all_paths.sort(key=lambda x: x[1], reverse=True)
    return all_paths[:k]

def top_k_paths(model: DiscreteBayesianNetwork, posterior: dict[str, float], start_node: str, technique_to_tactic: dict[str, str], tactic_order_index: dict[str, int], k: int=5) -> list[tuple[list[str], float]]:
    """
    Returns the top-k attack paths starting from the given node,
    ranked by tactic progression and posterior probability.

    Constraints:
    - Only allows forward progression in tactics unless the jump is from a lateral movement technique.
    - Paths must end at a technique or a leaf node.
    """
    import networkx as nx
    lateral_tactics = {'TA0008', 'TA0109'}

    def _get_tactic(node_id: str) -> str | None:
        if node_id.startswith('technique:'):
            tid = node_id.split(':', 1)[1]
            return technique_to_tactic.get(tid)
        return None

    def _is_lateral_tech(tid: str) -> bool:
        tactic = technique_to_tactic.get(tid)
        return tactic in lateral_tactics

    def is_valid_tactic_sequence(path: list[str]) -> bool:
        prev_tactic = None
        for i, n in enumerate(path):
            if not n.startswith('technique:'):
                continue
            tid = n.split(':', 1)[1]
            tac = technique_to_tactic.get(tid)
            if not tac:
                continue
            if prev_tactic is None:
                prev_tactic = tac
                continue
            if tac == prev_tactic:
                continue
            if tactic_order_index.get(tac, -1) < tactic_order_index.get(prev_tactic, -1):
                prev_tid = path[i - 1].split(':', 1)[1]
                if not _is_lateral_tech(prev_tid):
                    return False
            prev_tactic = tac
        return True

    def _tactic_rank(tac: str | None) -> int:
        return tactic_order_index.get(tac, -1) if tac else -1
    G = nx.DiGraph()
    G.add_edges_from(model.edges)
    all_paths = []

    def dfs(node, path, prob):
        path = path + [node]
        prob = prob * posterior.get(node, 0.01)
        successors = list(G.successors(node))
        if not successors:
            if is_valid_tactic_sequence(path):
                last_tac = next((technique_to_tactic.get(n.split(':', 1)[1]) for n in reversed(path) if n.startswith('technique:')), None)
                all_paths.append((path, prob, last_tac))
        else:
            for neighbor in successors:
                if neighbor not in path:
                    dfs(neighbor, path, prob)
    dfs(start_node, [], 1.0)
    all_paths.sort(key=lambda x: (_tactic_rank(x[2]), x[1]), reverse=True)
    return [(p, round(prob, 4)) for p, prob, _ in all_paths[:k]]