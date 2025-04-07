from collections import defaultdict
from typing import List, Dict

def estimate_parent_influence(target_node_id, target_type, parent_info, all_vulns, technique_score_map, technique_to_tactic_map):
    """
    Estimate influence from multiple parents.
    parent_info: list of (node_id, node_type)
    """

    tactic_weights = []
    influence_scores = []
    tactic_set = set()

    for pid, ptype in parent_info:
        if ptype == "device":
            # 取该设备的漏洞
            vulns = [v for v in all_vulns if v.get("parent_device_id") == pid]
            if not vulns:
                continue
            # 对该设备的漏洞求一个最大评分
            scores = []
            tactics = set()
            for v in vulns:
                cvss = float(v.get("cvss", 5.0))
                epss = float(v.get("epss", 0.0))
                p = (cvss / 10.0) * (0.5 + epss)
                if epss < 0.1:
                    p *= 0.5  # 🎯 EPS<0.1降低影响
                scores.append(p)
                # 收集漏洞的 tactic（通过 technique）
                for tid in v.get("attack_techniques", []):
                    if tactic := technique_to_tactic_map.get(tid):
                        tactics.add(tactic)

            influence_scores.append(max(scores))
            tactic_set.update(tactics)
            tactic_weights.append(tactics)

        elif ptype == "technique":
            score = technique_score_map.get(pid, 0.3)
            if score < 0.1:
                score *= 0.5
            influence_scores.append(score)
            tactic = technique_to_tactic_map.get(pid)
            tactic_set.add(tactic)
            tactic_weights.append({tactic})

    if not influence_scores:
        return 0.3  # fallback

    # 🎯 tactic 多样性评分
    distinct_tactic_count = len(set.union(*tactic_weights)) if tactic_weights else 0
    all_same = all(t == tactic_weights[0] for t in tactic_weights)
    
    if all_same:
        tactic_adjust = 0.7  # tactic repeate → turn down
    elif distinct_tactic_count > 1:
        tactic_adjust = 1.2  # tactic shows strong diversity → turnup
    else:
        tactic_adjust = 1.0

    # multiple parent Normalize to average instead of product
    base_score = sum(influence_scores) / len(influence_scores)

    return min(1.0, base_score * tactic_adjust)

# utils/estimat_probabilities.py

def compute_structural_probability(parents, node, technique_score_map, technique_to_tactic_map, vulnerabilities):
    """
    Estimate structural probability of a node given its parents.
    Uses tactic overlap, technique scores, and EPSS modifiers.

    Arguments:
    - parents: list of parent node ids (e.g., 'technique:T0803' or 'compromised:plc-01')
    - node: current node id
    - technique_score_map: map of technique_id → float score
    - technique_to_tactic_map: map of technique_id → tactic_id
    - vulnerabilities: all vulnerability entries

    Returns:
    - float: estimated probability between 0.0 and 1.0
    """
    parent_info = []
    for p in parents:
        pid = p.split(":")[1]
        ptype = "device" if p.startswith("compromised:") else "technique"
        tacs = set()

        if ptype == "device":
            vulns = [v for v in vulnerabilities if v.get("parent_device_id") == pid]
            for v in vulns:
                for tid in v.get("attack_techniques", []):
                    tacs.add(technique_to_tactic_map.get(tid))
        else:
            tacs.add(technique_to_tactic_map.get(pid))

        base_score = 0.6 + 0.1 * len(tacs) if ptype == "device" else technique_score_map.get(pid, 0.5)
        if ptype == "technique":
            for v in vulnerabilities:
                if pid in v.get("attack_techniques", []):
                    if float(v.get("epss", 0)) < 0.1:
                        base_score *= 0.5

        parent_info.append({"id": pid, "type": ptype, "tactics": tacs, "score": base_score})

    # tactic overlap analysis
    tactic_sets = [p["tactics"] for p in parent_info]
    total_tactics = set.union(*tactic_sets) if tactic_sets else set()
    overlap_count = sum(len(total_tactics & p["tactics"]) > 0 for p in parent_info)

    tactic_weight = 0.7 if overlap_count == len(parent_info) else 1.2
    avg_score = sum(p["score"] for p in parent_info) / len(parent_info) if parent_info else 0.1

    return round(min(1.0, avg_score * tactic_weight), 3)
