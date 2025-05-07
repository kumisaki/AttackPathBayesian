"""
Helper functions to estimate conditional probability distributions (CPDs).
This module supports computing node activation probabilities in Bayesian attack graphs.
"""

from __future__ import annotations
from typing import Dict, List, Mapping, Sequence, Set, Tuple

MIN_PROB, MAX_PROB = 0.0, 1.0
TACTIC_REPEAT_FACTOR = 0.7      # all tactics identical → down-weight
TACTIC_DIVERSE_FACTOR = 1.2     # tactics diverse      → up-weight
DEFAULT_PROB = 0.3


def _clamp(x: float, low: float = MIN_PROB, high: float = MAX_PROB) -> float:
    return max(low, min(high, x))

def estimate_parent_influence(
    parent_info: Sequence[Tuple[str, str]],
    *,
    device_vulns: Mapping[str, Sequence[dict]],
    technique_score_map: Mapping[str, float],
    technique_to_tactic_map: Mapping[str, str],
    future_children: Sequence[str] = (),
    tactic_order: Mapping[str, Sequence[str]] = {},
) -> float:
    """Return P(child=1 | given active parents), considering future propagation potential."""
    scores: List[float] = []
    tactic_sets: List[Set[str]] = []

    def _can_progress(t1: str, t2: str, order_map: Mapping[str, Sequence[str]]) -> bool:
        return t2 in order_map.get(t1, [])

    for pid, ptype in parent_info:
        if ptype == "device":
            vulns = device_vulns.get(pid, ())
            if not vulns:
                continue
            s = max(
                _clamp((float(v.get("cvss", 5.0)) / 10) * (0.5 + float(v.get("epss", 0))))
                * (0.5 if float(v.get("epss", 0)) < 0.1 else 1.0)
                for v in vulns
            )
            scores.append(s)
            tactic_sets.append(
                {
                    technique_to_tactic_map[tid]
                    for v in vulns
                    for tid in v.get("attack_techniques", [])
                    if tid in technique_to_tactic_map
                }
            )
        else:  # technique
            s = _clamp(technique_score_map.get(pid, DEFAULT_PROB))
            if s < 0.1:
                s *= 0.5
            scores.append(s)
            tactic_sets.append({technique_to_tactic_map.get(pid)})

    if not scores:
        return DEFAULT_PROB

    # --- Adjust based on diversity of tactics among parent nodes ---
    if not tactic_sets:
        diversity = 1.0
    elif all(ts == tactic_sets[0] for ts in tactic_sets):
        diversity = TACTIC_REPEAT_FACTOR
    elif len(set().union(*tactic_sets)) > 1:
        diversity = TACTIC_DIVERSE_FACTOR
    else:
        diversity = 1.0

    base = _clamp(sum(scores) / len(scores) * diversity)

    # --- Apply bonus if child node can propagate to diverse future tactics ---
    if future_children:
        tactics = {
            technique_to_tactic_map.get(tid.split(":", 1)[1])
            for tid in future_children
            if tid.startswith("technique:") and tid.split(":", 1)[1] in technique_to_tactic_map
        }
        tactics = {t for t in tactics if t}

        found_progression = False
        tactics = list(tactics)
        for i in range(len(tactics)):
            for j in range(i + 1, len(tactics)):
                if _can_progress(tactics[i], tactics[j], tactic_order) or \
                _can_progress(tactics[j], tactics[i], tactic_order):
                    found_progression = True
                    break
            if found_progression:
                break

        if found_progression:
            base *= 1.15  # Forward propagation bonus

    return _clamp(base)


def compute_structural_probability(
    parents: Sequence[str],
    node: str,
    *,
    technique_score_map: Mapping[str, float],
    technique_to_tactic_map: Mapping[str, str],
    vulnerabilities: Sequence[dict],
) -> float:
    device_idx: Dict[str, List[dict]] = {}
    for v in vulnerabilities:
        dev = v.get("parent_device_id")
        if dev:
            device_idx.setdefault(dev, []).append(v)

    info = [
        (p.split(":", 1)[1], "device" if p.startswith("compromised:") else "technique")
        for p in parents
    ]
    return estimate_parent_influence(
        parent_info=info,
        device_vulns=device_idx,
        technique_score_map=technique_score_map,
        technique_to_tactic_map=technique_to_tactic_map,
    )
