from extensions import get_project_db, attack_reference
from flask import session
from typing import Any, Dict, List

def get_current_project_db():
    db = session.get('project_db')
    if not db:
        raise KeyError('project_db missing from session')
    return get_project_db(db)

def get_devices() -> List[Dict[str, Any]]:
    devices = list(get_current_project_db().devices.find({}))
    for d in devices:
        d['_id'] = str(d['_id'])
    return devices

def get_subnets() -> List[Dict[str, Any]]:
    return list(get_current_project_db().subnets.find({}))

def get_vulnerabilities() -> List[Dict[str, Any]]:
    return list(get_current_project_db().vulnerabilities.find({}))

def get_firewall_rules() -> List[Dict[str, Any]]:
    return list(get_current_project_db().firewall_rules.find({}))

def get_techniques(q: str = None) -> list:
    if q:
        return list(attack_reference.techniques.find({"technique_name": {"$regex": q, "$options": "i"}}).limit(20))
    else:
        return list(attack_reference.techniques.find({}))

def get_techniques_by_ids(technique_ids: list) -> list:
    return list(attack_reference.techniques.find({"technique_id": {"$in": technique_ids}}))

def get_tactics() -> List[Dict[str, Any]]:
    return list(attack_reference.tactics.find({}))

def get_tactics_by_ids(tactic_ids: list) -> list:
    return list(attack_reference.tactics.find({"tactic_id": {"$in": tactic_ids}}))

def get_technique_to_tactic_map() -> Dict[str, str]:
    mappings = attack_reference.techniques_to_tactics.find({})
    return {m['technique_id']: m['tactic_id'] for m in mappings}

def get_tactic_chain() -> List[Dict[str, Any]]:
    return list(attack_reference.tactic_chain.find({}))

def get_technique_map() -> Dict[str, Any]:
    return {t['technique_id']: t for t in get_techniques()}

def get_tactic_map() -> Dict[str, Any]:
    return {t['tactic_id']: t for t in get_tactics()}

def get_device_map() -> Dict[str, Any]:
    return {str(d['_id']): d for d in get_devices()}

def get_technique_to_tactic_mappings_by_ids(technique_ids: list) -> list:
    return list(attack_reference.techniques_to_tactics.find({"technique_id": {"$in": technique_ids}})) 