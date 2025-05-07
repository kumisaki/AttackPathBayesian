def extract_attack_edges_with_techniques(model):
    """
    从贝叶斯网络中提取 (technique → compromised:device) 路径中对应的 src → tgt 映射。
    返回 {(deviceA, deviceB): technique_id}
    """
    edges = {}
    for src, tgt in model.edges:
        if src.startswith("technique:") and tgt.startswith("compromised:"):
            tid = src.split(":", 1)[1]
            dev_b = tgt.split(":", 1)[1]
            # 查找这个技术可能是从哪个设备发起的
            for parent in model.get_parents(src):
                if parent.startswith("compromised:"):
                    dev_a = parent.split(":", 1)[1]
                    edges[(dev_a, dev_b)] = tid
    return edges
