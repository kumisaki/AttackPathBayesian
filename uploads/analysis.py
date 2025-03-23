# analysis.py

import os
import io
import networkx as nx
import matplotlib
matplotlib.use('Agg')  # 后端绘图，不弹窗
import matplotlib.pyplot as plt

from flask import Blueprint, request, make_response, render_template, current_app
from extensions import mongo
from bson import ObjectId

# pgmpy 的示例组件
from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD

analysis_bp = Blueprint("analysis_bp", __name__)

@analysis_bp.route('/attack_path')
def attack_path():
    """
    基于网络拓扑 & 漏洞信息，构建简易贝叶斯网络并返回可视化结果(PNG).
    """
    # 1) 从MongoDB获取数据
    topology_data = list(mongo.db.network_topology.find())
    vuln_data = list(mongo.db.vulnerabilities.find())

    # 2) 构建一个简单的DAG (示例)
    #    - Node: "Node_<ip>" 表示某IP设备被攻陷状态( True / False )
    #    - Edge: 如果网络拓扑上 IP1 能访问 IP2, 且 IP1 存在高危漏洞 => IP2 受影响
    
    # 我们先把 IP 作为节点
    ip_nodes = [f"Node_{doc['ip_address']}" for doc in topology_data if 'ip_address' in doc]
    
    # 这里先做个极简示例：只要 A(本机) 有个高危漏洞 => A 被攻陷 => 可能导致 B 被攻陷（若topology显示可到达）
    # 真实情况下，还要结合CVE概率, lateral movement的条件概率, etc.

    # 构建一个空的 BayesianNetwork (pgmpy 里DAG用List of edges)
    # 我们先收集所有 edges => [("Node_IP1", "Node_IP2"), ...]
    edges = []

    # 先把 IP->IP 关系从topology_data里推断 (假设有 "neighbors" 字段或 "connected_to" 之类)
    # 如果你的数据里是 "location" 或别的, 需要自己定义
    # 这里仅演示, 假设 topology 里每条记录形如:
    # { "ip_address": "10.1.3.8", "adjacent_ips": ["10.1.3.17", "10.1.5.21"], ... }
    for doc in topology_data:
        ip = doc.get("ip_address")
        if not ip:
            continue
        node_name = f"Node_{ip}"
        neighbors = doc.get("adjacent_ips", [])
        for nbr in neighbors:
            nbr_name = f"Node_{nbr}"
            # 这里示例: Node_ip --> Node_nbr
            edges.append((node_name, nbr_name))

    # 组装BayesianNetwork
    # (pgmpy要求DAG无环, 请确保topology不会形成环状, 否则要做裁剪)
    bn_model = BayesianNetwork(edges)

    # 3) 给每个节点定义 CPD
    #    这里只演示 "每个节点(设备)被攻陷" 的二元变量 True/False
    #    先给无父节点(入口点)一个先验, 给有父节点的做一个"多父" CPD(仅示例)

    # Step 3a) 先找bn_model中无父节点的Node
    for node in bn_model.nodes():
        parents = list(bn_model.predecessors(node))
        # Node命名规则: node = "Node_10.1.3.8"

        # 查找对应mongo漏洞信息, 例如:
        #   - 如果 IP 设备有CVSS=9.0 => 攻击成功概率 ~0.75
        #   - 这里为了简化, 只从 vulnerabilities里找与 node 对应的 doc, 取 attack_probability
        ip_addr = node.replace("Node_", "")
        vdoc = next((v for v in vuln_data if v.get("ip_address") == ip_addr), None)
        p_attack = 0.1  # 缺省
        if vdoc and "attack_probability" in vdoc:
            # 让p_attack = vdoc["attack_probability"]
            # 但别忘了vdoc里可能是0~1, 这里简化处理
            p_attack = float(vdoc["attack_probability"])

        if not parents:
            # 无父: 先验CPD: P(Node=True) = p_attack, P(Node=False) = 1-p_attack
            cpd = TabularCPD(
                variable=node,
                variable_card=2,
                values=[[1 - p_attack], [p_attack]],  # 先False后True
                state_names={node: [False, True]} 
            )
            bn_model.add_cpds(cpd)
        else:
            # 有父: 父节点True时 => 攻陷概率  ??? 
            # 这里示例: if ANY parent is True => 0.8, else => p_attack (简化)
            # 真实情况需定义TTC(时间)或多父合并规则
            parent_cards = {}
            for p in parents:
                parent_cards[p] = [False, True]

            # 构建全部父节点组合(2^N)
            import itertools
            parent_states = list(itertools.product([False, True], repeat=len(parents)))

            # 对应 each combination -> Node=False row, Node=True row
            cpd_values_false = []
            cpd_values_true = []

            for combo in parent_states:
                # if any parent == True => p=0.8
                if any(combo):
                    cpd_values_false.append(0.2)
                    cpd_values_true.append(0.8)
                else:
                    # if all false => fallback to p_attack
                    cpd_values_false.append(1 - p_attack)
                    cpd_values_true.append(p_attack)

            cpd = TabularCPD(
                variable=node,
                variable_card=2,
                values=[cpd_values_false, cpd_values_true],
                evidence=parents,
                evidence_card=[2]*len(parents),
                state_names={node: [False, True], **{p:[False,True] for p in parents}}
            )
            bn_model.add_cpds(cpd)

    # 4) 验证模型(可选)
    bn_model.check_model()

    # 5) 将此 BayesianNetwork 可视化
    #    我们示例用 networkx + matplotlib 生成一张 PNG
    fig = draw_bn_graph(bn_model)

    # 6) 返回PNG响应, 或者可先把图保存到 static/analysis.png 再render_template
    png_output = io.BytesIO()
    fig.savefig(png_output, format='png')
    plt.close(fig)  # 释放资源

    png_output.seek(0)
    # 直接返回image/png
    response = make_response(png_output.getvalue())
    response.headers['Content-Type'] = 'image/png'
    return response

# analysis.py

import math
from flask import Blueprint, render_template, jsonify
from extensions import mongo

analysis_bp = Blueprint("analysis_bp", __name__)

# @analysis_bp.route('/attack_path_interactive')
# def attack_path_interactive():
#     """
#     演示：基于网络拓扑 + 漏洞信息构建攻击路径，并返回一个可交互的Cytoscape图表。
#     """
#     # 1) 从Mongo获取拓扑和漏洞
#     topology_data = list(mongo.db.network_topology.find())
#     vuln_data = list(mongo.db.vulnerabilities.find())
    
#     # 2) 构造简易“节点-边”关系
#     #   假设 network_topology 每条记录形如:
#     #   { "ip_address": "10.1.3.8", "adjacent_ips": ["10.1.3.17"], ... }
#     #   并在 vulnerabilities 里查找相同 ip_address 获取 "attack_probability"
    
#     # 构建节点列表
#     nodes = []
#     for doc in topology_data:
#         ip = doc.get("ip_address")
#         if not ip:
#             continue
#         # 查找对应漏洞文档
#         vdoc = next((v for v in vuln_data if v.get("ip_address") == ip), None)
#         p_attack = vdoc.get("attack_probability", 0) if vdoc else 0
        
#         # 构造 cytoscape 节点对象
#         node_id = f"Node_{ip}"
#         node_label = ip
#         nodes.append({
#             "data": {
#                 "id": node_id,
#                 "label": node_label,
#                 "prob": p_attack
#             }
#         })
    
#     # 构建边列表
#     edges = []
#     for doc in topology_data:
#         ip = doc.get("ip_address")
#         if not ip: 
#             continue
#         src_node = f"Node_{ip}"
#         neighbors = doc.get("adjacent_ips", [])
#         for nbr_ip in neighbors:
#             dst_node = f"Node_{nbr_ip}"
#             edges.append({
#                 "data": {
#                     "source": src_node,
#                     "target": dst_node
#                 }
#             })
    
#     # 最终 elements = nodes + edges
#     elements = nodes + edges
    
#     # 3) 这里演示直接“渲染模板”，在模板中使用JS变量 "elements" 来初始化 Cytoscape
#     return render_template('analysis_attack_path.html', elements=elements)

@analysis_bp.route('/attack_path_interactive')
def attack_path_interactive():
    topology_data = list(mongo.db.network_topology.find())
    vuln_data = list(mongo.db.vulnerabilities.find())

    nodes = []
    edges = []

    for doc in topology_data:
        ip = doc.get("ip_address")
        if not ip:
            continue
        vdoc = next((v for v in vuln_data if v.get("ip_address") == ip), None)
        p_attack = vdoc.get("attack_probability", 0.0) if vdoc else 0.0

        node_id = f"Node_{ip}"
        nodes.append({
            "data": {
                "id": node_id,
                "label": ip,
                "prob": p_attack,
                "ip_address": ip,  # 或其它你想展示的字段
            }
        })

        neighbors = doc.get("adjacent_ips", [])
        for nbr_ip in neighbors:
            edges.append({
                "data": {
                    "source": node_id,
                    "target": f"Node_{nbr_ip}"
                }
            })

    elements = nodes + edges
    return render_template('analysis_attack_path.html', elements=elements)


def draw_bn_graph(bn_model: BayesianNetwork):
    """
    将pgmpy的DAG转换为NetworkX图，用matplotlib绘制并返回 Figure 对象。
    """
    G = nx.DiGraph()
    G.add_nodes_from(bn_model.nodes())
    G.add_edges_from(bn_model.edges())

    fig, ax = plt.subplots(figsize=(10, 6))
    pos = nx.spring_layout(G, k=1.0, iterations=50)
    nx.draw_networkx_nodes(G, pos, node_size=1200, node_color="lightblue", ax=ax)
    nx.draw_networkx_labels(G, pos, ax=ax, font_size=8)
    nx.draw_networkx_edges(G, pos, ax=ax, arrowstyle='->', arrowsize=15)
    ax.axis('off')
    return fig
