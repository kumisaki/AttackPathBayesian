# app.py
import os
import csv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_pymongo import PyMongo
from bson import ObjectId
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "SOME_RANDOM_SECRET"  # 用于 flash 等功能

# ---------------------
# 1. 配置 MongoDB
# ---------------------
app.config["MONGO_URI"] = "mongodb://localhost:27017/vuln_db" 
mongo = PyMongo(app)

# 漏洞信息存储在 "vulnerabilities" 集合
vuln_collection = mongo.db.vulnerabilities

# 网络拓扑信息存储在 "network_topology" 集合
topology_collection = mongo.db.network_topology

# ---------------------
# 2. 上传文件配置
# ---------------------
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'csv'}

def allowed_file(filename):
    """判断文件扩展名是否属于允许的 CSV."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------------
# 3. 小工具函数
# ---------------------
def calc_attack_probability(cvss: float, epss: float) -> float:
    """
    演示用：根据CVSS(0~10)与EPSS(0~1)，算出一个大致的攻击成功概率(0~1).
    可根据需要改成更复杂的贝叶斯或其他计算。
    """
    cvss_scaled = cvss / 10.0
    prob = 1 - (1 - cvss_scaled) * (1 - epss)
    return round(prob, 3)

# ---------------------
# 4. 主页
# ---------------------
@app.route('/')
def index():
    return render_template('index.html')

# ------------------------------------------------------------------------------
# 5. 漏洞管理功能
#    - list: /vulns
#    - add or upload: /vulns/add
#    - edit: /vulns/edit/<id>
#    - delete: /vulns/delete/<id>
# ------------------------------------------------------------------------------
@app.route('/vulns')
def vuln_list():
    """查看全部漏洞列表."""
    all_vulns = list(vuln_collection.find())
    return render_template('vuln_list.html', vulns=all_vulns)

@app.route('/vulns/add', methods=['GET'])
def vuln_add_page():
    """
    显示同一页面:
    1) 手动添加漏洞
    2) 上传CSV批量添加
    """
    return render_template('vuln_add_or_upload.html')

@app.route('/vulns/add/manual', methods=['POST'])
def vuln_add_manual():
    """处理手动添加漏洞的表单."""
    ip_address = request.form.get('ip_address', '')
    cve_id = request.form.get('cve_id', '')
    description = request.form.get('description', '')
    cvss_str = request.form.get('cvss', '0')
    epss_str = request.form.get('epss', '0')
    severity = request.form.get('severity', '')

    try:
        cvss_val = float(cvss_str)
    except:
        cvss_val = 0.0
    try:
        epss_val = float(epss_str)
    except:
        epss_val = 0.0

    # 计算概率
    attack_prob = calc_attack_probability(cvss_val, epss_val)
    new_doc = {
        "ip_address": ip_address,
        "cve_id": cve_id,
        "description": description,
        "cvss": cvss_val,
        "epss": epss_val,
        "severity": severity,
        "attack_probability": attack_prob
    }
    vuln_collection.insert_one(new_doc)
    flash("已手动添加漏洞信息", "success")
    return redirect(url_for('vuln_list'))

@app.route('/vulns/add/upload', methods=['POST'])
def vuln_add_upload():
    """处理CSV上传，批量添加漏洞."""
    if 'file' not in request.files:
        flash("没有检测到 'file' 字段", "danger")
        return redirect(url_for('vuln_add_page'))

    file = request.files['file']
    if file.filename == '':
        flash("请选择要上传的 CSV 文件", "warning")
        return redirect(url_for('vuln_add_page'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        count = update_vuln_from_csv(save_path)
        flash(f"已批量更新/添加 {count} 条漏洞", "success")
        return redirect(url_for('vuln_list'))
    else:
        flash("仅支持 CSV 文件", "danger")
        return redirect(url_for('vuln_add_page'))

def update_vuln_from_csv(csv_path: str) -> int:
    """
    从CSV解析漏洞信息(含IP、CVE、CVSS等)，更新或插入 vulnerabilities 集合.
    这里用 cve_id 来判断是否已存在:
      - 如果找到相同 cve_id, 就更新
      - 否则插入新记录
    """
    updated_count = 0
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row.get('cve_id', '').strip()
            ip_addr = row.get('ip_address', '').strip()
            desc = row.get('description', '')
            cvss_str = row.get('cvss', '0')
            epss_str = row.get('epss', '0')
            severity = row.get('severity', '')

            try:
                cvss_val = float(cvss_str)
            except:
                cvss_val = 0.0
            try:
                epss_val = float(epss_str)
            except:
                epss_val = 0.0

            if not cve_id:
                # 如果没有 cve_id 就跳过
                continue

            doc = vuln_collection.find_one({"cve_id": cve_id})
            if doc:
                # 更新
                attack_prob = calc_attack_probability(cvss_val, epss_val)
                vuln_collection.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {
                        "ip_address": ip_addr,
                        "description": desc,
                        "cvss": cvss_val,
                        "epss": epss_val,
                        "severity": severity,
                        "attack_probability": attack_prob
                    }}
                )
            else:
                # 插入
                attack_prob = calc_attack_probability(cvss_val, epss_val)
                new_vuln = {
                    "ip_address": ip_addr,
                    "cve_id": cve_id,
                    "description": desc,
                    "cvss": cvss_val,
                    "epss": epss_val,
                    "severity": severity,
                    "attack_probability": attack_prob
                }
                vuln_collection.insert_one(new_vuln)
            updated_count += 1
    return updated_count

@app.route('/vulns/edit/<vuln_id>', methods=['GET', 'POST'])
def vuln_edit(vuln_id):
    """编辑漏洞信息."""
    doc = vuln_collection.find_one({"_id": ObjectId(vuln_id)})
    if not doc:
        flash("未找到该漏洞", "danger")
        return redirect(url_for('vuln_list'))
    
    if request.method == 'POST':
        ip_address = request.form.get('ip_address', '')
        cve_id = request.form.get('cve_id', '')
        description = request.form.get('description', '')
        cvss_str = request.form.get('cvss', '0')
        epss_str = request.form.get('epss', '0')
        severity = request.form.get('severity', '')

        try:
            cvss_val = float(cvss_str)
        except:
            cvss_val = 0.0
        try:
            epss_val = float(epss_str)
        except:
            epss_val = 0.0

        attack_prob = calc_attack_probability(cvss_val, epss_val)

        vuln_collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {
                "ip_address": ip_address,
                "cve_id": cve_id,
                "description": description,
                "cvss": cvss_val,
                "epss": epss_val,
                "severity": severity,
                "attack_probability": attack_prob
            }}
        )
        flash("漏洞已更新", "success")
        return redirect(url_for('vuln_list'))
    
    # GET 请求时渲染编辑页面
    return render_template('vuln_edit.html', vuln=doc)

@app.route('/vulns/delete/<vuln_id>')
def vuln_delete(vuln_id):
    """删除漏洞记录."""
    vuln_collection.delete_one({"_id": ObjectId(vuln_id)})
    flash("漏洞已删除", "info")
    return redirect(url_for('vuln_list'))

# ------------------------------------------------------------------------------
# 6. 网络拓扑管理功能
#    - list: /topology
#    - add or upload: /topology/add
#    - edit: /topology/edit/<id>
#    - delete: /topology/delete/<id>
# ------------------------------------------------------------------------------
@app.route('/topology')
def topology_list():
    """查看全部网络拓扑节点."""
    all_nodes = list(topology_collection.find())
    return render_template('topology_list.html', nodes=all_nodes)

@app.route('/topology/add', methods=['GET'])
def topology_add_page():
    """
    同一页面: 手动添加 or CSV上传
    """
    return render_template('topology_add_or_upload.html')

@app.route('/topology/add/manual', methods=['POST'])
def topology_add_manual():
    """手动添加拓扑节点."""
    device_name = request.form.get('device_name', '')
    ip_address = request.form.get('ip_address', '')
    device_type = request.form.get('device_type', '')
    location = request.form.get('location', '')
    notes = request.form.get('notes', '')

    new_node = {
        "device_name": device_name,
        "ip_address": ip_address,
        "device_type": device_type,
        "location": location,
        "notes": notes
    }
    topology_collection.insert_one(new_node)
    flash("拓扑节点已添加", "success")
    return redirect(url_for('topology_list'))

@app.route('/topology/add/upload', methods=['POST'])
def topology_add_upload():
    """CSV上传, 批量添加/更新拓扑节点."""
    if 'file' not in request.files:
        flash("没有检测到 'file' 字段", "danger")
        return redirect(url_for('topology_add_page'))

    file = request.files['file']
    if file.filename == '':
        flash("请选择要上传的 CSV 文件", "warning")
        return redirect(url_for('topology_add_page'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        count = update_topology_from_csv(save_path)
        flash(f"已批量导入 {count} 条拓扑节点", "success")
        return redirect(url_for('topology_list'))
    else:
        flash("仅支持 CSV 文件", "danger")
        return redirect(url_for('topology_add_page'))

def update_topology_from_csv(csv_file_path: str) -> int:
    """
    批量导入或更新网络拓扑节点. 
    示例逻辑: 如果数据库里有相同 ip_address, 则更新, 否则插入.
    """
    count = 0
    with open(csv_file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            device_name = row.get('device_name', '').strip()
            ip_address = row.get('ip_address', '').strip()
            device_type = row.get('device_type', '').strip()
            location = row.get('location', '').strip()
            notes = row.get('notes', '').strip()

            if not ip_address:
                # 若缺失IP，则跳过
                continue

            existing = topology_collection.find_one({"ip_address": ip_address})
            if existing:
                # 更新
                update_fields = {
                    "device_name": device_name,
                    "device_type": device_type,
                    "location": location,
                    "notes": notes
                }
                topology_collection.update_one(
                    {"_id": existing["_id"]},
                    {"$set": update_fields}
                )
            else:
                # 插入
                new_node = {
                    "device_name": device_name,
                    "ip_address": ip_address,
                    "device_type": device_type,
                    "location": location,
                    "notes": notes
                }
                topology_collection.insert_one(new_node)
            count += 1

    return count

@app.route('/topology/edit/<node_id>', methods=['GET', 'POST'])
def topology_edit(node_id):
    """编辑拓扑节点."""
    node = topology_collection.find_one({"_id": ObjectId(node_id)})
    if not node:
        flash("未找到该拓扑节点", "danger")
        return redirect(url_for('topology_list'))

    if request.method == 'POST':
        device_name = request.form.get('device_name', '')
        ip_address = request.form.get('ip_address', '')
        device_type = request.form.get('device_type', '')
        location = request.form.get('location', '')
        notes = request.form.get('notes', '')

        update_fields = {
            "device_name": device_name,
            "ip_address": ip_address,
            "device_type": device_type,
            "location": location,
            "notes": notes
        }
        topology_collection.update_one(
            {"_id": node["_id"]},
            {"$set": update_fields}
        )
        flash("拓扑节点已更新", "success")
        return redirect(url_for('topology_list'))

    # GET 请求: 显示编辑页面
    return render_template('topology_edit.html', node=node)

@app.route('/topology/delete/<node_id>')
def topology_delete(node_id):
    """删除拓扑节点."""
    topology_collection.delete_one({"_id": ObjectId(node_id)})
    flash("拓扑节点已删除", "info")
    return redirect(url_for('topology_list'))

# ---------------------
# 7. 启动应用
# ---------------------
if __name__ == '__main__':
    # 确保上传目录存在
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    app.run(debug=True)
