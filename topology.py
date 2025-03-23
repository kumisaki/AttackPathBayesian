# topology.py

import os
import csv
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from bson import ObjectId
from werkzeug.utils import secure_filename
from extensions import mongo

topo_bp = Blueprint("topo_bp", __name__)

@topo_bp.route('/')
def topology_list():
    """查看全部网络拓扑节点."""
    # 访问Mongo：mongo.db.network_topology
    topology_collection = mongo.db.network_topology
    all_nodes = list(topology_collection.find())
    return render_template('topology_list.html', nodes=all_nodes)

@topo_bp.route('/add', methods=['GET'])
def topology_add_page():
    """
    同一页面: 手动添加 or CSV上传.
    templates/topology_add_or_upload.html
    """
    return render_template('topology_add_or_upload.html')

@topo_bp.route('/add/manual', methods=['POST'])
def topology_add_manual():
    """手动添加拓扑节点."""
    topology_collection = mongo.db.network_topology

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
    return redirect(url_for('topo_bp.topology_list'))

@topo_bp.route('/add/upload', methods=['POST'])
def topology_add_upload():
    """CSV上传, 批量添加/更新拓扑节点."""
    topology_collection = mongo.db.network_topology

    if 'file' not in request.files:
        flash("没有检测到 'file' 字段", "danger")
        return redirect(url_for('topo_bp.topology_add_page'))

    file = request.files['file']
    if file.filename == '':
        flash("请选择要上传的 CSV 文件", "warning")
        return redirect(url_for('topo_bp.topology_add_page'))

    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        count = update_topology_from_csv(save_path, topology_collection)
        flash(f"已批量导入 {count} 条拓扑节点", "success")
        return redirect(url_for('topo_bp.topology_list'))
    else:
        flash("仅支持 CSV 文件", "danger")
        return redirect(url_for('topo_bp.topology_add_page'))

@topo_bp.route('/edit/<node_id>', methods=['GET', 'POST'])
def topology_edit(node_id):
    topology_collection = mongo.db.network_topology
    node = topology_collection.find_one({"_id": ObjectId(node_id)})
    if not node:
        flash("未找到该拓扑节点", "danger")
        return redirect(url_for('topo_bp.topology_list'))

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
        return redirect(url_for('topo_bp.topology_list'))

    # GET 请求
    return render_template('topology_edit.html', node=node)

@topo_bp.route('/delete/<node_id>')
def topology_delete(node_id):
    topology_collection = mongo.db.network_topology
    topology_collection.delete_one({"_id": ObjectId(node_id)})
    flash("拓扑节点已删除", "info")
    return redirect(url_for('topo_bp.topology_list'))

def update_topology_from_csv(csv_file_path, collection):
    """批量导入或更新网络拓扑节点."""
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
                continue

            existing = collection.find_one({"ip_address": ip_address})
            if existing:
                # update
                update_fields = {
                    "device_name": device_name,
                    "device_type": device_type,
                    "location": location,
                    "notes": notes
                }
                collection.update_one(
                    {"_id": existing["_id"]},
                    {"$set": update_fields}
                )
            else:
                # insert
                new_node = {
                    "device_name": device_name,
                    "ip_address": ip_address,
                    "device_type": device_type,
                    "location": location,
                    "notes": notes
                }
                collection.insert_one(new_node)
            count += 1
    return count

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'csv'
