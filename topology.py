# topology.py
import os
import csv
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from extensions import mongo

topology_bp = Blueprint("topology_bp", __name__)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'csv'

@topology_bp.route('/list')
def list_topology():
    subnets = list(mongo.db.subnets.find({}))
    devices = list(mongo.db.devices.find({}))
    device_map = {}
    for device in devices:
        parent = device.get("parent_subnet", "")
        if parent not in device_map:
            device_map[parent] = []
        device_map[parent].append(device)
    return render_template("topology_list.html", subnets=subnets, device_map=device_map)

# Subnet CRUD
@topology_bp.route('/subnet/add', methods=["GET"])
def add_subnet_page():
    return render_template("subnet_add_or_upload.html")

# Manual add subnet route
@topology_bp.route('/subnet/add/manual', methods=["POST"])
def add_subnet_manual():
    subnet_id = request.form.get("subnet_id")
    label = request.form.get("label")
    connected_subnets = request.form.get("connected_subnets")  # Comma-separated
    if connected_subnets:
        connected = [s.strip() for s in connected_subnets.split(",") if s.strip()]
    else:
        connected = []
    mongo.db.subnets.insert_one({
        "_id": subnet_id,
        "label": label,
        "connected_subnets": connected
    })
    flash("Subnet added successfully (manual).", "success")
    return redirect(url_for("topology_bp.list_topology"))

# CSV upload for subnets route
@topology_bp.route('/subnet/add/upload', methods=["POST"])
def add_subnet_upload():
    if 'file' not in request.files:
        flash("No file part.", "danger")
        return redirect(url_for("topology_bp.add_subnet_page"))
    file = request.files['file']
    if file.filename == '':
        flash("No selected file.", "warning")
        return redirect(url_for("topology_bp.add_subnet_page"))
    if file and allowed_file(file.filename):
        from werkzeug.utils import secure_filename
        filename = secure_filename(file.filename)
        filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)
        count = 0
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                subnet_id = row.get("subnet_id")
                label = row.get("label")
                connected_subnets = row.get("connected_subnets", "")
                if connected_subnets:
                    connected = [s.strip() for s in connected_subnets.split(",") if s.strip()]
                else:
                    connected = []
                if not subnet_id:
                    continue
                mongo.db.subnets.insert_one({
                    "_id": subnet_id,
                    "label": label,
                    "connected_subnets": connected
                })
                count += 1
        flash(f"{count} subnets uploaded successfully.", "success")
        return redirect(url_for("topology_bp.list"))
    else:
        flash("Invalid file format. Only CSV allowed.", "danger")
        return redirect(url_for("topology_bp.add_subnet_page"))

@topology_bp.route('/edit/<subnet_id>', methods=["GET", "POST"])
def edit_subnet(subnet_id):
    subnet = mongo.db.subnets.find_one({"_id": subnet_id})
    if not subnet:
        flash("Subnet not found.", "danger")
        return redirect(url_for("topology_bp.list_topology"))
    if request.method == "POST":
        label = request.form.get("label")
        connected_subnets = request.form.get("connected_subnets")
        connected = [s.strip() for s in connected_subnets.split(",") if s.strip()] if connected_subnets else []
        mongo.db.subnets.update_one({"_id": subnet_id}, {"$set": {"label": label, "connected_subnets": connected}})
        flash("Subnet updated successfully.", "success")
        return redirect(url_for("topology_bp.list_topology"))
    return render_template("topology_edit.html", subnet=subnet)

@topology_bp.route('/delete/<subnet_id>')
def delete_subnet(subnet_id):
    mongo.db.subnets.delete_one({"_id": subnet_id})
    flash("Subnet deleted.", "info")
    return redirect(url_for("topology_bp.list_topology"))

# Device management
@topology_bp.route('/device/add', methods=["GET"])
def add_device_page():
    subnets = list(mongo.db.subnets.find({}))
    return render_template("device_add_or_upload.html", subnets=subnets)

@topology_bp.route('/device/add/manual', methods=["POST"])
def add_device_manual():
    device_id = request.form.get("device_id")
    label = request.form.get("label")
    ip_address = request.form.get("ip_address")
    os_info = request.form.get("os")
    parent_subnet = request.form.get("parent_subnet")
    mongo.db.devices.insert_one({
        "_id": device_id,
        "label": label,
        "ip_address": ip_address,
        "os": os_info,
        "parent_subnet": parent_subnet
    })
    flash("Device added successfully (manual).", "success")
    return redirect(url_for("topology_bp.list_topology"))

@topology_bp.route('/device/add/upload', methods=["POST"])
def add_device_upload():
    if 'file' not in request.files:
        flash("No file part.", "danger")
        return redirect(url_for("topology_bp.add_device_page"))
    file = request.files['file']
    if file.filename == '':
        flash("No selected file.", "warning")
        return redirect(url_for("topology_bp.add_device_page"))
    if file and allowed_file(file.filename):
        from werkzeug.utils import secure_filename
        filename = secure_filename(file.filename)
        filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)
        count = 0
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                device_id = row.get("device_id")
                label = row.get("label")
                ip_address = row.get("ip_address")
                os_info = row.get("os")
                parent_subnet = row.get("parent_subnet")
                if not device_id:
                    continue
                mongo.db.devices.insert_one({
                    "_id": device_id,
                    "label": label,
                    "ip_address": ip_address,
                    "os": os_info,
                    "parent_subnet": parent_subnet
                })
                count += 1
        flash(f"{count} devices uploaded successfully.", "success")
        return redirect(url_for("topology_bp.list_topology"))
    else:
        flash("Invalid file format. Only CSV allowed.", "danger")
        return redirect(url_for("topology_bp.add_device_page"))

@topology_bp.route('/device/edit/<device_id>', methods=["GET", "POST"])
def edit_device(device_id):
    device = mongo.db.devices.find_one({"_id": device_id})
    if not device:
        flash("Device not found.", "danger")
        return redirect(url_for("topology_bp.list_topology"))
    if request.method == "POST":
        label = request.form.get("label")
        ip_address = request.form.get("ip_address")
        os_info = request.form.get("os")
        parent_subnet = request.form.get("parent_subnet")
        mongo.db.devices.update_one({"_id": device_id}, {"$set": {
            "label": label,
            "ip_address": ip_address,
            "os": os_info,
            "parent_subnet": parent_subnet
        }})
        flash("Device updated successfully.", "success")
        return redirect(url_for("topology_bp.list_topology"))
    subnets = list(mongo.db.subnets.find({}))
    return render_template("device_edit.html", device=device, subnets=subnets)

@topology_bp.route('/device/delete/<device_id>')
def delete_device(device_id):
    mongo.db.devices.delete_one({"_id": device_id})
    flash("Device deleted.", "info")
    return redirect(url_for("topology_bp.list_topology"))
