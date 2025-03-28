# topology.py
import os
import csv
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, session
from extensions import get_project_db
from io import StringIO
import ipaddress
import json


topology_bp = Blueprint("topology_bp", __name__)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'csv'

@topology_bp.route('/list')
def list_topology():
    db = get_project_db(session["project_db"])
    subnets = list(db.subnets.find({}))
    devices = list(db.devices.find({}))

    # Map: subnet_id -> list of devices connected to it
    device_map = {subnet["_id"]: [] for subnet in subnets}

    for device in devices:
        for iface in device.get("interfaces", []):
            subnet_id = iface.get("subnet")
            if subnet_id in device_map:
                device_map[subnet_id].append(device)

    return render_template("topology_list.html", subnets=subnets, device_map=device_map)

# Subnet CRUD
@topology_bp.route('/subnet/add', methods=["GET"])
def add_subnet_page():
    return render_template("subnet_add_or_upload.html")

# Manual add subnet route
@topology_bp.route('/subnet/add/manual', methods=["POST"])
def add_subnet_manual():
    db = get_project_db(session["project_db"])
    subnet_id = request.form.get("subnet_id")
    label = request.form.get("label")
    cidr = request.form.get("cidr")
    zone = request.form.get("zone")
    vlan_id = request.form.get("vlan_id")
    note = request.form.get("note")

    subnet_doc = {
        "_id": subnet_id,
        "label": label,
        "cidr": cidr,
        "zone": zone,
        "note": note
    }

    if vlan_id and vlan_id.isdigit():
        subnet_doc["vlan_id"] = int(vlan_id)

    db.subnets.insert_one(subnet_doc)
    flash("Subnet added successfully (manual).", "success")
    return redirect(url_for("topology_bp.list_topology"))

# CSV upload for subnets route
@topology_bp.route('/subnet/add/upload', methods=["POST"])
def add_subnet_upload():
    db = get_project_db(session["project_db"])

    if 'file' not in request.files:
        flash("No file part.", "danger")
        return redirect(url_for("topology_bp.add_subnet_page"))

    file = request.files['file']
    if file.filename == '':
        flash("No selected file.", "warning")
        return redirect(url_for("topology_bp.add_subnet_page"))

    stream = StringIO(file.stream.read().decode("utf-8"))
    reader = csv.DictReader(stream)

    subnets = []
    for row in reader:
        subnet = {
            "_id": row.get("_id") or row.get("subnet_id"),
            "label": row.get("label"),
            "cidr": row.get("cidr"),
            "zone": row.get("zone"),
            "note": row.get("note"),
        }
        vlan_raw = row.get("vlan_id")
        if vlan_raw and vlan_raw.isdigit():
            subnet["vlan_id"] = int(vlan_raw)
        subnets.append(subnet)

    if subnets:
        db.subnets.insert_many(subnets)
        flash(f"{len(subnets)} subnets uploaded.", "success")
    else:
        flash("No valid subnet records found.", "warning")

    return redirect(url_for("topology_bp.list_topology"))

@topology_bp.route('/edit/<subnet_id>', methods=["GET", "POST"])
def edit_subnet(subnet_id):
    db = get_project_db(session["project_db"])
    subnet = db.subnets.find_one({"_id": subnet_id})
    if not subnet:
        flash("Subnet not found.", "danger")
        return redirect(url_for("topology_bp.list_topology"))

    if request.method == "POST":
        label = request.form.get("label")
        cidr = request.form.get("cidr")
        zone = request.form.get("zone")
        vlan_id = request.form.get("vlan_id")
        note = request.form.get("note")

        update_fields = {
            "label": label,
            "cidr": cidr,
            "zone": zone,
            "note": note
        }

        if vlan_id and vlan_id.isdigit():
            update_fields["vlan_id"] = int(vlan_id)

        db.subnets.update_one({"_id": subnet_id}, {"$set": update_fields})
        flash("Subnet updated successfully.", "success")
        return redirect(url_for("topology_bp.list_topology"))

    return render_template("topology_edit.html", subnet=subnet)

@topology_bp.route('/delete/<subnet_id>')
def delete_subnet(subnet_id):
    get_project_db(session["project_db"]).subnets.delete_one({"_id": subnet_id})
    flash("Subnet deleted.", "info")
    return redirect(url_for("topology_bp.list_topology"))

# Device management
@topology_bp.route('/device/add', methods=["GET"])
def add_device_page():
    subnets = list(get_project_db(session["project_db"]).subnets.find({}))
    return render_template("device_add_or_upload.html", subnets=subnets)

@topology_bp.route('/device/add/manual', methods=["POST"])
def add_device_manual():
    db = get_project_db(session["project_db"])

    # Get form fields
    device_id = request.form.get("device_id")
    label = request.form.get("label")
    device_type = request.form.get("device_type")
    os_info = request.form.get("os")
    interfaces_json = request.form.get("interfaces_json")

    # Load interface list
    try:
        interfaces = json.loads(interfaces_json)
    except:
        interfaces = []

    # Fetch all subnets to assist in subnet matching
    subnet_docs = list(db.subnets.find({}))
    for iface in interfaces:
        if not iface.get("subnet") and iface.get("ip_address"):
            try:
                ip_obj = ipaddress.ip_address(iface["ip_address"])
                for subnet in subnet_docs:
                    if "cidr" in subnet and ip_obj in ipaddress.ip_network(subnet["cidr"]):
                        iface["subnet"] = subnet["_id"]
                        break
            except:
                continue

    # Insert new device document
    db.devices.insert_one({
        "_id": device_id,
        "label": label,
        "device_type": device_type,
        "os": os_info,
        "interfaces": interfaces
    })
    print(interfaces_json, interfaces)
    flash("Device added successfully.", "success")
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
                try:
                    interfaces = json.loads(row.get("interfaces", "[]"))
                    # Auto-match subnet for interfaces without subnet
                    for iface in interfaces:
                        if not iface.get("subnet") and iface.get("ip_address"):
                            try:
                                ip_obj = ipaddress.ip_address(iface["ip_address"])
                                for subnet in subnet_docs:
                                    if "cidr" in subnet and ip_obj in ipaddress.ip_network(subnet["cidr"]):
                                        iface["subnet"] = subnet["_id"]
                                        break
                            except:
                                continue

                    devices.append({
                        "_id": row["_id"],
                        "label": row["label"],
                        "device_type": row.get("device_type", "unknown"),
                        "os": row.get("os", ""),
                        "interfaces": interfaces
                    })
                except Exception as e:
                    print("Error parsing row:", row, "Error:", e)
                    flash(f"Error parsing row: {row.get('_id')}", "danger")
        if devices:
            db.devices.insert_many(devices)
            flash(f"{len(devices)} devices uploaded!", "success")
        return redirect(url_for("topology_bp.list_topology"))
    else:
        flash("Invalid file format. Only CSV allowed.", "danger")
        return redirect(url_for("topology_bp.add_device_page"))

@topology_bp.route("/device/edit/<device_id>", methods=["GET", "POST"])
def edit_device(device_id):
    db = get_project_db(session["project_db"])
    device = db.devices.find_one({"_id": device_id})
    if not device:
        flash("Device not found.", "danger")
        return redirect(url_for("topology_bp.list_topology"))

    if request.method == "POST":
        label = request.form.get("label")
        os_info = request.form.get("os")
        device_type = request.form.get("device_type")
        interfaces_json = request.form.get("interfaces_json")

        # Parse interfaces from JSON
        try:
            interfaces = json.loads(interfaces_json)
        except:
            interfaces = []

        # Fetch all subnets for IP-to-subnet matching
        subnet_docs = list(db.subnets.find({}))
        for iface in interfaces:
            if not iface.get("subnet") and iface.get("ip_address"):
                try:
                    ip_obj = ipaddress.ip_address(iface["ip_address"])
                    for subnet in subnet_docs:
                        if "cidr" in subnet and ip_obj in ipaddress.ip_network(subnet["cidr"]):
                            iface["subnet"] = subnet["_id"]
                            break
                except:
                    continue

        # Update device document
        db.devices.update_one({"_id": device_id}, {"$set": {
            "label": label,
            "device_type": device_type,
            "os": os_info,
            "interfaces": interfaces
        }})

        flash("Device updated successfully.", "success")
        return redirect(url_for("topology_bp.list_topology"))

    return render_template("device_edit.html", device=device)


@topology_bp.route('/device/delete/<device_id>')
def delete_device(device_id):
    get_project_db(session["project_db"]).devices.delete_one({"_id": device_id})
    flash("Device deleted.", "info")
    return redirect(url_for("topology_bp.list_topology"))
