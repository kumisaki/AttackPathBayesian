from flask import Flask, render_template, request, redirect, url_for, flash, session
from pymongo import MongoClient
from extensions import get_project_db, project_admin, attack_reference
from utils.init_reference import init_attack_reference
from topology import topology_bp
from vulnerability import vuln_bp
from analysis import analysis_bp
# from attack_topology_view import attack_topology_bp
import os

def create_app():
    # init_attack_reference() 
    app = Flask(__name__)
    app.secret_key = "your-secret-key"

    # Configure uploads folder
    app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    print('folder is prepared.')

    # Register blueprints
    app.register_blueprint(topology_bp, url_prefix="/topology")
    app.register_blueprint(vuln_bp, url_prefix="/vulnerability")
    app.register_blueprint(analysis_bp, url_prefix="/analysis")
    
    # app.register_blueprint(attack_topology_bp, url_prefix="/attack")

    # Home page: create new project/select a project
    @app.route("/")
    def index():
        projects = list(project_admin["projects"].find({}))
        return render_template("project_selector.html", projects=projects)

    # Change Project：put the databse name into session
    @app.route("/project/select", methods=["POST"])
    def select_project():
        dbname = request.form.get("project_db")
        if dbname:
            session["project_db"] = dbname
            flash(f"Switched to project: {dbname}", "success")
        else:
            flash("Project not selected", "danger")
        return redirect(url_for("index"))

    # Create new project
    @app.route("/project/create", methods=["POST"])
    def create_project():
        name = request.form.get("project_name")
        if not name:
            flash("Project name required", "danger")
            return redirect(url_for("index"))

        dbname = f"project_{name}"
        
        # Check for duplication
        if project_admin["projects"].find_one({"db": dbname}):
            flash(f"Project '{name}' already exists!", "warning")
            return redirect(url_for("index"))

        # Register in control DB
        project_admin["projects"].insert_one({"name": name, "db": dbname})

        # Create new MongoDB database by inserting dummy data
        client = MongoClient("mongodb://localhost:27017")
        new_db = client[dbname]
        new_db.subnets.insert_one({"_id": "__init__", "label": "init", "connected_subnets": []})
        new_db.subnets.delete_one({"_id": "__init__"})

        flash(f"Project '{name}' created!", "success")
        return redirect(url_for("index"))

    @app.route('/set_project/<project_id>')
    def set_project(project_id):
        session['project_db'] = project_id
        return redirect(request.referrer or url_for('index'))
    
    @app.context_processor
    def inject_project_context():
        return get_project_context()

    return app

def get_project_context():
    current_db = session.get("project_db")
    project_doc = get_project_db("project_admin").projects.find_one({"db": current_db})
    # print(current_db, project_doc)
    return {
        "current_project_name": project_doc["name"] if project_doc else "(No project selected)",
        "current_project_db": current_db,
        "available_projects": list(
            get_project_db("project_admin").projects.find({}, {"name": 1, "db": 1})
        )
    }

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
