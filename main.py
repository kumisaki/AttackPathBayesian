from flask import Flask, render_template, request, redirect, url_for, flash, session
from extensions import get_project_db, project_admin, attack_reference
from utils.init_reference import init_attack_reference
from topology import topology_bp
from vulnerability import vuln_bp
from analysis import analysis_bp
import os

def create_app():
    # init_attack_reference() 
    app = Flask(__name__)
    app.secret_key = "your-secret-key"

    # 注册原有功能模块
    app.register_blueprint(topology_bp, url_prefix="/topology")
    app.register_blueprint(vuln_bp, url_prefix="/vulnerability")
    app.register_blueprint(analysis_bp, url_prefix="/analysis")

    # 首页：项目选择入口
    @app.route("/")
    def index():
        projects = list(project_admin["projects"].find({}))
        return render_template("project_selector.html", projects=projects)

    # 切换项目：将所选数据库名写入 session
    @app.route("/project/select", methods=["POST"])
    def select_project():
        dbname = request.form.get("project_db")
        if dbname:
            session["project_db"] = dbname
            flash(f"Switched to project: {dbname}", "success")
        else:
            flash("Project not selected", "danger")
        return redirect(url_for("index"))

    # 创建新项目
    @app.route("/project/create", methods=["POST"])
    def create_project():
        name = request.form.get("project_name")
        if not name:
            flash("Project name required", "danger")
            return redirect(url_for("index"))
        dbname = f"project_{name}"
        # 在主控项目表中注册
        project_admin["projects"].insert_one({"name": name, "db": dbname})
        flash(f"Project '{name}' created!", "success")
        return redirect(url_for("index"))

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
