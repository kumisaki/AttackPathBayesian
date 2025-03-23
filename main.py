# main.py

import os
from flask import Flask, render_template
from extensions import mongo
from topology import topo_bp
from vulnerability import vuln_bp
from analysis import analysis_bp

def create_app():
    app = Flask(__name__)
    app.secret_key = "SOME_RANDOM_SECRET"

    # 配置 MongoDB
    app.config["MONGO_URI"] = "mongodb://localhost:27017/vuln_db"

    # 初始化 PyMongo
    mongo.init_app(app)  
    # 之后在其他模块中，可通过 from extensions import mongo 使用

    # 配置上传文件目录
    app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # 注册 Blueprint
    app.register_blueprint(topo_bp, url_prefix="/topology")
    app.register_blueprint(vuln_bp, url_prefix="/vulns")
    app.register_blueprint(analysis_bp, url_prefix="/analysis")

    # 路由: 首页
    @app.route('/')
    def index():
        return render_template('index.html')

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
