# main.py
from flask import Flask, render_template
from extensions import mongo
from analysis import analysis_bp
from topology import topology_bp
from vulnerability import vuln_bp
import os

def create_app():
    app = Flask(__name__)
    app.secret_key = "YOUR_SECRET_KEY"  # Replace with your secure secret key
    app.config["MONGO_URI"] = "mongodb://localhost:27017/attack_db"

    print('starting app...')
    # Initialize PyMongo
    mongo.init_app(app)
    print('initialisation completed.')
    
    print('configuring folder...')
    # Configure uploads folder
    app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    print('folder is prepared.')

    print('registing modules...')
    # Register blueprints
    print('registing analysis module...')
    app.register_blueprint(analysis_bp, url_prefix="/analysis")
    print('analysis module is prepared.')
    print('registing topology module...')
    app.register_blueprint(topology_bp, url_prefix="/topology")
    print('topology module is prepared.')
    print('registing vulnerability module...')
    app.register_blueprint(vuln_bp, url_prefix="/vulnerability")
    print('vulnerability module is prepared.')

    @app.route("/")
    def index():
        return render_template("index.html")

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
