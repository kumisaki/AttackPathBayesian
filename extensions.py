from pymongo import MongoClient

# Global clients
shared_client = MongoClient("mongodb://localhost:27017")
project_admin = shared_client["project_admin"]
attack_reference = shared_client["attack_reference"]

def get_project_db(project_name):
    return shared_client[project_name]
