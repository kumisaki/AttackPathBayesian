from pymongo import MongoClient

# connect to main control databse（used to store metadata of the project）
client_admin = MongoClient("mongodb://localhost:27017")
project_admin = client_admin["project_admin"]

client_ref = MongoClient("mongodb://localhost:27017")
attack_reference = client_ref["attack_reference"]

# get the databse dynamically according to specific project name
def get_project_db(project_name):
    client = MongoClient("mongodb://localhost:27017")
    return client[project_name]
