from pymongo import MongoClient

# 固定连接主控数据库（用于存放所有项目元数据）
client_admin = MongoClient("mongodb://localhost:27017")
project_admin = client_admin["project_admin"]

client_ref = MongoClient("mongodb://localhost:27017")
attack_reference = client_ref["attack_reference"]

# 用于根据项目名动态获取该项目的数据库
def get_project_db(project_name):
    client = MongoClient("mongodb://localhost:27017")
    return client[project_name]
