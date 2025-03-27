import os
import pandas as pd
from pymongo import MongoClient

def load_csv_records(filepath):
    print(f"📄 Checking file: {filepath}")
    if os.path.exists(filepath):
        df = pd.read_csv(filepath)
        print(f"✅ Loaded {len(df)} records from {os.path.basename(filepath)}")
        return df.to_dict(orient="records")
    else:
        print(f"❌ File not found: {filepath}")
        return []

def sync_collection(db, coll_name, records):
    coll = db[coll_name]
    if not records:
        print(f"⚠️ No records for {coll_name}, skipping insert.")
        return

    existing = list(coll.find({}))
    if len(existing) != len(records):
        coll.delete_many({})
        coll.insert_many(records)
        print(f"✅ {coll_name} updated with {len(records)} records.")
    else:
        print(f"✅ {coll_name} already up-to-date ({len(records)} records).")

def init_attack_reference():
    print("🚀 Connecting to MongoDB...")
    client = MongoClient("mongodb://localhost:27017")
    db = client["attack_reference"]

    base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))
    print(f"📂 Looking for data files in: {base_path}")

    sync_collection(db, "techniques", load_csv_records(os.path.join(base_path, "techniques.csv")))
    sync_collection(db, "tactics", load_csv_records(os.path.join(base_path, "tactics.csv")))
    sync_collection(db, "techniques_to_tactics", load_csv_records(os.path.join(base_path, "technique_to_tactics.csv")))
    sync_collection(db, "tactic_chain", load_csv_records(os.path.join(base_path, "tactic_chain.csv")))

    # Test insert if all were empty
    if not db.list_collection_names():
        print("🔁 Forcing dummy insert to create database...")
        db["_temp"].insert_one({"hello": "world"})
        db["_temp"].drop()
        print("✅ Database created.")

    print("✅ attack_reference initialization complete!")

if __name__ == "__main__":
    init_attack_reference()
