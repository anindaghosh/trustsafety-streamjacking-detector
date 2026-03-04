from datetime import datetime
from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

client = MongoClient(os.getenv("MONGODB_URI"))
db = client["streamjacking"]
coll = db["detection_results_latest"]
backup_name = f"detection_results_latest_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
backup = db[backup_name]
backup.insert_many(coll.find())
print("Backup created with", backup.count_documents({}), "documents.")
