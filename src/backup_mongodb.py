"""
Backup MongoDB collection to JSON file using Python
"""

import json
import os
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

# Connect to MongoDB
conn_str = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
client = MongoClient(conn_str)

# Database and collection
db = client['streamjacking']
collection = db['detection_results_v2']

# Count documents
count = collection.count_documents({})
print(f"Found {count} documents in collection")

# Fetch all documents
print("Exporting...")
documents = list(collection.find())

# Convert ObjectId to string for JSON serialization
for doc in documents:
    doc['_id'] = str(doc['_id'])

# Create backup directory
os.makedirs('backups', exist_ok=True)

# Save to file
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
backup_file = f'backups/detection_results_v2_backup_{timestamp}.json'

with open(backup_file, 'w') as f:
    json.dump(documents, f, indent=2)

print(f"\n✅ Backup complete!")
print(f"📁 Saved to: {backup_file}")
print(f"📊 Records backed up: {len(documents)}")

# Show file size
size_mb = os.path.getsize(backup_file) / (1024 * 1024)
print(f"💾 File size: {size_mb:.2f} MB")
