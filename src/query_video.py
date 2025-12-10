"""
Query MongoDB for specific video detection details
"""
import sys
from pymongo import MongoClient
import json
from dotenv import load_dotenv
import os

load_dotenv()

def get_video_details(video_id):
    try:
        conn_str = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
        client = MongoClient(conn_str, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        
        db = client['streamjacking']
        collection = db['detection_results_v3']
        
        doc = collection.find_one({'video_id': video_id})
        
        client.close()
        
        if doc:
            # Remove MongoDB _id for cleaner output
            if '_id' in doc:
                doc['_id'] = str(doc['_id'])
            return doc
        else:
            return None
            
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == '__main__':
    video_id = sys.argv[1] if len(sys.argv) > 1 else 'njVWY_yf0ws'
    
    result = get_video_details(video_id)
    
    if result:
        print(json.dumps(result, indent=2))
    else:
        print(f"Video {video_id} not found in database")
