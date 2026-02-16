import os
from pymongo import MongoClient
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from dotenv import load_dotenv
from datetime import datetime
import time

# Load environment variables
load_dotenv()

# MongoDB connection
MONGO_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
print(f"Connecting to MongoDB at: {MONGO_URI}")
client = MongoClient(MONGO_URI)

# Debug: List available databases
print("\nAvailable databases:", client.list_database_names())

db = client['streamjacking']  # Changed from 'streamjacking_detector' to 'streamjacking'
print(f"Using database: streamjacking")
print(f"Available collections: {db.list_collection_names()}")

collection = db['detection_results_latest']
print(f"Using collection: detection_results_latest")

# Debug: Check a sample document to see the structure
sample_doc = collection.find_one()
if sample_doc:
    print(f"\nSample document keys: {list(sample_doc.keys())}")
    print(f"Sample document (first 500 chars): {str(sample_doc)[:500]}")
else:
    print("\n⚠️  No documents found in collection!")

# YouTube API setup
YOUTUBE_API_KEY = os.getenv('YOUTUBE_API_KEY')
youtube = build('youtube', 'v3', developerKey=YOUTUBE_API_KEY)

def check_video_status(video_id):
    """Check if a YouTube video is still active"""
    try:
        response = youtube.videos().list(
            part='status,snippet',
            id=video_id
        ).execute()
        
        if not response['items']:
            return False, 'Video not found'
        
        video = response['items'][0]
        status = video['status']
        
        # Check if video is available
        if status.get('privacyStatus') == 'private':
            return False, 'Private'
        elif status.get('uploadStatus') == 'deleted':
            return False, 'Deleted'
        elif status.get('uploadStatus') == 'rejected':
            return False, 'Rejected'
        else:
            return True, 'Active'
            
    except HttpError as e:
        if e.resp.status == 404:
            return False, 'Not found (404)'
        else:
            return None, f'Error: {e.resp.status}'
    except Exception as e:
        return None, f'Exception: {str(e)}'

def verify_videos():
    """Verify all videos in the collection"""
    total_videos = collection.count_documents({})
    print(f"Total videos to verify: {total_videos}")
    
    active_count = 0
    inactive_count = 0
    error_count = 0
    
    # Process videos in batches
    for i, doc in enumerate(collection.find({}), 1):
        video_id = doc.get('video_id')
        
        if not video_id:
            print(f"[{i}/{total_videos}] Skipping document with no video_id")
            continue
        
        is_active, reason = check_video_status(video_id)
        
        # Update document with verification status
        update_data = {
            'verification_date': datetime.now(datetime.UTC),
            'verification_status': reason
        }
        
        if is_active is True:
            update_data['is_active'] = True
            active_count += 1
            status_symbol = '✓'
        elif is_active is False:
            update_data['is_active'] = False
            inactive_count += 1
            status_symbol = '✗'
        else:
            update_data['is_active'] = None
            error_count += 1
            status_symbol = '!'
        
        collection.update_one(
            {'_id': doc['_id']},
            {'$set': update_data}
        )
        
        print(f"[{i}/{total_videos}] {status_symbol} {video_id}: {reason}")
        
        # Rate limiting - YouTube API has quota limits
        if i % 50 == 0:
            time.sleep(1)
    
    print("\n=== Verification Summary ===")
    print(f"Total videos: {total_videos}")
    print(f"Active: {active_count}")
    print(f"Inactive: {inactive_count}")
    print(f"Errors: {error_count}")

if __name__ == '__main__':
    if not YOUTUBE_API_KEY:
        print("Error: YOUTUBE_API_KEY not found in environment variables")
        exit(1)
    
    verify_videos()