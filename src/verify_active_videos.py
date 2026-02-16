import os
from pymongo import MongoClient
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from dotenv import load_dotenv
from datetime import datetime, timezone
import time

# Load environment variables
load_dotenv()

# MongoDB connection
MONGO_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URI)
db = client['streamjacking']
collection = db['detection_results_latest']

# YouTube API setup
YOUTUBE_API_KEY = os.getenv('YOUTUBE_API_KEY')
youtube = build('youtube', 'v3', developerKey=YOUTUBE_API_KEY)

def check_video_status(video_id, channel_id=None):
    """Check if a YouTube video is still active and determine why if not"""
    try:
        response = youtube.videos().list(
            part='status,snippet',
            id=video_id
        ).execute()
        
        if not response['items']:
            # Video not found - check if it's because the channel is terminated
            if channel_id:
                reason = check_channel_status(channel_id)
                if reason:
                    return False, reason
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

def check_channel_status(channel_id):
    """Check if a channel is terminated or unavailable"""
    try:
        response = youtube.channels().list(
            part='status,snippet',
            id=channel_id
        ).execute()
        
        if not response['items']:
            # Channel not found - likely terminated
            return 'Channel terminated'
        
        channel = response['items'][0]
        
        # Check if channel is active
        if channel.get('status', {}).get('isLinked') == False:
            return 'Channel unlinked'
        
        # If we can fetch the channel, it exists
        return None
        
    except HttpError as e:
        if e.resp.status == 403:
            return 'Channel terminated (403)'
        elif e.resp.status == 404:
            return 'Channel terminated (404)'
        else:
            return None
    except Exception as e:
        return None

def verify_videos():
    """Verify all videos in the collection"""
    total_videos = collection.count_documents({})
    print(f"Total videos to verify: {total_videos}")
    
    active_count = 0
    inactive_count = 0
    error_count = 0
    reason_counts = {}  # Track different reasons for inactive videos
    
    # Process videos in batches
    for i, doc in enumerate(collection.find({}), 1):
        video_id = doc.get('video_id')
        channel_id = doc.get('channel_id')
        
        if not video_id:
            print(f"[{i}/{total_videos}] Skipping document with no video_id")
            continue
        
        is_active, reason = check_video_status(video_id, channel_id)
        
        # Update document with verification status
        update_data = {
            'verification_date': datetime.now(timezone.utc),
            'verification_status': reason
        }
        
        if is_active is True:
            update_data['is_active'] = True
            active_count += 1
            status_symbol = '✓'
        elif is_active is False:
            update_data['is_active'] = False
            inactive_count += 1
            # Track reason counts
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            # Use different symbol for channel termination
            if 'Channel terminated' in reason:
                status_symbol = '🚫'
            else:
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
    
    if reason_counts:
        print("\n=== Inactive Video Breakdown ===")
        for reason, count in sorted(reason_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {reason}: {count}")
            
    # Calculate percentages
    if total_videos > 0:
        active_pct = (active_count / total_videos) * 100
        inactive_pct = (inactive_count / total_videos) * 100
        print(f"\n📊 Active: {active_pct:.1f}% | Inactive: {inactive_pct:.1f}%")

if __name__ == '__main__':
    if not YOUTUBE_API_KEY:
        print("Error: YOUTUBE_API_KEY not found in environment variables")
        exit(1)
    
    verify_videos()