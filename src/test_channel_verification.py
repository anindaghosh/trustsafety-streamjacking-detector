"""
Quick test to verify channel termination detection for a few videos
"""
import os
from pymongo import MongoClient
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from dotenv import load_dotenv

load_dotenv()

# MongoDB connection
MONGO_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URI)
db = client['streamjacking']
collection = db['detection_results_latest']

# YouTube API setup
YOUTUBE_API_KEY = os.getenv('YOUTUBE_API_KEY')
youtube = build('youtube', 'v3', developerKey=YOUTUBE_API_KEY)

def check_channel_status(channel_id):
    """Check if a channel is terminated or unavailable"""
    try:
        response = youtube.channels().list(
            part='status,snippet',
            id=channel_id
        ).execute()
        
        if not response['items']:
            return 'Channel terminated'
        
        channel = response['items'][0]
        
        if channel.get('status', {}).get('isLinked') == False:
            return 'Channel unlinked'
        
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

# Get 5 videos that were marked as "Video not found"
videos = list(collection.find({'verification_status': 'Video not found'}).limit(5))

print(f"Testing {len(videos)} videos marked as 'Video not found'\n")

for v in videos:
    video_id = v['video_id']
    channel_id = v.get('channel_id', 'N/A')
    
    print(f"Video: {video_id}")
    print(f"Channel ID: {channel_id}")
    
    if channel_id != 'N/A':
        channel_status = check_channel_status(channel_id)
        if channel_status:
            print(f"✅ Detected: {channel_status}")
        else:
            print(f"❌ Channel still exists (video individually removed)")
    else:
        print(f"⚠️  No channel ID in database")
    print()
