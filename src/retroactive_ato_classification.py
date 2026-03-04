"""
Retroactive Account Takeover Classification
Backfills the 'takeover_type' field for existing streamjacking detections.
"""

import os
import time
from typing import Dict
from pymongo import MongoClient
from dotenv import load_dotenv
from youtube_streamjacking_detector_enhanced import (
    EnhancedYouTubeAPIClient,
    EnhancedStreamJackingDetector,
    EnhancedChannelMetadata,
    EnhancedVideoMetadata
)

load_dotenv()

def retroactively_classify_takeovers(
    api_key: str, 
    collection_name: str = 'detection_results_latest',
    max_quota: int = 10000
):
    print("=" * 70)
    print("RETROACTIVE ACCOUNT TAKEOVER CLASSIFICATION")
    print("=" * 70)
    
    # Initialize components
    api_client = EnhancedYouTubeAPIClient(api_key)
    detector = EnhancedStreamJackingDetector(api_client)
    
    # Connect to MongoDB
    conn_str = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
    client = MongoClient(conn_str)
    db = client['streamjacking']
    collection = db[collection_name]
    
    # Find hijack detections that haven't been classified yet
    query = {
        'risk_category': {'$in': ['CRITICAL', 'HIGH']},
        'takeover_type': {'$exists': False}
    }
    
    # Let's also include those explicitly marked as UNKNOWN from partial runs
    query_unknown = {
        'risk_category': {'$in': ['CRITICAL', 'HIGH']},
        'takeover_type': 'UNKNOWN'
    }
    
    cursor = collection.find({'$or': [query, query_unknown]})
    total_to_process = collection.count_documents({'$or': [query, query_unknown]})
    
    print(f"Found {total_to_process} high-risk detections needing classification.")
    
    success_count = 0
    skipped_count = 0
    
    for idx, doc in enumerate(cursor, 1):
        if api_client.quota_used >= max_quota:
            print(f"\n⚠️  Reached quota limit ({api_client.quota_used}/{max_quota}). Stopping.")
            break
            
        video_id = doc.get('video_id')
        channel_id = doc.get('channel_id')
        print(f"\n[{idx}/{total_to_process}] Processing {channel_id} (Video: {video_id})")
        
        try:
            # 1. Fetch channel metadata (5 quota)
            channel_meta = api_client.get_channel_metadata(channel_id)
            if not channel_meta:
                print("   ⚠️  Could not fetch channel metadata. Skipping.")
                skipped_count += 1
                continue
                
            age_days = detector._compute_channel_age_days(channel_meta.published_at)
            
            # 2. Reconstruct video_analyzed to get the live crypto signals
            video_analyzed = EnhancedVideoMetadata(
                video_id=video_id,
                title=doc.get('video_title', ''),
                description='',
                channel_id=channel_id,
                channel_title=doc.get('channel_title', ''),
                published_at='',
                is_live=True,
                live_streaming_details=None,
                view_count=0,
                like_count=0,
                comment_count=0,
                suspicious_signals=doc.get('video_signals', [])
            )
            
            # 3. Simulate composite risk dict
            composite_risk = {'risk_category': doc.get('risk_category')}
            
            # 4. Fetch past videos if age > 365 (~3 quota units via playlist API)
            past_videos = []
            if age_days > 365:
                print("   Fetching past videos (~3 quota units)...")
                past_videos, _ = api_client.get_channel_history(channel_id)
            
            # 5. Classify
            takeover_type = detector.classify_takeover(
                channel_meta, 
                past_videos, 
                video_analyzed, 
                composite_risk
            )
            
            print(f"   ✅ Classification: {takeover_type}")
            
            # 6. Update MongoDB
            collection.update_one(
                {'_id': doc['_id']},
                {'$set': {'takeover_type': takeover_type}}
            )
            
            success_count += 1
            time.sleep(0.5)
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
            skipped_count += 1
            
    print("\n" + "=" * 70)
    print("BACKFILL COMPLETE")
    print(f"Successfully backfilled: {success_count}")
    print(f"Skipped/Errors: {skipped_count}")
    print(f"Quota used: {api_client.quota_used} units")
    print("=" * 70)
    
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--collection', default='detection_results_latest')
    parser.add_argument('--max-quota', type=int, default=10000)
    args = parser.parse_args()
    
    api_key = os.environ.get('YOUTUBE_API_KEY')
    if not api_key:
        print("Set YOUTUBE_API_KEY environment variable first.")
        exit(1)
        
    retroactively_classify_takeovers(api_key, args.collection, args.max_quota)
