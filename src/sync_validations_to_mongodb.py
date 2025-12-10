"""
Sync existing validation labels from JSON to MongoDB
Useful for syncing previously validated detections to the database
"""

import json
import os
import sys
from dotenv import load_dotenv

load_dotenv()

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
except ImportError:
    print("❌ Error: pymongo not installed")
    print("Install with: pip install pymongo")
    sys.exit(1)


def sync_validations_to_mongodb(validated_file: str, database: str = 'streamjacking', collection: str = 'detection_results_v2'):
    """
    Sync validation labels from JSON file to MongoDB
    
    Args:
        validated_file: Path to validated detections JSON
        database: MongoDB database name
        collection: Collection name
    """
    
    # Load validated data
    print(f"Loading validated data from {validated_file}...")
    with open(validated_file, 'r') as f:
        validated_data = json.load(f)
    
    print(f"Found {len(validated_data)} validated detections")
    
    # Connect to MongoDB
    print("\nConnecting to MongoDB...")
    try:
        conn_str = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
        client = MongoClient(conn_str, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        print("✅ Connected to MongoDB")
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        return
    
    db = client[database]
    coll = db[collection]
    
    # Sync each validation
    print(f"\nSyncing validation labels to {database}.{collection}...")
    
    synced = 0
    not_found = 0
    failed = 0
    
    for item in validated_data:
        video_id = item.get('video_id')
        validation = item.get('validation', {})
        
        if not video_id:
            print(f"⚠️  Skipping item with no video_id")
            failed += 1
            continue
        
        try:
            result = coll.update_one(
                {'video_id': video_id},
                {
                    '$set': {
                        'validation': validation,
                        'validated_at': validation.get('reviewed_at'),
                        'ground_truth_label': validation.get('label'),
                        'validation_reasoning': validation.get('reasoning'),
                        'scam_type': validation.get('scam_type')
                    }
                }
            )
            
            if result.matched_count > 0:
                synced += 1
                if synced % 10 == 0:
                    print(f"   Synced {synced}/{len(validated_data)}...")
            else:
                not_found += 1
                print(f"⚠️  Not found in DB: {video_id[:12]}...")
                
        except Exception as e:
            failed += 1
            print(f"❌ Failed to sync {video_id[:12]}: {e}")
    
    # Summary
    print("\n" + "="*70)
    print("SYNC SUMMARY")
    print("="*70)
    print(f"Total validated detections: {len(validated_data)}")
    print(f"✅ Synced successfully:     {synced}")
    print(f"⚠️  Not found in database:  {not_found}")
    print(f"❌ Failed to sync:          {failed}")
    print("="*70)
    
    client.close()
    
    if not_found > 0:
        print(f"\n💡 Tip: {not_found} detections weren't found in MongoDB.")
        print("   This usually means they were validated from an older detection run.")
        print("   Re-run the detector to populate MongoDB with all detections.")


def main():
    if len(sys.argv) < 2:
        print("Usage: python sync_validations_to_mongodb.py <validated_file.json>")
        print("\nExample:")
        print("  python sync_validations_to_mongodb.py data/results/streamjacking_detection_results_validated.json")
        return
    
    validated_file = sys.argv[1]
    
    if not os.path.exists(validated_file):
        print(f"❌ Error: File not found: {validated_file}")
        return
    
    # Optional: custom database/collection
    database = sys.argv[2] if len(sys.argv) > 2 else 'streamjacking'
    collection = sys.argv[3] if len(sys.argv) > 3 else 'detection_results_v3'
    
    sync_validations_to_mongodb(validated_file, database, collection)
    
    print("\n✅ Sync complete!")


if __name__ == "__main__":
    main()
