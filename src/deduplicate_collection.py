"""
Quick script to deduplicate MongoDB collection by video_id
Keeps the most recent entry for each video_id
"""

import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

def deduplicate_collection(collection_name: str = 'detection_results_v3_labeling', dry_run: bool = False):
    """Remove duplicate video_id entries, keeping the most recent"""
    
    print("=" * 70)
    print(f"DEDUPLICATING COLLECTION: {collection_name}")
    print("=" * 70)
    print()
    
    # Connect to MongoDB
    conn_str = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
    client = MongoClient(conn_str, serverSelectionTimeoutMS=5000)
    db = client['streamjacking']
    collection = db[collection_name]
    
    # Get initial count
    initial_count = collection.count_documents({})
    print(f"📊 Initial document count: {initial_count}")
    
    # Find duplicates using aggregation
    print("\n🔍 Finding duplicates...")
    pipeline = [
        {
            '$group': {
                '_id': '$video_id',
                'count': {'$sum': 1},
                'docs': {'$push': '$$ROOT'}
            }
        },
        {
            '$match': {
                'count': {'$gt': 1}
            }
        }
    ]
    
    duplicates = list(collection.aggregate(pipeline))
    
    if not duplicates:
        print("✅ No duplicates found!")
        client.close()
        return
    
    print(f"⚠️  Found {len(duplicates)} video_ids with duplicates")
    
    # Track deletions
    total_to_delete = 0
    deleted_count = 0
    
    for dup in duplicates:
        video_id = dup['_id']
        docs = dup['docs']
        count = len(docs)
        
        # Sort by _id (ObjectId contains timestamp) to keep most recent
        docs_sorted = sorted(docs, key=lambda x: x['_id'], reverse=True)
        
        # Keep the first (most recent), delete the rest
        to_keep = docs_sorted[0]
        to_delete = docs_sorted[1:]
        
        print(f"\n  Video: {video_id}")
        print(f"    Duplicates: {count}")
        print(f"    Keeping:    {to_keep['_id']} (most recent)")
        print(f"    Deleting:   {len(to_delete)} older entries")
        
        total_to_delete += len(to_delete)
        
        if not dry_run:
            # Delete older entries
            for doc in to_delete:
                result = collection.delete_one({'_id': doc['_id']})
                if result.deleted_count > 0:
                    deleted_count += 1
    
    # Final count
    final_count = collection.count_documents({})
    
    print()
    print("=" * 70)
    print("DEDUPLICATION COMPLETE")
    print("=" * 70)
    print(f"📊 Initial count:     {initial_count}")
    print(f"📊 Final count:       {final_count}")
    print(f"🗑️  Duplicates found:  {len(duplicates)} video_ids")
    print(f"🗑️  Documents deleted: {deleted_count}")
    
    if dry_run:
        print()
        print("🔍 DRY RUN MODE - No changes were made")
        print(f"   Would have deleted {total_to_delete} documents")
    
    print("=" * 70)
    
    client.close()


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Deduplicate MongoDB collection by video_id')
    parser.add_argument('--collection', default='detection_results_v3_labeling',
                       help='Collection name (default: detection_results_v3_labeling)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be deleted without actually deleting')
    
    args = parser.parse_args()
    
    deduplicate_collection(args.collection, args.dry_run)
