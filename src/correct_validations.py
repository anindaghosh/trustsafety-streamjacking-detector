import os
import sys
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

def update_validation_labels_in_mongodb():
    """
    Update validation labels from 'true_positive' to 'false_negative' in MongoDB.
    
    Queries the collection and updates all records where validation.label == 'true_positive'
    to validation.label == 'false_negative'.
    """
    
    # Connect to MongoDB
    conn_str = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
    
    try:
        client = MongoClient(conn_str, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        print("✅ Connected to MongoDB")
        
        db = client['streamjacking']
        collection = db['detection_results_v2']
        
        # Find all documents where validation.label == 'true_positive'
        query = {'validation.label': 'true_positive'}
        
        # Count documents that match
        count = collection.count_documents(query)
        
        if count == 0:
            print("ℹ️  No documents found with validation.label == 'true_positive'")
            client.close()
            return
        
        print(f"📊 Found {count} documents with validation.label == 'true_positive'")
        
        # Ask for confirmation
        response = input(f"\n⚠️  Are you sure you want to update {count} documents? (yes/no): ")
        
        if response.lower() not in ['yes', 'y']:
            print("❌ Update cancelled")
            client.close()
            return
        
        # Update documents
        update_operation = {
            '$set': {
                'validation.label': 'false_negative',
                'validation.corrected_at': datetime.utcnow().isoformat()
            }
        }
        
        result = collection.update_many(query, update_operation)
        
        print(f"\n✅ Successfully updated {result.modified_count} documents")
        print(f"   validation.label: 'true_positive' → 'false_negative'")
        
        # Show sample of updated documents
        print("\n📋 Sample updated documents:")
        updated_docs = collection.find({'validation.label': 'false_negative'}).limit(5)
        
        for i, doc in enumerate(updated_docs, 1):
            video_id = doc.get('video_id', 'N/A')
            channel = doc.get('channel_title', 'Unknown')
            risk_score = doc.get('total_risk_score', doc.get('video_risk_score', 0))
            print(f"   {i}. {channel} (video: {video_id}, risk: {risk_score:.1f})")
        
        client.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\nTroubleshooting:")
        print("  1. Check MongoDB is running: mongosh")
        print("  2. Verify MONGODB_URI in .env file")
        print("  3. Confirm database/collection exists")
        sys.exit(1)


if __name__ == "__main__":
    print("="*80)
    print("UPDATE VALIDATION LABELS IN MONGODB")
    print("="*80)
    print("\nThis script will update records where:")
    print("  validation.label == 'true_positive'")
    print("  → validation.label = 'false_negative'")
    print("\nDatabase: streamjacking")
    print("Collection: detection_results_v2")
    print("="*80 + "\n")
    
    update_validation_labels_in_mongodb()