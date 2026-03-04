"""
backfill_descriptions.py — One-time script to fetch and store
video/channel descriptions for existing MongoDB documents.

This is needed because earlier detector runs did not store
video_description or channel_description fields. Without them,
the CryptoBERT training export falls back to channel_title only,
causing the training/inference format mismatch (Signal 12 bug).

Run:
    cd streamjacking-detector
    source venv/bin/activate
    python src/backfill_descriptions.py --max-quota 2000

After this completes, re-export and retrain:
    python src/export_training_data.py
    python src/finetune_cryptobert.py --epochs 4 --batch-size 16
"""

import os, sys, time, argparse
sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()

from pymongo import MongoClient
from youtube_streamjacking_detector_enhanced import EnhancedYouTubeAPIClient

SEP = "=" * 65


def backfill(api_key: str, collection_name: str, max_quota: int, validated_only: bool):
    client = MongoClient(os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/'))
    db = client['streamjacking']
    coll = db[collection_name]

    # Target: docs that are missing video_description
    query_filter = {"video_description": {"$exists": False}}
    if validated_only:
        query_filter["validation.label"] = {"$exists": True}

    total = coll.count_documents(query_filter)
    print(f"\n{SEP}")
    print(f"  DESCRIPTION BACKFILL")
    print(SEP)
    print(f"  Collection  : {collection_name}")
    print(f"  Target docs : {total} (missing video_description)")
    print(f"  Validated only: {validated_only}")
    print(f"  Max quota   : {max_quota} units")
    print(f"{SEP}\n")

    if total == 0:
        print("✅ All documents already have video_description. Nothing to do.")
        client.close()
        return

    api = EnhancedYouTubeAPIClient(api_key)
    updated = 0
    failed = 0

    cursor = coll.find(query_filter, {
        "video_id": 1, "channel_id": 1, "video_title": 1, "channel_title": 1
    })

    for idx, doc in enumerate(cursor, 1):
        if api.quota_used >= max_quota:
            print(f"\n⚠️  Quota limit reached ({api.quota_used}/{max_quota}). Stopping.")
            break

        video_id = doc.get("video_id")
        channel_id = doc.get("channel_id")
        print(f"[{idx}/{total}] {video_id} | quota={api.quota_used}", end=" ")

        update_fields = {}

        # Fetch video metadata (costs 1 quota unit via videos.list)
        try:
            video_meta = api.get_video_metadata(video_id)
            if video_meta:
                update_fields["video_description"] = (video_meta.description or "")[:500]
                update_fields["tags"] = video_meta.tags[:20] if video_meta.tags else []
        except Exception as e:
            print(f"\n  ⚠️  Video fetch failed: {e}")
            update_fields["video_description"] = ""
            update_fields["tags"] = []

        # Fetch channel metadata (costs 1 quota unit via channels.list)
        if channel_id:
            try:
                ch_meta = api.get_channel_metadata(channel_id)
                if ch_meta and hasattr(ch_meta, 'description'):
                    update_fields["channel_description"] = (ch_meta.description or "")[:500]
            except Exception as e:
                print(f"\n  ⚠️  Channel fetch failed: {e}")
                update_fields["channel_description"] = ""

        if update_fields:
            coll.update_one({"_id": doc["_id"]}, {"$set": update_fields})
            updated += 1
            has_desc = bool(update_fields.get("video_description") or update_fields.get("channel_description"))
            print(f"→ {'✅ desc found' if has_desc else '⚪ empty desc'}")
        else:
            failed += 1
            print("→ ❌ no update")

        time.sleep(0.2)  # be gentle on the API

    client.close()
    print(f"\n{SEP}")
    print(f"  BACKFILL COMPLETE")
    print(f"  Updated : {updated}")
    print(f"  Failed  : {failed}")
    print(f"  Quota used: {api.quota_used} units")
    print(f"\nNext steps:")
    print(f"  python src/export_training_data.py")
    print(f"  python src/finetune_cryptobert.py --epochs 4 --batch-size 16")
    print(SEP)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Backfill video/channel descriptions in MongoDB")
    parser.add_argument("--collection", default="detection_results_latest")
    parser.add_argument("--max-quota", type=int, default=2000,
                        help="Max YouTube API quota to spend (default: 2000)")
    parser.add_argument("--validated-only", action="store_true",
                        help="Only backfill documents that have validation labels (faster, for training)")
    args = parser.parse_args()

    api_key = os.environ.get("YOUTUBE_API_KEY")
    if not api_key:
        print("❌ Set YOUTUBE_API_KEY in your .env file first.")
        sys.exit(1)

    backfill(api_key, args.collection, args.max_quota, args.validated_only)
