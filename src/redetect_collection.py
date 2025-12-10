"""
Re-run enhanced detector on existing MongoDB collection
Supports fresh API fetches with fallback to cached data, quota management, and resume capability
"""

import os
import sys
import json
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

# Import detector classes
from youtube_streamjacking_detector_enhanced import (
    EnhancedYouTubeAPIClient,
    EnhancedStreamJackingDetector,
    EnhancedChannelMetadata,
    EnhancedVideoMetadata
)

load_dotenv()

class RedetectionManager:
    """Manages re-detection of videos in MongoDB collection"""
    
    def __init__(self, 
                 api_key: str,
                 collection_name: str = 'detection_results_v3_labeling',
                 max_quota_usage: int = 5000,
                 checkpoint_file: str = 'redetection_checkpoint.json'):
        self.api_client = EnhancedYouTubeAPIClient(api_key)
        self.detector = EnhancedStreamJackingDetector(self.api_client)
        self.max_quota_usage = max_quota_usage
        self.checkpoint_file = checkpoint_file
        
        # Connect to MongoDB
        conn_str = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
        self.client = MongoClient(conn_str, serverSelectionTimeoutMS=5000)
        self.db = self.client['streamjacking']
        self.collection = self.db[collection_name]
        
        # Load checkpoint
        self.checkpoint = self._load_checkpoint()
        
        # Track skipped videos
        self.skipped_videos = []
        
    def _load_checkpoint(self) -> Dict:
        """Load checkpoint from file"""
        if os.path.exists(self.checkpoint_file):
            with open(self.checkpoint_file, 'r') as f:
                return json.load(f)
        return {
            'processed_video_ids': [],
            'skipped_video_ids': [],
            'last_processed_index': 0,
            'total_processed': 0,
            'total_skipped': 0,
            'quota_used': 0,
            'started_at': None,
            'last_updated': None
        }
    
    def _save_checkpoint(self):
        """Save checkpoint to file"""
        self.checkpoint['last_updated'] = datetime.now().isoformat()
        with open(self.checkpoint_file, 'w') as f:
            json.dump(self.checkpoint, f, indent=2)
    
    def _create_video_metadata_from_cache(self, doc: Dict) -> Optional[EnhancedVideoMetadata]:
        """Create video metadata object from cached MongoDB data"""
        try:
            return EnhancedVideoMetadata(
                video_id=doc.get('video_id', ''),
                title=doc.get('video_title', ''),
                description=doc.get('video_description', ''),
                channel_id=doc.get('channel_id', ''),
                channel_title=doc.get('channel_title', ''),
                published_at=doc.get('published_at', ''),
                is_live=doc.get('is_live', False),
                live_streaming_details=doc.get('live_streaming_details'),
                view_count=doc.get('view_count', 0),
                like_count=doc.get('like_count', 0),
                comment_count=doc.get('comment_count', 0),
                tags=doc.get('tags', []),
                comments_disabled=doc.get('comments_disabled', False),
                live_chat_id=doc.get('live_chat_id'),
                default_language=doc.get('default_language')
            )
        except Exception as e:
            print(f"   ⚠️  Error creating video metadata from cache: {e}")
            return None
    
    def _create_channel_metadata_from_cache(self, doc: Dict) -> Optional[EnhancedChannelMetadata]:
        """Create channel metadata object from cached MongoDB data"""
        try:
            return EnhancedChannelMetadata(
                channel_id=doc.get('channel_id', ''),
                channel_title=doc.get('channel_title', ''),
                custom_url=doc.get('channel_custom_url'),
                handle=doc.get('channel_handle'),
                description=doc.get('channel_description', ''),
                subscriber_count=doc.get('subscriber_count', 0),
                video_count=doc.get('video_count', 0),
                view_count=doc.get('channel_view_count', 0),
                published_at=doc.get('channel_published_at', ''),
                country=doc.get('country'),
                thumbnail_url=doc.get('channel_thumbnail_url', ''),
                topic_categories=doc.get('topic_categories', []),
                branding_settings=doc.get('branding_settings', {}),
                hidden_subscriber_count=doc.get('hidden_subscriber_count', False),
                default_language=doc.get('channel_default_language')
            )
        except Exception as e:
            print(f"   ⚠️  Error creating channel metadata from cache: {e}")
            return None
    
    def _fetch_fresh_metadata(self, video_id: str, channel_id: str) -> Tuple[Optional[EnhancedVideoMetadata], Optional[EnhancedChannelMetadata]]:
        """Attempt to fetch fresh metadata from YouTube API"""
        video_meta = None
        channel_meta = None
        
        # Check quota before making calls
        if self.api_client.quota_used >= self.max_quota_usage:
            return None, None
        
        try:
            # Fetch video metadata (1 unit)
            video_meta = self.api_client.get_video_metadata(video_id)
            if video_meta:
                print(f"      ✓ Fresh video metadata fetched (quota: {self.api_client.quota_used})")
            
            # Fetch channel metadata (1 unit)
            if self.api_client.quota_used < self.max_quota_usage:
                channel_meta = self.api_client.get_channel_metadata(channel_id)
                if channel_meta:
                    print(f"      ✓ Fresh channel metadata fetched (quota: {self.api_client.quota_used})")
            
            time.sleep(0.5)  # Rate limiting
            
        except Exception as e:
            print(f"      ⚠️  API error: {e}")
        
        return video_meta, channel_meta
    
    def _validate_metadata_quality(self, video_meta: EnhancedVideoMetadata, channel_meta: Optional[EnhancedChannelMetadata]) -> bool:
        """Validate that metadata has critical fields for accurate detection"""
        # Critical fields that must be present for accurate detection
        if not video_meta.description:
            print(f"      ⚠️  Missing video description (critical for scam detection)")
            return False
        
        if channel_meta and not channel_meta.description:
            print(f"      ⚠️  Missing channel description")
            # Not critical, but log it
        
        return True
    
    def redetect_video(self, doc: Dict, fresh_api_only: bool = True) -> Dict:
        """Re-run detection on a single video using only fresh API data"""
        video_id = doc.get('video_id')
        channel_id = doc.get('channel_id')
        
        # Check quota availability
        if self.api_client.quota_used >= self.max_quota_usage:
            raise Exception(f"Quota exhausted ({self.api_client.quota_used}/{self.max_quota_usage})")
        
        # Fetch fresh metadata (required)
        video_meta, channel_meta = self._fetch_fresh_metadata(video_id, channel_id)
        
        if not video_meta:
            raise Exception("Fresh API data unavailable - skipping video")
        
        # Validate metadata quality
        if not self._validate_metadata_quality(video_meta, channel_meta):
            raise Exception("Insufficient metadata quality - description missing")
        
        # Run enhanced detection
        video_analyzed = self.detector.analyze_video_enhanced(video_meta)
        
        channel_analyzed = None
        if channel_meta:
            channel_analyzed = self.detector.analyze_channel_enhanced(channel_meta)
        
        # Apply composite rules
        composite_result = self.detector.apply_composite_rules(video_analyzed, channel_analyzed)
        
        # Prepare update document
        update_doc = {
            'video_risk_score': video_analyzed.risk_score,
            'video_signals': video_analyzed.suspicious_signals,
            'risk_category': composite_result['risk_category'],
            'confidence_score': composite_result['confidence_score'],
            'total_risk_score': composite_result['total_risk_score'],
            'redetected_at': datetime.now().isoformat(),
            'redetection_quota_used': self.api_client.quota_used - self.checkpoint['quota_used']
        }
        
        if channel_analyzed:
            update_doc['channel_risk_score'] = channel_analyzed.risk_score
            update_doc['channel_signals'] = channel_analyzed.suspicious_signals
        
        return update_doc
    
    def run_redetection(self, 
                       batch_size: int = 50,
                       dry_run: bool = False):
        """Run re-detection using ONLY fresh API data (no cache fallback)"""
        
        print("=" * 70)
        print("STREAMJACKING DETECTOR - FRESH API RE-DETECTION")
        print("=" * 70)
        print()
        print("🔒 MODE: Fresh API Only (no cached data fallback)")
        print("   This ensures complete metadata including descriptions")
        print()
        
        # Get total count
        total_videos = self.collection.count_documents({})
        print(f"📊 Total videos in collection: {total_videos}")
        print(f"📊 Already processed: {len(self.checkpoint['processed_video_ids'])}")
        print(f"📊 Previously skipped: {len(self.checkpoint.get('skipped_video_ids', []))}")
        print(f"📊 Remaining: {total_videos - len(self.checkpoint['processed_video_ids']) - len(self.checkpoint.get('skipped_video_ids', []))}")
        print(f"⚡ Quota budget: {self.max_quota_usage} units")
        print(f"⚡ Quota already used: {self.checkpoint['quota_used']} units")
        print(f"⚡ Estimated videos processable: ~{(self.max_quota_usage - self.checkpoint['quota_used']) // 2}")
        print()
        
        if dry_run:
            print("🔍 DRY RUN MODE - No changes will be saved")
            print()
        
        # Initialize checkpoint if first run
        if not self.checkpoint['started_at']:
            self.checkpoint['started_at'] = datetime.now().isoformat()
        
        # Query videos not yet processed or skipped
        processed_ids = set(self.checkpoint['processed_video_ids'])
        skipped_ids = set(self.checkpoint.get('skipped_video_ids', []))
        excluded_ids = list(processed_ids | skipped_ids)
        query = {'video_id': {'$nin': excluded_ids}} if excluded_ids else {}
        
        cursor = self.collection.find(query).batch_size(batch_size)
        
        batch_count = 0
        success_count = 0
        skipped_count = 0
        error_count = 0
        quota_exhausted = False
        
        for doc in cursor:
            video_id = doc.get('video_id')
            channel_title = doc.get('channel_title', 'Unknown')
            video_title = doc.get('video_title', 'Unknown')
            
            batch_count += 1
            
            print(f"\n[{batch_count}] Processing: {video_id}")
            print(f"    Channel: {channel_title}")
            print(f"    Video: {video_title[:80]}...")
            print(f"    Current risk: {doc.get('risk_category', 'UNKNOWN')}")
            
            # Check quota
            if self.api_client.quota_used >= self.max_quota_usage:
                print(f"    ⚠️  QUOTA LIMIT REACHED ({self.api_client.quota_used}/{self.max_quota_usage})")
                quota_exhausted = True
                break
            
            try:
                # Re-detect using fresh API only
                update_doc = self.redetect_video(doc, fresh_api_only=True)
                
                print(f"    ✅ New risk: {update_doc['risk_category']} "
                      f"(score: {update_doc['total_risk_score']:.1f}, "
                      f"confidence: {update_doc['confidence_score']:.0%})")
                print(f"    📊 Video signals: {len(update_doc['video_signals'])}")
                if 'channel_signals' in update_doc:
                    print(f"    📊 Channel signals: {len(update_doc['channel_signals'])}")
                
                # Update MongoDB
                if not dry_run:
                    self.collection.update_one(
                        {'video_id': video_id},
                        {'$set': update_doc}
                    )
                
                # Update checkpoint
                self.checkpoint['processed_video_ids'].append(video_id)
                self.checkpoint['total_processed'] += 1
                self.checkpoint['quota_used'] = self.api_client.quota_used
                success_count += 1
                
                # Save checkpoint every 10 videos
                if batch_count % 10 == 0:
                    self._save_checkpoint()
                    print(f"\n    💾 Checkpoint saved ({self.checkpoint['total_processed']} processed, {self.checkpoint.get('total_skipped', 0)} skipped)")
                
            except Exception as e:
                error_msg = str(e)
                
                # Check if video should be skipped (API unavailable or missing description)
                if "Fresh API data unavailable" in error_msg or "Insufficient metadata quality" in error_msg or "Quota exhausted" in error_msg:
                    print(f"    ⏭️  SKIPPED: {error_msg}")
                    
                    # Track skipped video
                    if 'skipped_video_ids' not in self.checkpoint:
                        self.checkpoint['skipped_video_ids'] = []
                    self.checkpoint['skipped_video_ids'].append(video_id)
                    self.checkpoint['total_skipped'] = self.checkpoint.get('total_skipped', 0) + 1
                    skipped_count += 1
                    
                    # If quota exhausted, stop processing
                    if "Quota exhausted" in error_msg:
                        quota_exhausted = True
                        break
                else:
                    print(f"    ❌ Error: {e}")
                    error_count += 1
                
                continue
        
        # Final checkpoint save
        self._save_checkpoint()
        
        # Summary
        print()
        print("=" * 70)
        print("RE-DETECTION COMPLETE")
        print("=" * 70)
        print(f"✅ Successfully processed: {success_count}")
        print(f"⏭️  Skipped (API/quality issues): {skipped_count}")
        print(f"❌ Errors: {error_count}")
        print(f"📊 Total processed (cumulative): {self.checkpoint['total_processed']}/{total_videos}")
        print(f"📊 Total skipped (cumulative): {self.checkpoint.get('total_skipped', 0)}/{total_videos}")
        print(f"⚡ Quota used (this session): {self.api_client.quota_used} units")
        print(f"⚡ Quota used (total): {self.checkpoint['quota_used']} units")
        
        if quota_exhausted:
            print()
            print("⚠️  QUOTA LIMIT REACHED - Resume later to continue")
            print(f"   Skipped videos will be retried in next session")
            print(f"   Run script again tomorrow to process remaining videos")
        
        if skipped_count > 0:
            print()
            print("💡 TIP: Skipped videos can be retried by:")
            print("   1. Running script again with fresh quota (next day)")
            print("   2. Or use --reset-checkpoint to re-process all skipped videos")
        
        print("=" * 70)
    
    def reset_checkpoint(self, keep_processed: bool = False):
        """Reset checkpoint to start fresh or retry skipped videos"""
        if keep_processed:
            # Only clear skipped videos, keep processed ones
            self.checkpoint['skipped_video_ids'] = []
            self.checkpoint['total_skipped'] = 0
            print("✅ Checkpoint reset: Cleared skipped videos, keeping processed ones")
        else:
            # Full reset
            self.checkpoint = {
                'processed_video_ids': [],
                'skipped_video_ids': [],
                'last_processed_index': 0,
                'total_processed': 0,
                'total_skipped': 0,
                'quota_used': 0,
                'started_at': None,
                'last_updated': None
            }
            print("✅ Checkpoint reset: All videos will be reprocessed")
        
        self._save_checkpoint()
    
    def close(self):
        """Close MongoDB connection"""
        self.client.close()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Re-run enhanced detector on MongoDB collection')
    parser.add_argument('--collection', default='detection_results_v3_labeling',
                       help='MongoDB collection name (default: detection_results_v3_labeling)')
    parser.add_argument('--max-quota', type=int, default=5000,
                       help='Maximum API quota to use (default: 5000)')
    parser.add_argument('--batch-size', type=int, default=50,
                       help='Batch size for processing (default: 50)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Run without saving changes to database')
    parser.add_argument('--reset-checkpoint', action='store_true',
                       help='Reset checkpoint and start from beginning')
    parser.add_argument('--retry-skipped', action='store_true',
                       help='Clear skipped videos and retry them (keeps processed videos)')
    
    args = parser.parse_args()
    
    # Get API key
    api_key = os.environ.get('YOUTUBE_API_KEY')
    if not api_key:
        print("❌ Error: YOUTUBE_API_KEY not found in environment")
        print("   Set it with: export YOUTUBE_API_KEY='your-key'")
        sys.exit(1)
    
    # Initialize manager
    manager = RedetectionManager(
        api_key=api_key,
        collection_name=args.collection,
        max_quota_usage=args.max_quota
    )
    
    # Reset checkpoint if requested
    if args.reset_checkpoint:
        manager.reset_checkpoint(keep_processed=False)
        print()
    elif args.retry_skipped:
        manager.reset_checkpoint(keep_processed=True)
        print()
    
    try:
        # Run re-detection
        manager.run_redetection(
            batch_size=args.batch_size,
            dry_run=args.dry_run
        )
    finally:
        manager.close()


if __name__ == '__main__':
    main()
