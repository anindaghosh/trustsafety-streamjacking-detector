"""
Interactive Validation Tool - Terminal-based labeling interface
"""

import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Optional
import webbrowser

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False


class InteractiveValidator:
    def __init__(self, data_file: str, progress_file: str = None):
        """
        Initialize validator
        
        Args:
            data_file: Path to detection results JSON
            progress_file: Path to save progress (auto-saves)
        """
        self.data_file = data_file
        self.progress_file = progress_file or data_file.replace('.json', '_validated.json')
        
        # Load detections
        with open(data_file, 'r') as f:
            data = json.load(f)
            if isinstance(data, dict) and 'results' in data:
                self.detections = data['results']
            else:
                self.detections = data
        
        # Load existing progress if available
        self.validated = self._load_progress()
        
        self.current_index = len(self.validated)
        self.stats = {'tp': 0, 'fp': 0, 'uncertain': 0, 'skipped': 0}
        
        # Initialize MongoDB connection (optional)
        self.mongo_collection = None
        if MONGODB_AVAILABLE:
            self._init_mongodb()
        
    def _init_mongodb(self):
        """Initialize MongoDB connection"""
        try:
            conn_str = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
            client = MongoClient(conn_str, serverSelectionTimeoutMS=5000)
            client.admin.command('ping')
            
            db = client['streamjacking']
            self.mongo_collection = db['detection_results_v2']
            print("✅ MongoDB connected - validation labels will be synced to database")
        except Exception as e:
            print(f"⚠️  MongoDB not available: {e}")
            print("   Validation labels will only be saved to JSON file")
            self.mongo_collection = None
    
    def _load_progress(self) -> List[Dict]:
        """Load existing validation progress"""
        if os.path.exists(self.progress_file):
            with open(self.progress_file, 'r') as f:
                return json.load(f)
        return []
    
    def _save_progress(self):
        """Auto-save progress to JSON and MongoDB"""
        with open(self.progress_file, 'w') as f:
            json.dump(self.validated, f, indent=2)
        print(f"   💾 Progress saved to file ({len(self.validated)} validated)")
    
    def _sync_validation_to_mongodb(self, validated_detection: Dict) -> bool:
        """Sync validation label to MongoDB"""
        if self.mongo_collection is None:
            return False
        
        try:
            video_id = validated_detection.get('video_id')
            validation = validated_detection.get('validation', {})
            
            # Update the detection record with validation info
            result = self.mongo_collection.update_one(
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
            
            if result.modified_count > 0:
                print(f"   ✅ Synced to MongoDB")
                return True
            else:
                print(f"   ⚠️  MongoDB: Record not found for video {video_id[:12]}...")
                return False
                
        except Exception as e:
            print(f"   ⚠️  MongoDB sync failed: {e}")
            return False
    
    def _display_detection(self, detection: Dict, index: int):
        """Display detection details"""
        print("\n" + "="*80)
        print(f"🔍 DETECTION #{index + 1} of {len(self.detections)}")
        print("="*80)
        
        print(f"\n📺 VIDEO: {detection.get('video_title', 'N/A')}")
        print(f"   URL: {detection.get('video_url', 'N/A')}")
        
        print(f"\n👤 CHANNEL: {detection.get('channel_title', 'N/A')}")
        print(f"   URL: {detection.get('channel_url', 'N/A')}")
        
        print(f"\n⚠️  RISK SCORE: {detection.get('total_risk_score', 0):.1f} ({detection.get('risk_category', 'UNKNOWN')})")
        print(f"   Confidence: {detection.get('confidence_score', 0):.2f}")
        
        print(f"\n🚩 TRIGGERED SIGNALS:")
        video_signals = detection.get('video_signals', [])
        channel_signals = detection.get('channel_signals', [])
        
        if video_signals:
            print(f"   Video ({len(video_signals)}):")
            for sig in video_signals[:5]:  # Show top 5
                print(f"      • {sig}")
            if len(video_signals) > 5:
                print(f"      ... and {len(video_signals) - 5} more")
        
        if channel_signals:
            print(f"   Channel ({len(channel_signals)}):")
            for sig in channel_signals[:5]:
                print(f"      • {sig}")
            if len(channel_signals) > 5:
                print(f"      ... and {len(channel_signals) - 5} more")
        
        print("\n" + "-"*80)
    
    def _get_label(self) -> Optional[Dict]:
        """Get validation label from user"""
        print("\n🏷️  LABEL THIS DETECTION:")
        print("   [1] True Positive  - Definitely stream-jacking/scam")
        print("   [2] False Positive - Legitimate content")
        print("   [3] Uncertain      - Unclear, needs more review")
        print("   [o] Open URL       - Open video/channel in browser")
        print("   [s] Skip           - Skip for now")
        print("   [b] Back           - Go to previous")
        print("   [q] Quit           - Save and exit")
        
        while True:
            choice = input("\n👉 Your choice: ").strip().lower()
            
            if choice == '1':
                return self._get_detailed_label('true_positive')
            elif choice == '2':
                return self._get_detailed_label('false_positive')
            elif choice == '3':
                return self._get_detailed_label('uncertain')
            elif choice == 'o':
                return None  # Signal to open URL
            elif choice == 's':
                self.stats['skipped'] += 1
                return {'label': 'skipped'}
            elif choice == 'b':
                return {'label': 'back'}
            elif choice == 'q':
                return {'label': 'quit'}
            else:
                print("   ❌ Invalid choice. Please try again.")
    
    def _get_detailed_label(self, label: str) -> Dict:
        """Get detailed labeling info"""
        print(f"\n📝 You labeled as: {label.replace('_', ' ').upper()}")
        
        # Get reasoning
        print("\n💭 Why? (brief explanation):")
        reasoning = input("   > ").strip()
        
        # Get scam type if TP
        scam_type = None
        if label == 'true_positive':
            print("\n🎯 Scam Type:")
            print("   [1] Impersonation")
            print("   [2] Giveaway Scam")
            print("   [3] Phishing/Malware")
            print("   [4] Hijacked Channel")
            print("   [5] Other")
            
            type_choice = input("   👉 Type: ").strip()
            scam_types = {
                '1': 'impersonation',
                '2': 'giveaway_scam',
                '3': 'phishing',
                '4': 'hijacked_channel',
                '5': 'other'
            }
            scam_type = scam_types.get(type_choice, 'other')
        
        # Update stats
        if label == 'true_positive':
            self.stats['tp'] += 1
        elif label == 'false_positive':
            self.stats['fp'] += 1
        elif label == 'uncertain':
            self.stats['uncertain'] += 1
        
        return {
            'label': label,
            'reasoning': reasoning,
            'scam_type': scam_type,
            'reviewed_at': datetime.now().isoformat(),
            'reviewer': os.environ.get('USER', 'unknown')
        }
    
    def _show_progress(self):
        """Show validation progress"""
        total = len(self.detections)
        validated = len(self.validated)
        remaining = total - validated
        
        print("\n" + "="*80)
        print("📊 PROGRESS")
        print("="*80)
        print(f"   Validated: {validated}/{total} ({validated/total*100:.1f}%)")
        print(f"   Remaining: {remaining}")
        print(f"\n   True Positives:  {self.stats['tp']}")
        print(f"   False Positives: {self.stats['fp']}")
        print(f"   Uncertain:       {self.stats['uncertain']}")
        print(f"   Skipped:         {self.stats['skipped']}")
        
        if validated > 0:
            precision_est = self.stats['tp'] / (self.stats['tp'] + self.stats['fp']) if (self.stats['tp'] + self.stats['fp']) > 0 else 0
            print(f"\n   Estimated Precision: {precision_est:.2%}")
        
        print("="*80)
    
    def validate(self):
        """Run interactive validation"""
        print("\n" + "🎯 INTERACTIVE VALIDATION TOOL " + "🎯".center(80))
        print("="*80)
        print("Review detections and label them as TP/FP/Uncertain")
        print("Progress is auto-saved after each label")
        print("="*80)
        
        if self.validated:
            print(f"\n✅ Resuming from {len(self.validated)} previously validated detections")
        
        while self.current_index < len(self.detections):
            detection = self.detections[self.current_index]
            
            self._display_detection(detection, self.current_index)
            
            label_result = self._get_label()
            
            # Handle special commands
            if label_result is None:
                # Open URLs
                video_url = detection.get('video_url')
                channel_url = detection.get('channel_url')
                if video_url:
                    print(f"   🌐 Opening video: {video_url}")
                    webbrowser.open(video_url)
                if channel_url:
                    print(f"   🌐 Opening channel: {channel_url}")
                    webbrowser.open(channel_url)
                continue  # Re-display same detection
            
            if label_result['label'] == 'quit':
                print("\n💾 Saving progress...")
                self._save_progress()
                self._show_progress()
                print("\n👋 Validation paused. Run again to resume.")
                return
            
            if label_result['label'] == 'back':
                if self.current_index > 0:
                    self.current_index -= 1
                    # Remove last validation
                    if self.validated:
                        removed = self.validated.pop()
                        # Update stats
                        if removed['validation']['label'] == 'true_positive':
                            self.stats['tp'] -= 1
                        elif removed['validation']['label'] == 'false_positive':
                            self.stats['fp'] -= 1
                        elif removed['validation']['label'] == 'uncertain':
                            self.stats['uncertain'] -= 1
                    print("   ⏪ Moved back to previous detection")
                else:
                    print("   ⚠️  Already at first detection")
                continue
            
            if label_result['label'] == 'skipped':
                self.current_index += 1
                continue
            
            # Save validation
            validated_detection = detection.copy()
            validated_detection['validation'] = label_result
            self.validated.append(validated_detection)
            
            # Sync to MongoDB immediately
            self._sync_validation_to_mongodb(validated_detection)
            
            # Auto-save every 5 detections
            if len(self.validated) % 5 == 0:
                self._save_progress()
            
            self.current_index += 1
            
            print("   ✅ Labeled successfully!")
        
        # Final save
        self._save_progress()
        self._show_progress()
        
        print("\n" + "="*80)
        print("🎉 VALIDATION COMPLETE!")
        print("="*80)
        print(f"\n✅ All {len(self.detections)} detections validated!")
        print(f"📁 Results saved to: {self.progress_file}")
        
        # Export to CSV
        self._export_to_csv()
    
    def _export_to_csv(self):
        """Export validated results to CSV"""
        csv_file = self.progress_file.replace('.json', '.csv')
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            writer.writerow([
                'video_id',
                'channel_id',
                'video_title',
                'channel_title',
                'risk_score',
                'risk_category',
                'ground_truth_label',
                'scam_type',
                'reasoning',
                'reviewed_at',
                'reviewer',
                'video_url',
                'channel_url'
            ])
            
            for item in self.validated:
                val = item.get('validation', {})
                writer.writerow([
                    item.get('video_id'),
                    item.get('channel_id'),
                    item.get('video_title'),
                    item.get('channel_title'),
                    item.get('total_risk_score'),
                    item.get('risk_category'),
                    val.get('label'),
                    val.get('scam_type', ''),
                    val.get('reasoning', ''),
                    val.get('reviewed_at', ''),
                    val.get('reviewer', ''),
                    item.get('video_url'),
                    item.get('channel_url')
                ])
        
        print(f"\n📊 CSV exported to: {csv_file}")


def main():
    """Run interactive validator"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python interactive_validator.py <detections.json>")
        print("\nExample:")
        print("  python interactive_validator.py data/results/streamjacking_detection_results.json")
        return
    
    data_file = sys.argv[1]
    
    if not os.path.exists(data_file):
        print(f"❌ Error: File not found: {data_file}")
        return
    
    validator = InteractiveValidator(data_file)
    
    try:
        validator.validate()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        validator._save_progress()
        validator._show_progress()
        print("💾 Progress saved. Run again to resume.")


if __name__ == "__main__":
    main()
