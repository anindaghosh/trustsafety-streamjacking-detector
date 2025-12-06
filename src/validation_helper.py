"""
Validation Helper - Prepare sample for manual ground truth labeling
"""

import json
import random
from typing import List, Dict
import csv


def load_results(filepath: str) -> List[Dict]:
    """Load detection results"""
    with open(filepath, 'r') as f:
        data = json.load(f)
        if isinstance(data, dict) and 'results' in data:
            return data['results']
        return data


def stratified_sample(results: List[Dict], 
                     high_risk_n: int = 25,
                     medium_risk_n: int = 20,
                     low_risk_n: int = 5) -> List[Dict]:
    """Create stratified sample across risk levels"""
    
    high_risk = [r for r in results if r['total_risk_score'] >= 70]
    medium_risk = [r for r in results if 40 <= r['total_risk_score'] < 70]
    low_risk = [r for r in results if r['total_risk_score'] < 40]
    
    # Sample from each tier
    sample = []
    
    if len(high_risk) >= high_risk_n:
        sample.extend(random.sample(high_risk, high_risk_n))
    else:
        sample.extend(high_risk)
    
    if len(medium_risk) >= medium_risk_n:
        sample.extend(random.sample(medium_risk, medium_risk_n))
    else:
        sample.extend(medium_risk)
    
    if len(low_risk) >= low_risk_n:
        sample.extend(random.sample(low_risk, low_risk_n))
    else:
        sample.extend(low_risk)
    
    # Shuffle to avoid order bias during manual review
    random.shuffle(sample)
    
    return sample


def create_validation_csv(sample: List[Dict], output_file: str):
    """Create CSV template for manual labeling"""
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Header
        writer.writerow([
            'ID',
            'Video URL',
            'Channel URL',
            'Video Title',
            'Channel Name',
            'Risk Score',
            'Risk Category',
            'Top Signals',
            'Ground Truth Label',
            'Notes'
        ])
        
        # Data rows
        for idx, result in enumerate(sample, 1):
            # Get top 3 signals
            all_signals = result.get('video_signals', []) + result.get('channel_signals', [])
            top_signals = '; '.join(all_signals[:3]) if all_signals else 'None'
            
            writer.writerow([
                idx,
                result.get('video_url', ''),
                result.get('channel_url', ''),
                result.get('video_title', '')[:80],  # Truncate long titles
                result.get('channel_title', ''),
                result.get('total_risk_score', 0),
                result.get('risk_category', 'UNKNOWN'),
                top_signals[:150],  # Truncate long signal lists
                '',  # Empty for manual labeling
                ''   # Empty for notes
            ])
    
    print(f"✅ Created validation CSV: {output_file}")
    print(f"   {len(sample)} samples ready for manual review")


def create_validation_json(sample: List[Dict], output_file: str):
    """Create JSON template for manual labeling"""
    
    validation_data = []
    
    for idx, result in enumerate(sample, 1):
        validation_entry = {
            'id': idx,
            'video_id': result.get('video_id'),
            'channel_id': result.get('channel_id'),
            'video_title': result.get('video_title'),
            'channel_title': result.get('channel_title'),
            'video_url': result.get('video_url'),
            'channel_url': result.get('channel_url'),
            'risk_score': result.get('total_risk_score'),
            'risk_category': result.get('risk_category'),
            'signals': {
                'video': result.get('video_signals', []),
                'channel': result.get('channel_signals', [])
            },
            'ground_truth': {
                'label': None,  # To fill: 'true_positive', 'false_positive', 'uncertain'
                'reasoning': '',
                'actual_scam_type': None,  # e.g., 'impersonation', 'giveaway_scam', 'legitimate'
                'reviewed_by': '',
                'review_date': None
            }
        }
        validation_data.append(validation_entry)
    
    with open(output_file, 'w') as f:
        json.dump(validation_data, f, indent=2)
    
    print(f"✅ Created validation JSON: {output_file}")
    print(f"   {len(validation_data)} samples ready for manual review")


def print_validation_instructions():
    """Print instructions for manual validation"""
    
    print("\n" + "="*80)
    print("MANUAL VALIDATION INSTRUCTIONS")
    print("="*80)
    
    print("\n📋 LABELING GUIDELINES:")
    print("\n1. For each entry, visit the YouTube URL and examine:")
    print("   • Video title and description")
    print("   • Channel name and about section")
    print("   • Video content (if still available)")
    print("   • Comments section (if enabled)")
    print("   • Channel history and other videos")
    
    print("\n2. Assign Ground Truth Label:")
    print("   • 'true_positive' - Definitely stream-jacking/scam")
    print("   • 'false_positive' - Legitimate content")
    print("   • 'uncertain' - Unclear, needs more investigation")
    
    print("\n3. Common Stream-Jacking Indicators:")
    print("   ✓ Impersonating celebrities/brands")
    print("   ✓ Crypto giveaway scams")
    print("   ✓ Fake live events with scam links")
    print("   ✓ Hijacked accounts with suspicious content")
    print("   ✓ Urgent language pushing immediate action")
    
    print("\n4. Common False Positives:")
    print("   ✓ Legitimate news channels (Bloomberg, CNBC)")
    print("   ✓ Educational crypto content")
    print("   ✓ Space enthusiast channels (LabPadre)")
    print("   ✓ Legitimate company channels")
    
    print("\n5. Document Your Reasoning:")
    print("   • Why you classified it this way")
    print("   • What made it obvious or unclear")
    print("   • Any patterns you notice")
    
    print("\n" + "="*80)
    print("\n💡 TIP: Review in batches of 10-15 to maintain consistency")
    print("💡 TIP: Take breaks to avoid decision fatigue")
    print("="*80 + "\n")


def main():
    """Generate validation samples"""
    import sys
    
    # Set random seed for reproducibility
    random.seed(42)
    
    if len(sys.argv) < 2:
        print("Usage: python validation_helper.py <results_file.json>")
        return
    
    results_file = sys.argv[1]
    
    print(f"Loading results from {results_file}...")
    results = load_results(results_file)
    
    print(f"Total results: {len(results)}")
    
    # Count by risk level
    high = sum(1 for r in results if r['total_risk_score'] >= 70)
    medium = sum(1 for r in results if 40 <= r['total_risk_score'] < 70)
    low = sum(1 for r in results if r['total_risk_score'] < 40)
    
    print(f"Risk distribution:")
    print(f"  High (≥70):   {high}")
    print(f"  Medium (40-69): {medium}")
    print(f"  Low (<40):    {low}")
    
    # Create stratified sample
    print("\nCreating stratified sample...")
    sample = stratified_sample(results, high_risk_n=25, medium_risk_n=20, low_risk_n=5)
    
    print(f"Sample size: {len(sample)}")
    
    # Create validation files
    import os
    os.makedirs('data/analysis', exist_ok=True)
    
    create_validation_csv(sample, 'data/analysis/validation_sample.csv')
    create_validation_json(sample, 'data/analysis/validation_sample.json')
    
    # Print instructions
    print_validation_instructions()
    
    print("✅ Validation setup complete!")
    print("\nNext steps:")
    print("1. Open data/analysis/validation_sample.csv in Excel/Google Sheets")
    print("2. Review each URL and fill in 'Ground Truth Label' column")
    print("3. Add notes in the 'Notes' column")
    print("4. Save and use for precision/recall calculation")


if __name__ == "__main__":
    main()
