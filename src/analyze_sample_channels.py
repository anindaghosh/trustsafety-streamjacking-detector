"""
Pre-analyze sample channels to assist with manual validation
Identifies likely false positives and high-confidence scams
"""

import json
from collections import defaultdict
from typing import List, Dict


def load_validation_sample(filepath: str) -> List[Dict]:
    """Load validation sample"""
    with open(filepath, 'r') as f:
        return json.load(f)


def analyze_channel_patterns(channels: List[Dict]) -> Dict:
    """Analyze patterns in the sample to assist with manual review"""
    
    analysis = {
        'likely_false_positives': [],
        'high_confidence_scams': [],
        'needs_careful_review': [],
        'patterns': defaultdict(list)
    }
    
    for channel in channels:
        channel_title = channel.get('channel_title', '').lower()
        video_title = channel.get('video_title', '').lower()
        signals = channel.get('signals', {})
        video_signals = signals.get('video', [])
        channel_signals = signals.get('channel', [])
        risk_score = channel.get('risk_score', 0)
        
        # Pattern detection
        channel_info = {
            'id': channel['id'],
            'channel_title': channel.get('channel_title'),
            'video_title': channel.get('video_title'),
            'risk_score': risk_score,
            'video_url': channel.get('video_url'),
            'channel_url': channel.get('channel_url'),
            'reasoning': []
        }
        
        # Known legitimate channels (likely false positives)
        known_legitimate = [
            'bloomberg', 'cnbc', 'fox business', 'cnn', 'reuters',
            'labpadre', 'nasaspaceflight', 'everyday astronaut',
            'coindesk', 'cointelegraph', 'bitcoin magazine'
        ]
        
        if any(legit in channel_title for legit in known_legitimate):
            channel_info['reasoning'].append(f"Known legitimate: {channel_title}")
            analysis['likely_false_positives'].append(channel_info)
            continue
        
        # High-confidence scam indicators
        scam_confidence_score = 0
        
        # Check for multiple strong signals
        has_impersonation = any('impersonation' in str(s).lower() for s in video_signals + channel_signals)
        has_crypto_address = any('crypto address' in str(s).lower() or 'suspicious url' in str(s).lower() for s in video_signals)
        has_scam_keywords = any('scam keyword' in str(s).lower() for s in video_signals)
        has_giveaway = 'giveaway' in video_title or 'giveaway' in channel_title
        
        if has_impersonation:
            scam_confidence_score += 3
            channel_info['reasoning'].append("Has impersonation signals")
        
        if has_crypto_address:
            scam_confidence_score += 2
            channel_info['reasoning'].append("Contains crypto addresses/suspicious URLs")
        
        if has_scam_keywords:
            scam_confidence_score += 2
            channel_info['reasoning'].append("Contains scam keywords")
        
        if has_giveaway:
            scam_confidence_score += 2
            channel_info['reasoning'].append("Mentions giveaway")
        
        # Check for celebrity impersonation in title
        celebrities = ['elon musk', 'cathie wood', 'michael saylor', 'vitalik', 
                      'tesla', 'spacex', 'coinbase', 'binance']
        impersonated = [celeb for celeb in celebrities if celeb in video_title or celeb in channel_title]
        
        if impersonated and (has_crypto_address or has_giveaway):
            scam_confidence_score += 3
            channel_info['reasoning'].append(f"Impersonating: {', '.join(impersonated)}")
        
        # Classify based on confidence
        if scam_confidence_score >= 7:
            channel_info['confidence'] = 'high'
            analysis['high_confidence_scams'].append(channel_info)
        elif scam_confidence_score >= 4:
            channel_info['confidence'] = 'medium'
            analysis['needs_careful_review'].append(channel_info)
        else:
            channel_info['confidence'] = 'low'
            # Check if it's likely legitimate despite score
            if 'podcast' in channel_title or 'news' in channel_title or 'finance' in channel_title:
                channel_info['reasoning'].append("Appears to be news/educational content")
                analysis['likely_false_positives'].append(channel_info)
            else:
                analysis['needs_careful_review'].append(channel_info)
    
    return analysis


def print_pre_analysis(analysis: Dict):
    """Print pre-analysis to assist with manual review"""
    
    print("\n" + "="*80)
    print("PRE-ANALYSIS: VALIDATION ASSISTANCE")
    print("="*80)
    
    print(f"\n🟢 LIKELY FALSE POSITIVES ({len(analysis['likely_false_positives'])})")
    print(f"{'─'*80}")
    print("These appear to be legitimate channels that triggered detection:")
    print()
    
    for channel in analysis['likely_false_positives'][:10]:  # Show first 10
        print(f"ID {channel['id']:3d} | Score: {channel['risk_score']:5.1f} | {channel['channel_title']}")
        for reason in channel['reasoning']:
            print(f"       → {reason}")
        print(f"       URL: {channel['video_url']}")
        print()
    
    print(f"\n🔴 HIGH CONFIDENCE SCAMS ({len(analysis['high_confidence_scams'])})")
    print(f"{'─'*80}")
    print("Strong indicators of stream-jacking/scams:")
    print()
    
    for channel in analysis['high_confidence_scams'][:10]:  # Show first 10
        print(f"ID {channel['id']:3d} | Score: {channel['risk_score']:5.1f} | {channel['channel_title']}")
        print(f"       Video: {channel['video_title'][:70]}")
        for reason in channel['reasoning']:
            print(f"       → {reason}")
        print(f"       URL: {channel['video_url']}")
        print()
    
    print(f"\n🟡 NEEDS CAREFUL REVIEW ({len(analysis['needs_careful_review'])})")
    print(f"{'─'*80}")
    print("Ambiguous cases requiring manual inspection:")
    print()
    
    for channel in analysis['needs_careful_review'][:10]:  # Show first 10
        print(f"ID {channel['id']:3d} | Score: {channel['risk_score']:5.1f} | {channel['channel_title']}")
        print(f"       Video: {channel['video_title'][:70]}")
        for reason in channel['reasoning']:
            print(f"       → {reason}")
        print()
    
    print("\n" + "="*80)


def create_pre_labeled_csv(analysis: Dict, output_file: str):
    """Create CSV with pre-filled suggestions (user can override)"""
    import csv
    
    # Flatten all channels with suggestions
    suggested_labels = []
    
    for channel in analysis['likely_false_positives']:
        channel['suggested_label'] = 'false_positive'
        suggested_labels.append(channel)
    
    for channel in analysis['high_confidence_scams']:
        channel['suggested_label'] = 'true_positive'
        suggested_labels.append(channel)
    
    for channel in analysis['needs_careful_review']:
        channel['suggested_label'] = ''  # No suggestion
        suggested_labels.append(channel)
    
    # Sort by ID
    suggested_labels.sort(key=lambda x: x['id'])
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        writer.writerow([
            'ID',
            'Video URL',
            'Channel URL',
            'Risk Score',
            'Channel Name',
            'Video Title',
            'Suggested Label',
            'Your Label',
            'Confidence',
            'Pre-Analysis Notes',
            'Your Notes'
        ])
        
        for channel in suggested_labels:
            writer.writerow([
                channel['id'],
                channel.get('video_url', ''),
                channel.get('channel_url', ''),
                f"{channel['risk_score']:.1f}",
                channel.get('channel_title', ''),
                channel.get('video_title', '')[:80],
                channel.get('suggested_label', ''),
                '',  # For user to fill
                channel.get('confidence', ''),
                '; '.join(channel['reasoning']),
                ''  # For user notes
            ])
    
    print(f"\n✅ Created pre-analyzed CSV: {output_file}")
    print(f"   Use suggestions as starting point, but verify each one!")


def main():
    """Pre-analyze validation sample"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python analyze_sample_channels.py data/analysis/validation_sample.json")
        return
    
    sample_file = sys.argv[1]
    
    print(f"Loading validation sample from {sample_file}...")
    sample = load_validation_sample(sample_file)
    
    print(f"Analyzing {len(sample)} channels...")
    analysis = analyze_channel_patterns(sample)
    
    print_pre_analysis(analysis)
    
    # Create pre-labeled CSV
    create_pre_labeled_csv(analysis, 'data/analysis/validation_sample_prelabeled.csv')
    
    # Save analysis to JSON
    with open('data/analysis/pre_analysis.json', 'w') as f:
        json.dump(analysis, f, indent=2, default=str)
    
    print(f"\n✅ Pre-analysis complete!")
    print(f"\n💡 IMPORTANT: These are SUGGESTIONS based on patterns.")
    print(f"   Always verify by visiting the YouTube URLs yourself!")
    print(f"   Use the pre-labeled CSV as a starting point, not ground truth.")


if __name__ == "__main__":
    main()
