"""
Calculate precision, recall, F1 score from ground truth validation
"""

import json
import csv
import sys
from typing import Dict, List, Tuple
from collections import defaultdict


def load_validated_results(filepath: str) -> List[Dict]:
    """Load validated results from interactive validator JSON output"""
    with open(filepath, 'r') as f:
        return json.load(f)


def load_ground_truth_from_csv(filepath: str) -> List[Dict]:
    """Load ground truth labels from CSV"""
    ground_truth = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('Ground Truth Label'):  # Only include labeled entries
                ground_truth.append({
                    'id': int(row['ID']),
                    'risk_score': float(row['Risk Score']),
                    'predicted_category': row['Risk Category'],
                    'ground_truth_label': row['Ground Truth Label'].strip().lower(),
                    'notes': row.get('Notes', '')
                })
    
    return ground_truth


def load_ground_truth_from_json(filepath: str) -> List[Dict]:
    """Load ground truth labels from JSON"""
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    ground_truth = []
    for entry in data:
        if entry['ground_truth']['label']:  # Only include labeled entries
            ground_truth.append({
                'id': entry['id'],
                'risk_score': entry['risk_score'],
                'predicted_category': entry['risk_category'],
                'ground_truth_label': entry['ground_truth']['label'].strip().lower(),
                'notes': entry['ground_truth'].get('reasoning', '')
            })
    
    return ground_truth


def calculate_metrics_at_threshold(ground_truth: List[Dict], threshold: float) -> Dict:
    """Calculate precision, recall, F1 at a specific risk score threshold"""
    
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0
    
    for entry in ground_truth:
        predicted_positive = entry['risk_score'] >= threshold
        actual_positive = entry['ground_truth_label'] == 'true_positive'
        
        if predicted_positive and actual_positive:
            true_positives += 1
        elif predicted_positive and not actual_positive:
            false_positives += 1
        elif not predicted_positive and actual_positive:
            false_negatives += 1
        elif not predicted_positive and not actual_positive:
            true_negatives += 1
    
    # Calculate metrics
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (true_positives + true_negatives) / len(ground_truth) if len(ground_truth) > 0 else 0
    
    return {
        'threshold': threshold,
        'true_positives': true_positives,
        'false_positives': false_positives,
        'false_negatives': false_negatives,
        'true_negatives': true_negatives,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'accuracy': accuracy
    }


def analyze_false_positives(ground_truth: List[Dict]) -> Dict:
    """Analyze patterns in false positives"""
    
    false_positives = [
        entry for entry in ground_truth 
        if entry['risk_score'] >= 70 and entry['ground_truth_label'] == 'false_positive'
    ]
    
    # Group by notes/reasoning
    patterns = defaultdict(list)
    for fp in false_positives:
        # Extract key patterns from notes
        note_lower = fp['notes'].lower()
        if 'bloomberg' in note_lower or 'news' in note_lower:
            patterns['legitimate_news'].append(fp)
        elif 'educational' in note_lower or 'tutorial' in note_lower:
            patterns['educational_content'].append(fp)
        elif 'space' in note_lower or 'rocket' in note_lower:
            patterns['space_enthusiast'].append(fp)
        elif 'legitimate' in note_lower or 'official' in note_lower:
            patterns['legitimate_company'].append(fp)
        else:
            patterns['other'].append(fp)
    
    return {
        'total_false_positives': len(false_positives),
        'patterns': {k: len(v) for k, v in patterns.items()},
        'false_positive_rate': len(false_positives) / len(ground_truth) if len(ground_truth) > 0 else 0
    }


def analyze_false_negatives(ground_truth: List[Dict]) -> Dict:
    """Analyze patterns in false negatives"""
    
    false_negatives = [
        entry for entry in ground_truth 
        if entry['risk_score'] < 70 and entry['ground_truth_label'] == 'true_positive'
    ]
    
    return {
        'total_false_negatives': len(false_negatives),
        'missed_scams': false_negatives,
        'false_negative_rate': len(false_negatives) / len(ground_truth) if len(ground_truth) > 0 else 0
    }


def print_metrics_report(ground_truth: List[Dict]):
    """Print comprehensive metrics report"""
    
    print("\n" + "="*80)
    print("VALIDATION METRICS REPORT")
    print("="*80)
    
    # Overall statistics
    total = len(ground_truth)
    true_positives_count = sum(1 for e in ground_truth if e['ground_truth_label'] == 'true_positive')
    false_positives_count = sum(1 for e in ground_truth if e['ground_truth_label'] == 'false_positive')
    uncertain_count = sum(1 for e in ground_truth if e['ground_truth_label'] == 'uncertain')
    
    print(f"\n📊 GROUND TRUTH DISTRIBUTION")
    print(f"{'─'*80}")
    print(f"Total Labeled:        {total}")
    print(f"True Positives:       {true_positives_count} ({true_positives_count/total*100:.1f}%)")
    print(f"False Positives:      {false_positives_count} ({false_positives_count/total*100:.1f}%)")
    print(f"Uncertain:            {uncertain_count} ({uncertain_count/total*100:.1f}%)")
    
    # Calculate metrics at different thresholds
    thresholds = [50, 60, 70, 80, 90]
    
    print(f"\n📈 PERFORMANCE AT DIFFERENT THRESHOLDS")
    print(f"{'─'*80}")
    print(f"{'Threshold':<12} {'Precision':<12} {'Recall':<12} {'F1 Score':<12} {'Accuracy':<12}")
    print(f"{'─'*80}")
    
    best_f1 = 0
    best_threshold = 70
    
    for threshold in thresholds:
        metrics = calculate_metrics_at_threshold(ground_truth, threshold)
        print(f"{threshold:<12.0f} {metrics['precision']:<12.3f} {metrics['recall']:<12.3f} {metrics['f1_score']:<12.3f} {metrics['accuracy']:<12.3f}")
        
        if metrics['f1_score'] > best_f1:
            best_f1 = metrics['f1_score']
            best_threshold = threshold
    
    print(f"{'─'*80}")
    print(f"✅ Best F1 Score: {best_f1:.3f} at threshold {best_threshold}")
    
    # Detailed metrics at current threshold (70)
    current_metrics = calculate_metrics_at_threshold(ground_truth, 70)
    
    print(f"\n📊 DETAILED METRICS AT THRESHOLD 70")
    print(f"{'─'*80}")
    print(f"True Positives:       {current_metrics['true_positives']}")
    print(f"False Positives:      {current_metrics['false_positives']}")
    print(f"False Negatives:      {current_metrics['false_negatives']}")
    print(f"True Negatives:       {current_metrics['true_negatives']}")
    print(f"")
    print(f"Precision:            {current_metrics['precision']:.3f}")
    print(f"Recall:               {current_metrics['recall']:.3f}")
    print(f"F1 Score:             {current_metrics['f1_score']:.3f}")
    print(f"Accuracy:             {current_metrics['accuracy']:.3f}")
    
    # False positive analysis
    fp_analysis = analyze_false_positives(ground_truth)
    
    print(f"\n🔍 FALSE POSITIVE ANALYSIS")
    print(f"{'─'*80}")
    print(f"Total False Positives: {fp_analysis['total_false_positives']}")
    print(f"False Positive Rate:   {fp_analysis['false_positive_rate']:.3f}")
    print(f"\nCommon Patterns:")
    for pattern, count in fp_analysis['patterns'].items():
        if count > 0:
            print(f"  • {pattern.replace('_', ' ').title()}: {count}")
    
    # False negative analysis
    fn_analysis = analyze_false_negatives(ground_truth)
    
    print(f"\n⚠️  FALSE NEGATIVE ANALYSIS")
    print(f"{'─'*80}")
    print(f"Total False Negatives: {fn_analysis['total_false_negatives']}")
    print(f"False Negative Rate:   {fn_analysis['false_negative_rate']:.3f}")
    
    if fn_analysis['missed_scams']:
        print(f"\nMissed Scams (Score < 70 but actual scam):")
        for missed in fn_analysis['missed_scams']:
            print(f"  • Score {missed['risk_score']:.1f}: {missed['notes'][:60]}...")
    
    print("\n" + "="*80)


def calculate_metrics_from_validator(validated_data: List[Dict]) -> Dict:
    """Calculate metrics from interactive validator output"""
    tp = fp = uncertain = skipped = 0
    scam_types = defaultdict(int)
    by_risk = defaultdict(lambda: {'tp': 0, 'fp': 0, 'uncertain': 0})
    
    for item in validated_data:
        val = item.get('validation', {})
        label = val.get('label')
        risk_cat = item.get('risk_category', 'UNKNOWN')
        
        if label == 'true_positive':
            tp += 1
            by_risk[risk_cat]['tp'] += 1
            scam_type = val.get('scam_type', 'unknown')
            scam_types[scam_type] += 1
        elif label == 'false_positive':
            fp += 1
            by_risk[risk_cat]['fp'] += 1
        elif label == 'uncertain':
            uncertain += 1
            by_risk[risk_cat]['uncertain'] += 1
        elif label == 'skipped':
            skipped += 1
    
    total_labeled = tp + fp + uncertain
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    
    return {
        'overall': {
            'true_positives': tp,
            'false_positives': fp,
            'uncertain': uncertain,
            'skipped': skipped,
            'total_labeled': total_labeled,
            'precision': precision
        },
        'by_risk_category': dict(by_risk),
        'scam_types': dict(scam_types)
    }


def main():
    """Calculate validation metrics"""
    import os
    
    if len(sys.argv) < 2:
        print("Usage: python calculate_metrics.py <validation_file.csv or .json>")
        print("\nSupported formats:")
        print("  1. Interactive validator output: *_validated.json")
        print("  2. Manual CSV: validation_sample.csv")
        print("  3. Manual JSON: validation_sample.json")
        return
    
    validation_file = sys.argv[1]
    
    if not os.path.exists(validation_file):
        print(f"Error: File not found: {validation_file}")
        return
    
    print(f"Loading validation data from {validation_file}...")
    
    # Determine file type and load
    if '_validated.json' in validation_file:
        # Interactive validator output
        validated_data = load_validated_results(validation_file)
        print(f"Loaded {len(validated_data)} validated detections (interactive validator format)")
        
        metrics = calculate_metrics_from_validator(validated_data)
        
        print("\n" + "="*80)
        print("📊 VALIDATION METRICS")
        print("="*80)
        
        overall = metrics['overall']
        print(f"\n🎯 OVERALL PERFORMANCE:")
        print(f"   Total Labeled: {overall['total_labeled']}")
        print(f"   ✅ True Positives:  {overall['true_positives']}")
        print(f"   ❌ False Positives: {overall['false_positives']}")
        print(f"   ❓ Uncertain:       {overall['uncertain']}")
        print(f"   ⏭️  Skipped:         {overall['skipped']}")
        print(f"\n📈 PRECISION: {overall['precision']:.2%}")
        
        if metrics['by_risk_category']:
            print(f"\n📊 BY RISK CATEGORY:")
            for risk_cat, counts in metrics['by_risk_category'].items():
                total = counts['tp'] + counts['fp'] + counts['uncertain']
                if total > 0:
                    prec = counts['tp'] / (counts['tp'] + counts['fp']) if (counts['tp'] + counts['fp']) > 0 else 0
                    print(f"   {risk_cat}: Precision={prec:.2%} (TP:{counts['tp']}, FP:{counts['fp']})")
        
        if metrics['scam_types']:
            print(f"\n🎯 SCAM TYPES:")
            for scam_type, count in sorted(metrics['scam_types'].items(), key=lambda x: x[1], reverse=True):
                print(f"   • {scam_type}: {count}")
        
        print("="*80)
        
        # Save metrics
        output_file = validation_file.replace('_validated.json', '_metrics.json')
        with open(output_file, 'w') as f:
            json.dump(metrics, f, indent=2)
        print(f"\n💾 Metrics saved to: {output_file}")
        
    elif validation_file.endswith('.csv'):
        ground_truth = load_ground_truth_from_csv(validation_file)
        if not ground_truth:
            print("Error: No labeled data found.")
            return
        print(f"Loaded {len(ground_truth)} labeled samples")
        print_metrics_report(ground_truth)
        
    elif validation_file.endswith('.json'):
        ground_truth = load_ground_truth_from_json(validation_file)
        if not ground_truth:
            print("Error: No labeled data found.")
            return
        print(f"Loaded {len(ground_truth)} labeled samples")
        print_metrics_report(ground_truth)
    
    else:
        print("Error: File must be .csv or .json")
        return


if __name__ == "__main__":
    main()
