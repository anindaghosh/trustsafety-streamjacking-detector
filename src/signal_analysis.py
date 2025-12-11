"""
Comprehensive signal-specific analysis tool for YouTube streamjacking detector research.
Evaluates which detection signals are most reliable for academic paper.
"""

import json
import os
import re
from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict, List, Tuple, Set
import argparse

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib import rcParams
import numpy as np
from pymongo import MongoClient
from dotenv import load_dotenv
import seaborn as sns

# Load environment variables
load_dotenv()

# NYU Purple Color Palette
NYU_PURPLE = '#57068c'
NYU_VIOLET = '#8900e1'
NYU_LIGHT = '#c8b2d6'
NYU_DARK = '#330662'
NYU_ACCENT = '#ff6f00'

# Set publication-quality defaults
rcParams['font.family'] = 'sans-serif'
rcParams['font.sans-serif'] = ['Arial', 'Helvetica', 'DejaVu Sans']
rcParams['font.size'] = 11
rcParams['axes.labelsize'] = 12
rcParams['axes.titlesize'] = 14
rcParams['xtick.labelsize'] = 10
rcParams['ytick.labelsize'] = 10
rcParams['legend.fontsize'] = 10
rcParams['figure.titlesize'] = 16


class SignalDefinition:
    """Definition of a detection signal"""
    def __init__(self, signal_id: int, name: str, signal_type: str, patterns: List[str]):
        self.signal_id = signal_id
        self.name = name
        self.signal_type = signal_type  # 'video' or 'channel'
        self.patterns = patterns  # List of regex/substring patterns to match
        

# Define all 11 signals
SIGNAL_DEFINITIONS = [
    SignalDefinition(1, "Character Substitution", "video", 
                     [r"character substitution", r"substitution impersonation"]),
    SignalDefinition(2, "Comments Disabled", "video",
                     [r"comments disabled"]),
    SignalDefinition(3, "Crypto Addresses/URLs", "video",
                     [r"crypto address", r"crypto url", r"suspicious url", r"contains crypto address"]),
    SignalDefinition(4, "QR Codes", "video",
                     [r"qr code", r"qr-code"]),
    SignalDefinition(5, "Scam Domains", "video",
                     [r"scam domain", r"suspicious domain"]),
    SignalDefinition(6, "Multiple Scam Keywords", "video",
                     [r"multiple scam keyword", r"scam keyword"]),
    SignalDefinition(7, "Name Impersonation", "channel",
                     [r"name impersonation", r"exact match", r"title impersonation"]),
    SignalDefinition(8, "Topic Mismatch", "channel",
                     [r"topic mismatch"]),
    SignalDefinition(9, "Tag Combinations", "channel",
                     [r"suspicious tag", r"tag combination"]),
    SignalDefinition(10, "Channel Age/Content Ratio", "channel",
                     [r"old account", r"minimal content", r"content ratio", r"account age"]),
    SignalDefinition(11, "Live Chat Scams", "video",
                     [r"live chat", r"pinned", r"super chat"])
]


class SignalAnalyzer:
    """Analyzes detection signals from validated samples"""
    
    def __init__(self, collection_name: str = 'detection_results_v3'):
        self.collection_name = collection_name
        self.samples = []
        self.signal_data = {}
        self.signal_definitions = {s.signal_id: s for s in SIGNAL_DEFINITIONS}
        
    def load_data_from_mongodb(self) -> int:
        """Load validated samples from MongoDB"""
        try:
            conn_str = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
            client = MongoClient(conn_str, serverSelectionTimeoutMS=5000)
            client.admin.command('ping')
            
            db = client['streamjacking']
            collection = db[self.collection_name]
            
            # Query only documents with validation labels
            self.samples = list(collection.find({
                'validation.label': {'$exists': True, '$ne': None}
            }))
            
            client.close()
            
            print(f"✅ Loaded {len(self.samples)} validated samples from MongoDB")
            return len(self.samples)
            
        except Exception as e:
            print(f"❌ Error connecting to MongoDB: {e}")
            print("Make sure MongoDB is running and MONGODB_URI is set in .env")
            return 0
    
    def extract_signals_from_sample(self, sample: Dict) -> Set[int]:
        """Extract which signals are present in a sample"""
        detected_signals = set()
        
        # Get signal arrays
        video_signals = sample.get('video_signals', []) or []
        channel_signals = sample.get('channel_signals', []) or []
        
        # Convert to lowercase strings
        video_signals_text = ' '.join(str(s).lower() for s in video_signals)
        channel_signals_text = ' '.join(str(s).lower() for s in channel_signals)
        
        # Check each signal definition
        for signal_def in SIGNAL_DEFINITIONS:
            if signal_def.signal_type == 'video':
                text = video_signals_text
            else:
                text = channel_signals_text
            
            # Check if any pattern matches
            for pattern in signal_def.patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    detected_signals.add(signal_def.signal_id)
                    break
        
        return detected_signals
    
    def get_actual_label(self, sample: Dict) -> bool:
        """Get ground truth: True if actual positive (scam), False if actual negative"""
        label = sample.get('validation', {}).get('label', '')
        # true_positive and false_negative are actual positives
        return label in ['true_positive', 'false_negative']
    
    def calculate_signal_metrics(self) -> Dict:
        """Calculate per-signal metrics"""
        print("\n📊 Calculating per-signal metrics...")
        
        results = {}
        
        for signal_id, signal_def in self.signal_definitions.items():
            tp = fp = tn = fn = 0
            samples_with_signal = []
            
            for sample in self.samples:
                detected_signals = self.extract_signals_from_sample(sample)
                actual_positive = self.get_actual_label(sample)
                signal_present = signal_id in detected_signals
                
                # Confusion matrix
                if signal_present and actual_positive:
                    tp += 1
                    samples_with_signal.append(sample['video_id'])
                elif signal_present and not actual_positive:
                    fp += 1
                    samples_with_signal.append(sample['video_id'])
                elif not signal_present and actual_positive:
                    fn += 1
                elif not signal_present and not actual_positive:
                    tn += 1
            
            # Calculate metrics
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            support = tp + fp
            
            results[f"signal_{signal_id}"] = {
                'name': signal_def.name,
                'type': signal_def.signal_type,
                'confusion_matrix': {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn},
                'metrics': {
                    'precision': round(precision, 3),
                    'recall': round(recall, 3),
                    'f1': round(f1, 3),
                    'accuracy': round(accuracy, 3),
                    'false_positive_rate': round(fpr, 3)
                },
                'support': support,
                'samples_with_signal': samples_with_signal[:5]  # First 5 for reference
            }
            
            print(f"  Signal {signal_id:2d} ({signal_def.name:30s}): "
                  f"P={precision:.2f} R={recall:.2f} F1={f1:.2f} Support={support}")
        
        # Rank signals by F1 score
        sorted_signals = sorted(results.items(), 
                               key=lambda x: x[1]['metrics']['f1'], 
                               reverse=True)
        for rank, (sig_id, data) in enumerate(sorted_signals, 1):
            results[sig_id]['rank'] = rank
        
        return results
    
    def calculate_signal_cooccurrence(self) -> np.ndarray:
        """Calculate signal co-occurrence matrix"""
        print("\n🔗 Calculating signal co-occurrence...")
        
        n_signals = len(SIGNAL_DEFINITIONS)
        cooccurrence = np.zeros((n_signals, n_signals))
        
        for sample in self.samples:
            detected_signals = list(self.extract_signals_from_sample(sample))
            
            # Update co-occurrence matrix
            for i, sig1 in enumerate(detected_signals):
                for sig2 in detected_signals:
                    cooccurrence[sig1-1][sig2-1] += 1
        
        return cooccurrence
    
    def analyze_combinations(self, signal_metrics: Dict) -> Dict:
        """Test signal combinations for optimal performance"""
        print("\n🔬 Analyzing signal combinations...")
        
        # Sort signals by F1 score
        sorted_signals = sorted(
            signal_metrics.items(),
            key=lambda x: x[1]['metrics']['f1'],
            reverse=True
        )
        
        # Test cumulative performance
        cumulative_performance = []
        selected_signals = []
        
        for sig_id, sig_data in sorted_signals:
            if sig_data['metrics']['f1'] == 0:
                continue  # Skip signals with no predictive power
                
            selected_signals.append(sig_id)
            
            # Calculate performance with this subset
            tp = fp = tn = fn = 0
            
            for sample in self.samples:
                detected_signals = self.extract_signals_from_sample(sample)
                actual_positive = self.get_actual_label(sample)
                
                # Check if ANY of the selected signals are present
                any_signal_present = any(
                    int(sig.split('_')[1]) in detected_signals 
                    for sig in selected_signals
                )
                
                if any_signal_present and actual_positive:
                    tp += 1
                elif any_signal_present and not actual_positive:
                    fp += 1
                elif not any_signal_present and actual_positive:
                    fn += 1
                else:
                    tn += 1
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            cumulative_performance.append({
                'signals': selected_signals.copy(),
                'count': len(selected_signals),
                'precision': round(precision, 3),
                'recall': round(recall, 3),
                'f1': round(f1, 3)
            })
            
            print(f"  With {len(selected_signals):2d} signals: "
                  f"P={precision:.3f} R={recall:.3f} F1={f1:.3f}")
        
        # Find optimal subset (highest F1)
        optimal = max(cumulative_performance, key=lambda x: x['f1'])
        
        # Test logical groups
        video_signals = [s for s in signal_metrics.keys() 
                        if signal_metrics[s]['type'] == 'video']
        channel_signals = [s for s in signal_metrics.keys() 
                          if signal_metrics[s]['type'] == 'channel']
        
        video_f1 = self._calculate_group_f1(video_signals)
        channel_f1 = self._calculate_group_f1(channel_signals)
        all_f1 = self._calculate_group_f1(list(signal_metrics.keys()))
        
        return {
            'cumulative_performance': cumulative_performance,
            'optimal_subset': optimal['signals'],
            'optimal_f1': optimal['f1'],
            'optimal_count': optimal['count'],
            'all_signals_f1': all_f1,
            'video_only_f1': video_f1,
            'channel_only_f1': channel_f1
        }
    
    def _calculate_group_f1(self, signal_ids: List[str]) -> float:
        """Calculate F1 for a group of signals"""
        tp = fp = tn = fn = 0
        
        for sample in self.samples:
            detected_signals = self.extract_signals_from_sample(sample)
            actual_positive = self.get_actual_label(sample)
            
            any_signal_present = any(
                int(sig.split('_')[1]) in detected_signals 
                for sig in signal_ids
            )
            
            if any_signal_present and actual_positive:
                tp += 1
            elif any_signal_present and not actual_positive:
                fp += 1
            elif not any_signal_present and actual_positive:
                fn += 1
            else:
                tn += 1
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return round(f1, 3)
    
    def generate_recommendations(self, signal_metrics: Dict, combinations: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Find highest precision signal
        highest_precision = max(signal_metrics.items(), 
                               key=lambda x: x[1]['metrics']['precision'])
        recommendations.append(
            f"Signal {highest_precision[0].split('_')[1]} ({highest_precision[1]['name']}) "
            f"has highest precision ({highest_precision[1]['metrics']['precision']:.2f})"
        )
        
        # Find signals causing false positives
        high_fp_signals = [
            (sid, data) for sid, data in signal_metrics.items()
            if data['confusion_matrix']['fp'] > data['confusion_matrix']['tp']
        ]
        if high_fp_signals:
            for sid, data in high_fp_signals:
                recommendations.append(
                    f"Signal {sid.split('_')[1]} ({data['name']}) causes more false positives "
                    f"({data['confusion_matrix']['fp']}) than true positives ({data['confusion_matrix']['tp']})"
                )
        
        # Optimal subset recommendation
        if combinations['optimal_count'] < len(signal_metrics):
            optimal_names = [
                signal_metrics[sig]['name'] 
                for sig in combinations['optimal_subset']
            ]
            recommendations.append(
                f"Optimal subset uses {combinations['optimal_count']} signals "
                f"(F1={combinations['optimal_f1']:.3f}): {', '.join(optimal_names)}"
            )
        
        # Compare video vs channel signals
        if combinations['video_only_f1'] > combinations['channel_only_f1']:
            recommendations.append(
                f"Video signals (F1={combinations['video_only_f1']:.3f}) "
                f"outperform channel signals (F1={combinations['channel_only_f1']:.3f})"
            )
        else:
            recommendations.append(
                f"Channel signals (F1={combinations['channel_only_f1']:.3f}) "
                f"outperform video signals (F1={combinations['video_only_f1']:.3f})"
            )
        
        # Identify weak signals
        weak_signals = [
            (sid, data) for sid, data in signal_metrics.items()
            if data['metrics']['f1'] < 0.3 and data['support'] > 0
        ]
        if weak_signals:
            for sid, data in weak_signals:
                recommendations.append(
                    f"Consider disabling Signal {sid.split('_')[1]} ({data['name']}) "
                    f"due to low F1 score ({data['metrics']['f1']:.2f})"
                )
        
        return recommendations


def create_visualizations(signal_metrics: Dict, cooccurrence: np.ndarray, 
                         combinations: Dict, output_dir: str):
    """Generate all visualizations"""
    print("\n🎨 Creating visualizations...")
    
    signals_dir = os.path.join(output_dir, 'visualizations', 'signals')
    os.makedirs(signals_dir, exist_ok=True)
    
    # 1. Per-signal performance bar chart
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Sort by F1 descending
    sorted_data = sorted(signal_metrics.items(), 
                        key=lambda x: x[1]['metrics']['f1'], 
                        reverse=True)
    
    signal_names = [data['name'] for _, data in sorted_data]
    precisions = [data['metrics']['precision'] for _, data in sorted_data]
    recalls = [data['metrics']['recall'] for _, data in sorted_data]
    f1s = [data['metrics']['f1'] for _, data in sorted_data]
    
    x = np.arange(len(signal_names))
    width = 0.25
    
    ax.bar(x - width, precisions, width, label='Precision', color=NYU_PURPLE, alpha=0.8)
    ax.bar(x, recalls, width, label='Recall', color=NYU_VIOLET, alpha=0.8)
    ax.bar(x + width, f1s, width, label='F1 Score', color=NYU_LIGHT, alpha=0.8)
    
    ax.set_xlabel('Detection Signal', fontweight='bold')
    ax.set_ylabel('Score', fontweight='bold')
    ax.set_title('Per-Signal Performance Metrics (Sorted by F1 Score)', 
                fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(signal_names, rotation=45, ha='right')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    ax.set_ylim(0, 1.1)
    
    plt.tight_layout()
    plt.savefig(os.path.join(signals_dir, '01_signal_performance.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved signal performance chart")
    
    # 2. Signal co-occurrence heatmap
    fig, ax = plt.subplots(figsize=(12, 10))
    
    # Normalize by diagonal (self-occurrence)
    cooccurrence_norm = cooccurrence.copy()
    for i in range(len(cooccurrence)):
        if cooccurrence[i, i] > 0:
            cooccurrence_norm[i, :] /= cooccurrence[i, i]
            cooccurrence_norm[:, i] /= cooccurrence[i, i]
    
    sns.heatmap(cooccurrence_norm, annot=True, fmt='.2f', cmap='Purples',
                cbar_kws={'label': 'Co-occurrence Rate'},
                xticklabels=[f"S{i+1}" for i in range(11)],
                yticklabels=[f"S{i+1}" for i in range(11)],
                ax=ax, square=True)
    
    ax.set_title('Signal Co-occurrence Matrix (Normalized)', fontweight='bold', pad=20)
    ax.set_xlabel('Signal', fontweight='bold')
    ax.set_ylabel('Signal', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(signals_dir, '02_cooccurrence_matrix.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved co-occurrence heatmap")
    
    # 3. Cumulative F1 score line chart
    fig, ax = plt.subplots(figsize=(12, 7))
    
    cumulative = combinations['cumulative_performance']
    counts = [c['count'] for c in cumulative]
    f1_scores = [c['f1'] for c in cumulative]
    precisions = [c['precision'] for c in cumulative]
    recalls = [c['recall'] for c in cumulative]
    
    ax.plot(counts, f1_scores, marker='o', linewidth=2.5, markersize=8,
            color=NYU_PURPLE, label='F1 Score')
    ax.plot(counts, precisions, marker='s', linewidth=2, markersize=6,
            color=NYU_VIOLET, label='Precision', linestyle='--', alpha=0.7)
    ax.plot(counts, recalls, marker='^', linewidth=2, markersize=6,
            color=NYU_LIGHT, label='Recall', linestyle='--', alpha=0.7)
    
    # Mark optimal point
    optimal_idx = next(i for i, c in enumerate(cumulative) 
                      if c['f1'] == combinations['optimal_f1'])
    ax.plot(counts[optimal_idx], f1_scores[optimal_idx], marker='*',
            markersize=20, color=NYU_ACCENT, label='Optimal',
            markeredgecolor='black', markeredgewidth=1.5)
    
    ax.set_xlabel('Number of Signals Used', fontweight='bold')
    ax.set_ylabel('Score', fontweight='bold')
    ax.set_title('Cumulative Performance: Adding Signals by F1 Rank', 
                fontweight='bold', pad=20)
    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.set_ylim(0, 1.1)
    
    plt.tight_layout()
    plt.savefig(os.path.join(signals_dir, '03_cumulative_f1.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved cumulative F1 chart")
    
    # 4. Video vs Channel signals comparison
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    video_signals = {k: v for k, v in signal_metrics.items() if v['type'] == 'video'}
    channel_signals = {k: v for k, v in signal_metrics.items() if v['type'] == 'channel'}
    
    # Video signals
    video_names = [v['name'] for v in video_signals.values()]
    video_f1s = [v['metrics']['f1'] for v in video_signals.values()]
    video_precisions = [v['metrics']['precision'] for v in video_signals.values()]
    
    x1 = np.arange(len(video_names))
    width = 0.35
    ax1.bar(x1 - width/2, video_precisions, width, label='Precision', 
            color=NYU_PURPLE, alpha=0.8)
    ax1.bar(x1 + width/2, video_f1s, width, label='F1 Score', 
            color=NYU_VIOLET, alpha=0.8)
    ax1.set_title('Video Signals Performance', fontweight='bold', pad=15)
    ax1.set_xlabel('Signal', fontweight='bold')
    ax1.set_ylabel('Score', fontweight='bold')
    ax1.set_xticks(x1)
    ax1.set_xticklabels(video_names, rotation=45, ha='right')
    ax1.legend()
    ax1.grid(axis='y', alpha=0.3)
    ax1.set_ylim(0, 1.1)
    
    # Channel signals
    channel_names = [v['name'] for v in channel_signals.values()]
    channel_f1s = [v['metrics']['f1'] for v in channel_signals.values()]
    channel_precisions = [v['metrics']['precision'] for v in channel_signals.values()]
    
    x2 = np.arange(len(channel_names))
    ax2.bar(x2 - width/2, channel_precisions, width, label='Precision',
            color=NYU_PURPLE, alpha=0.8)
    ax2.bar(x2 + width/2, channel_f1s, width, label='F1 Score',
            color=NYU_VIOLET, alpha=0.8)
    ax2.set_title('Channel Signals Performance', fontweight='bold', pad=15)
    ax2.set_xlabel('Signal', fontweight='bold')
    ax2.set_ylabel('Score', fontweight='bold')
    ax2.set_xticks(x2)
    ax2.set_xticklabels(channel_names, rotation=45, ha='right')
    ax2.legend()
    ax2.grid(axis='y', alpha=0.3)
    ax2.set_ylim(0, 1.1)
    
    plt.tight_layout()
    plt.savefig(os.path.join(signals_dir, '04_video_vs_channel.png'), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved video vs channel comparison")
    
    print(f"\n✅ All visualizations saved to {signals_dir}")


def main():
    parser = argparse.ArgumentParser(
        description='Comprehensive signal-specific analysis for streamjacking detector'
    )
    parser.add_argument('--collection', default='detection_results_latest',
                       help='MongoDB collection name (default: detection_results_latest)')
    parser.add_argument('--output-dir', default='../data/analysis',
                       help='Output directory for results (default: ../data/analysis)')
    
    args = parser.parse_args()
    
    print("="*70)
    print("  SIGNAL-SPECIFIC ANALYSIS FOR STREAMJACKING DETECTION")
    print("="*70)
    
    # Initialize analyzer
    analyzer = SignalAnalyzer(collection_name=args.collection)
    
    # Load data
    n_samples = analyzer.load_data_from_mongodb()
    if n_samples == 0:
        print("❌ No validated samples found. Exiting.")
        return
    
    # Calculate per-signal metrics
    signal_metrics = analyzer.calculate_signal_metrics()
    
    # Calculate signal co-occurrence
    cooccurrence = analyzer.calculate_signal_cooccurrence()
    
    # Analyze combinations
    combinations = analyzer.analyze_combinations(signal_metrics)
    
    # Generate recommendations
    recommendations = analyzer.generate_recommendations(signal_metrics, combinations)
    
    # Prepare output report
    report = {
        'analysis_date': datetime.now().isoformat(),
        'validation_samples': n_samples,
        'signals': signal_metrics,
        'combinations': combinations,
        'recommendations': recommendations
    }
    
    # Save report
    output_file = os.path.join(args.output_dir, 'signal_analysis_report.json')
    os.makedirs(args.output_dir, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n💾 Saved comprehensive report to {output_file}")
    
    # Generate visualizations
    create_visualizations(signal_metrics, cooccurrence, combinations, args.output_dir)
    
    # Print summary
    print("\n" + "="*70)
    print("  ANALYSIS SUMMARY")
    print("="*70)
    print(f"\n📈 Overall Performance:")
    print(f"   All signals F1: {combinations['all_signals_f1']:.3f}")
    print(f"   Optimal subset F1: {combinations['optimal_f1']:.3f} "
          f"(using {combinations['optimal_count']} signals)")
    print(f"   Video-only F1: {combinations['video_only_f1']:.3f}")
    print(f"   Channel-only F1: {combinations['channel_only_f1']:.3f}")
    
    print(f"\n💡 Key Recommendations:")
    for i, rec in enumerate(recommendations[:5], 1):
        print(f"   {i}. {rec}")
    
    print("\n" + "="*70)
    print("✅ Analysis complete!")
    print("="*70)


if __name__ == '__main__':
    main()
