"""
Generate comprehensive visualizations for validation metrics in NYU purple colors
Creates publication-ready charts for presentation slides
"""

import json
import os
from typing import Dict, List
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib import rcParams
import numpy as np
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# NYU Purple Color Palette
NYU_PURPLE = '#57068c'  # Primary NYU purple
NYU_VIOLET = '#8900e1'  # Lighter purple
NYU_LIGHT = '#c8b2d6'   # Light purple
NYU_DARK = '#330662'    # Dark purple
NYU_ACCENT = '#ff6f00'  # Orange accent for emphasis

# Additional colors for multi-class
COLORS = {
    'true_positive': NYU_PURPLE,
    'false_positive': NYU_ACCENT,
    'true_negative': NYU_LIGHT,
    'false_negative': NYU_VIOLET,
    'high': NYU_PURPLE,
    'medium': NYU_VIOLET,
    'low': NYU_LIGHT,
    'critical': NYU_DARK
}

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


def load_validation_data_from_mongodb() -> List[Dict]:
    """Load validated results from MongoDB"""
    try:
        conn_str = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
        client = MongoClient(conn_str, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        
        db = client['streamjacking']
        collection = db['detection_results_v3']
        
        validated_docs = list(collection.find({
            'validation.label': {'$exists': True, '$ne': None}
        }))
        
        client.close()
        print(f"✅ Loaded {len(validated_docs)} validated samples from MongoDB")
        return validated_docs
        
    except Exception as e:
        print(f"❌ Error loading from MongoDB: {e}")
        return []


def calculate_metrics(data: List[Dict]) -> Dict:
    """Calculate all metrics from validation data"""
    # Count confusion matrix elements
    tp = sum(1 for d in data if d.get('validation', {}).get('label') == 'true_positive')
    fp = sum(1 for d in data if d.get('validation', {}).get('label') == 'false_positive')
    tn = sum(1 for d in data if d.get('validation', {}).get('label') == 'true_negative')
    fn = sum(1 for d in data if d.get('validation', {}).get('label') == 'false_negative')
    
    # Calculate metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    
    # Risk category distribution
    risk_dist = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    for doc in data:
        cat = doc.get('risk_category', 'UNKNOWN')
        risk_dist[cat] = risk_dist.get(cat, 0) + 1
    
    return {
        'confusion_matrix': {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn},
        'metrics': {
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'accuracy': accuracy,
            'specificity': specificity
        },
        'risk_distribution': risk_dist,
        'total_samples': len(data)
    }


def plot_diagnostic_grid(metrics: Dict, output_path: str):
    """Create diagnostic grid - 2x2 tile visualization showing where system succeeded and failed"""
    cm = metrics['confusion_matrix']
    
    fig, ax = plt.subplots(figsize=(14, 10))
    ax.set_xlim(0, 2)
    ax.set_ylim(0, 2)
    ax.set_aspect('equal')
    ax.axis('off')
    
    # Define colors for each quadrant
    colors = {
        'tp': '#4CAF50',  # Green - Success
        'fn': '#F44336',  # Red - Blind Spots
        'fp': '#FFC107',  # Yellow/Orange - Urgency Trap
        'tn': '#2196F3'   # Blue - Stability
    }
    
    # Define quadrant data: (x, y, width, height, color, count, title, subtitle, emoji)
    quadrants = [
        # Top-left: True Positives (Detected as STREAMJACK, Actual STREAMJACK)
        (0, 1, 1, 1, colors['tp'], cm['tp'], 'True Positives', 'Caught STREAMJACKs', '🟩 Success'),
        # Top-right: False Negatives (Detected as SAFE, Actual STREAMJACK)
        (1, 1, 1, 1, colors['fn'], cm['fn'], 'False Negatives', 'Missed STREAMJACKs', '🟥 The Blind Spots'),
        # Bottom-left: False Positives (Detected as STREAMJACK, Actual SAFE)
        (0, 0, 1, 1, colors['fp'], cm['fp'], 'False Positives', 'False Alarms', '🟨 Urgency Trap'),
        # Bottom-right: True Negatives (Detected as SAFE, Actual SAFE)
        (1, 0, 1, 1, colors['tn'], cm['tn'], 'True Negatives', 'Correctly Ignored', '🟦 Stability')
    ]
    
    # Draw each quadrant
    for x, y, w, h, color, count, title, subtitle, emoji in quadrants:
        # Draw rectangle
        rect = mpatches.Rectangle((x, y), w, h, linewidth=3, 
                                   edgecolor='white', facecolor=color, alpha=0.85)
        ax.add_patch(rect)
        
        # Add count (large)
        ax.text(x + w/2, y + h/2 + 0.15, str(count),
               ha='center', va='center', fontsize=72, fontweight='bold',
               color='white', family='sans-serif')
        
        # Add title
        ax.text(x + w/2, y + h/2 - 0.15, title,
               ha='center', va='center', fontsize=16, fontweight='bold',
               color='white')
        
        # Add subtitle
        ax.text(x + w/2, y + h/2 - 0.28, subtitle,
               ha='center', va='center', fontsize=13,
               color='white', style='italic')
        
        # Add emoji label
        ax.text(x + w/2, y + 0.08, emoji,
               ha='center', va='center', fontsize=11,
               color='white', fontweight='bold')
    
    # Add column headers
    ax.text(0.5, 2.12, 'Detected as STREAMJACK', ha='center', va='bottom',
           fontsize=18, fontweight='bold', color=NYU_PURPLE)
    ax.text(1.5, 2.12, 'Detected as SAFE', ha='center', va='bottom',
           fontsize=18, fontweight='bold', color=NYU_PURPLE)
    
    # Add row labels
    ax.text(-0.15, 1.5, 'Actual\nSTREAMJACK', ha='right', va='center',
           fontsize=18, fontweight='bold', color=NYU_PURPLE, rotation=0)
    ax.text(-0.15, 0.5, 'Actual\nSAFE', ha='right', va='center',
           fontsize=18, fontweight='bold', color=NYU_PURPLE, rotation=0)
    
    # Add title
    fig.text(0.5, 0.96, 'Diagnostic Grid: Where The System Succeeded & Failed',
            ha='center', fontsize=22, fontweight='bold', color=NYU_DARK)
    
    # Add interpretation text at bottom
    interpretation = (
        "🟩 Success: Correctly identified STREAMJACKs  |  "
        "🟥 Blind Spots: Missed STREAMJACKs that need attention  |  "
        "🟨 Urgency Trap: False alarms  |  "
        "🟦 Stability: Correctly identified safe content"
    )
    fig.text(0.5, 0.02, interpretation,
            ha='center', fontsize=11, color='#666666', style='italic')
    
    plt.tight_layout(rect=[0, 0.04, 1, 0.94])
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✅ Saved: {output_path}")
    plt.close()


def plot_confusion_matrix(metrics: Dict, output_path: str):
    """Create confusion matrix heatmap"""
    cm = metrics['confusion_matrix']
    matrix = np.array([[cm['tp'], cm['fn']], 
                       [cm['fp'], cm['tn']]])
    
    fig, ax = plt.subplots(figsize=(8, 6))
    
    # Create heatmap
    im = ax.imshow(matrix, cmap='Purples', aspect='auto', vmin=0, vmax=max(matrix.flatten()))
    
    # Labels
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(['Predicted\nPositive', 'Predicted\nNegative'], fontsize=12)
    ax.set_yticklabels(['Actual\nPositive', 'Actual\nNegative'], fontsize=12)
    ax.set_xlabel('Predicted Label', fontsize=13, fontweight='bold')
    ax.set_ylabel('Actual Label', fontsize=13, fontweight='bold')
    ax.set_title('Confusion Matrix', fontsize=16, fontweight='bold', pad=20)
    
    # Add text annotations
    labels = [['True Positive', 'False Negative'],
              ['False Positive', 'True Negative']]
    for i in range(2):
        for j in range(2):
            text_color = 'white' if matrix[i, j] > max(matrix.flatten()) / 2 else 'black'
            ax.text(j, i, f'{labels[i][j]}\n{matrix[i, j]}',
                   ha='center', va='center', color=text_color, 
                   fontsize=12, fontweight='bold')
    
    # Colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Count', rotation=270, labelpad=20, fontsize=11)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✅ Saved: {output_path}")
    plt.close()


def plot_performance_metrics(metrics: Dict, output_path: str):
    """Create bar chart of performance metrics"""
    m = metrics['metrics']
    metric_names = ['Precision', 'Recall', 'F1 Score', 'Accuracy', 'Specificity']
    values = [m['precision'], m['recall'], m['f1'], m['accuracy'], m['specificity']]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    bars = ax.barh(metric_names, values, color=NYU_PURPLE, edgecolor=NYU_DARK, linewidth=1.5)
    
    # Add value labels
    for i, (bar, val) in enumerate(zip(bars, values)):
        ax.text(val + 0.02, i, f'{val:.1%}', 
               va='center', fontsize=11, fontweight='bold')
    
    ax.set_xlabel('Score', fontsize=13, fontweight='bold')
    ax.set_title('Detection Performance Metrics', fontsize=16, fontweight='bold', pad=20)
    ax.set_xlim(0, 1.1)
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)
    
    # Add reference line at 0.8 (target)
    ax.axvline(x=0.8, color=NYU_ACCENT, linestyle='--', linewidth=2, alpha=0.7, label='Target (80%)')
    ax.legend(loc='lower right', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✅ Saved: {output_path}")
    plt.close()


def plot_risk_distribution(metrics: Dict, output_path: str):
    """Create pie chart of risk category distribution"""
    risk_dist = metrics['risk_distribution']
    
    # Filter out zero values
    labels = []
    sizes = []
    colors_list = []
    for cat in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if risk_dist.get(cat, 0) > 0:
            labels.append(cat)
            sizes.append(risk_dist[cat])
            colors_list.append(COLORS.get(cat.lower(), NYU_LIGHT))
    
    fig, ax = plt.subplots(figsize=(9, 7))
    
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct='%1.1f%%',
                                        colors=colors_list, startangle=90,
                                        textprops={'fontsize': 12, 'fontweight': 'bold'},
                                        wedgeprops={'edgecolor': 'white', 'linewidth': 2})
    
    # Make percentage text white
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontsize(11)
    
    ax.set_title('Risk Category Distribution', fontsize=16, fontweight='bold', pad=20)
    
    # Add count legend
    legend_labels = [f'{label}: {size} samples' for label, size in zip(labels, sizes)]
    ax.legend(legend_labels, loc='upper left', bbox_to_anchor=(1, 1), fontsize=10)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✅ Saved: {output_path}")
    plt.close()


def plot_validation_label_distribution(data: List[Dict], output_path: str):
    """Create stacked bar chart showing validation label distribution"""
    label_counts = {'true_positive': 0, 'false_positive': 0, 
                   'true_negative': 0, 'false_negative': 0}
    
    for doc in data:
        label = doc.get('validation', {}).get('label')
        if label in label_counts:
            label_counts[label] += 1
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Create grouped data
    categories = ['Actual\nPositives', 'Actual\nNegatives']
    tp_fn = [label_counts['true_positive'], label_counts['false_negative']]
    fp_tn = [label_counts['false_positive'], label_counts['true_negative']]
    
    x = np.arange(len(categories))
    width = 0.35
    
    # Create bars
    bars1 = ax.bar(x - width/2, [label_counts['true_positive'], label_counts['false_positive']], 
                   width, label='Detected (Predicted Positive)', 
                   color=NYU_PURPLE, edgecolor=NYU_DARK, linewidth=1.5)
    bars2 = ax.bar(x + width/2, [label_counts['false_negative'], label_counts['true_negative']], 
                   width, label='Missed (Predicted Negative)', 
                   color=NYU_VIOLET, edgecolor=NYU_DARK, linewidth=1.5)
    
    # Add value labels
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}',
                       ha='center', va='bottom', fontsize=11, fontweight='bold')
    
    ax.set_xlabel('Ground Truth', fontsize=13, fontweight='bold')
    ax.set_ylabel('Count', fontsize=13, fontweight='bold')
    ax.set_title('Validation Results by Ground Truth', fontsize=16, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=12)
    ax.legend(fontsize=11, loc='upper right')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✅ Saved: {output_path}")
    plt.close()


def plot_error_analysis_by_risk(data: List[Dict], output_path: str):
    """Create stacked bar chart showing errors by risk category"""
    # Group by risk category and validation label
    risk_errors = {
        'CRITICAL': {'fn': 0, 'fp': 0, 'correct': 0},
        'HIGH': {'fn': 0, 'fp': 0, 'correct': 0},
        'MEDIUM': {'fn': 0, 'fp': 0, 'correct': 0},
        'LOW': {'fn': 0, 'fp': 0, 'correct': 0}
    }
    
    for doc in data:
        risk_cat = doc.get('risk_category', 'UNKNOWN')
        label = doc.get('validation', {}).get('label')
        
        if risk_cat in risk_errors:
            if label == 'false_negative':
                risk_errors[risk_cat]['fn'] += 1
            elif label == 'false_positive':
                risk_errors[risk_cat]['fp'] += 1
            elif label in ['true_positive', 'true_negative']:
                risk_errors[risk_cat]['correct'] += 1
    
    # Prepare data
    categories = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    fn_counts = [risk_errors[cat]['fn'] for cat in categories]
    fp_counts = [risk_errors[cat]['fp'] for cat in categories]
    correct_counts = [risk_errors[cat]['correct'] for cat in categories]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = np.arange(len(categories))
    width = 0.6
    
    # Create stacked bars
    p1 = ax.bar(x, correct_counts, width, label='Correct', 
                color=NYU_PURPLE, edgecolor=NYU_DARK, linewidth=1.5)
    p2 = ax.bar(x, fp_counts, width, bottom=correct_counts, label='False Positives',
                color=NYU_ACCENT, edgecolor=NYU_DARK, linewidth=1.5)
    p3 = ax.bar(x, fn_counts, width, 
                bottom=[c+f for c, f in zip(correct_counts, fp_counts)],
                label='False Negatives', color=NYU_VIOLET, edgecolor=NYU_DARK, linewidth=1.5)
    
    # Add value labels for non-zero segments
    for i, cat in enumerate(categories):
        y_offset = 0
        for count, label_text in [(correct_counts[i], 'Correct'), 
                                   (fp_counts[i], 'FP'), 
                                   (fn_counts[i], 'FN')]:
            if count > 0:
                ax.text(i, y_offset + count/2, str(count),
                       ha='center', va='center', color='white',
                       fontsize=10, fontweight='bold')
            y_offset += count
    
    ax.set_xlabel('Risk Category', fontsize=13, fontweight='bold')
    ax.set_ylabel('Number of Samples', fontsize=13, fontweight='bold')
    ax.set_title('Error Analysis by Risk Category', fontsize=16, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=12)
    ax.legend(fontsize=11, loc='upper right')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✅ Saved: {output_path}")
    plt.close()


def plot_precision_recall_curve(metrics: Dict, output_path: str):
    """Create precision-recall visualization with current performance point"""
    m = metrics['metrics']
    
    fig, ax = plt.subplots(figsize=(9, 7))
    
    # Create curves for different thresholds (simulated)
    # In reality, we'd have different thresholds, but we'll show the current point
    # and reference zones
    
    # Fill zones
    ax.fill_between([0, 1], [0, 0], [0.5, 0.5], alpha=0.1, color='red', label='Poor Performance')
    ax.fill_between([0, 1], [0.5, 0.5], [0.7, 0.7], alpha=0.1, color='orange', label='Fair Performance')
    ax.fill_between([0, 1], [0.7, 0.7], [1, 1], alpha=0.1, color='green', label='Good Performance')
    
    # Plot current performance point
    ax.scatter([m['recall']], [m['precision']], s=300, c=NYU_PURPLE, 
              marker='*', edgecolors=NYU_DARK, linewidths=2, 
              label=f'Current System\n(P={m["precision"]:.1%}, R={m["recall"]:.1%})',
              zorder=5)
    
    # Add F1 iso-lines
    f1_scores = [0.4, 0.6, 0.8]
    for f1 in f1_scores:
        x = np.linspace(0.01, 1, 100)
        y = (f1 * x) / (2 * x - f1)
        y[y < 0] = 0
        y[y > 1] = 1
        ax.plot(x, y, '--', color='gray', alpha=0.5, linewidth=1)
        ax.text(0.9, (f1 * 0.9) / (2 * 0.9 - f1) + 0.02, f'F1={f1:.1f}', 
               fontsize=9, color='gray')
    
    ax.set_xlabel('Recall (Sensitivity)', fontsize=13, fontweight='bold')
    ax.set_ylabel('Precision', fontsize=13, fontweight='bold')
    ax.set_title('Precision-Recall Performance', fontsize=16, fontweight='bold', pad=20)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.grid(True, alpha=0.3, linestyle='--')
    ax.legend(loc='lower left', fontsize=9)
    ax.set_axisbelow(True)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✅ Saved: {output_path}")
    plt.close()


def plot_metrics_comparison(metrics: Dict, output_path: str):
    """Create radar chart comparing different metrics"""
    m = metrics['metrics']
    
    categories = ['Precision', 'Recall', 'F1 Score', 'Accuracy', 'Specificity']
    values = [m['precision'], m['recall'], m['f1'], m['accuracy'], m['specificity']]
    
    # Number of variables
    N = len(categories)
    
    # Compute angle for each axis
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    values += values[:1]  # Complete the circle
    angles += angles[:1]
    
    fig, ax = plt.subplots(figsize=(9, 9), subplot_kw=dict(projection='polar'))
    
    # Plot data
    ax.plot(angles, values, 'o-', linewidth=3, color=NYU_PURPLE, label='Current Performance')
    ax.fill(angles, values, alpha=0.25, color=NYU_PURPLE)
    
    # Target line at 0.8
    target = [0.8] * (N + 1)
    ax.plot(angles, target, '--', linewidth=2, color=NYU_ACCENT, label='Target (80%)', alpha=0.7)
    
    # Fix axis to go from 0 to 1
    ax.set_ylim(0, 1)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=12, fontweight='bold')
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(['20%', '40%', '60%', '80%', '100%'], fontsize=10)
    ax.grid(True, linestyle='--', alpha=0.5)
    
    ax.set_title('Performance Metrics Radar', fontsize=16, fontweight='bold', 
                pad=30, y=1.08)
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1), fontsize=11)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✅ Saved: {output_path}")
    plt.close()


def generate_summary_stats(metrics: Dict, output_path: str):
    """Create summary statistics figure with key numbers"""
    cm = metrics['confusion_matrix']
    m = metrics['metrics']
    
    fig, ax = plt.subplots(figsize=(12, 8))
    ax.axis('off')
    
    # Title
    fig.text(0.5, 0.95, 'Validation Metrics Summary', 
            ha='center', fontsize=20, fontweight='bold')
    
    # Confusion Matrix Summary
    fig.text(0.25, 0.85, 'Confusion Matrix', ha='center', 
            fontsize=16, fontweight='bold', color=NYU_PURPLE)
    
    stats_text = f"""
    True Positives:     {cm['tp']}
    False Positives:    {cm['fp']}
    True Negatives:     {cm['tn']}
    False Negatives:    {cm['fn']}
    
    Total Samples:      {metrics['total_samples']}
    """
    fig.text(0.25, 0.65, stats_text, ha='center', fontsize=13,
            family='monospace', verticalalignment='top')
    
    # Performance Metrics
    fig.text(0.75, 0.85, 'Performance Metrics', ha='center', 
            fontsize=16, fontweight='bold', color=NYU_PURPLE)
    
    metrics_text = f"""
    Precision:     {m['precision']:.1%}
    Recall:        {m['recall']:.1%}
    F1 Score:      {m['f1']:.1%}
    Accuracy:      {m['accuracy']:.1%}
    Specificity:   {m['specificity']:.1%}
    """
    fig.text(0.75, 0.65, metrics_text, ha='center', fontsize=13,
            family='monospace', verticalalignment='top')
    
    # Risk Distribution
    fig.text(0.5, 0.40, 'Risk Category Distribution', ha='center', 
            fontsize=16, fontweight='bold', color=NYU_PURPLE)
    
    risk_text = ""
    for cat, count in metrics['risk_distribution'].items():
        if count > 0:
            pct = count / metrics['total_samples'] * 100
            risk_text += f"{cat:10s}: {count:3d} ({pct:5.1f}%)\n    "
    
    fig.text(0.5, 0.25, risk_text, ha='center', fontsize=12,
            family='monospace', verticalalignment='top')
    
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✅ Saved: {output_path}")
    plt.close()


def main():
    """Generate all visualizations"""
    print("=" * 60)
    print("STREAMJACKING DETECTOR - VALIDATION METRICS VISUALIZATION")
    print("=" * 60)
    print()
    
    # Load data
    data = load_validation_data_from_mongodb()
    if not data:
        print("❌ No validation data found. Exiting.")
        return
    
    # Calculate metrics
    print(f"\n📊 Calculating metrics from {len(data)} validated samples...")
    metrics = calculate_metrics(data)
    
    # Create output directory
    output_dir = '../data/analysis/visualizations'
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\n🎨 Generating visualizations in NYU purple colors...")
    print()
    
    # Generate all plots
    plot_diagnostic_grid(metrics, f'{output_dir}/00_diagnostic_grid.png')
    plot_confusion_matrix(metrics, f'{output_dir}/01_confusion_matrix.png')
    plot_performance_metrics(metrics, f'{output_dir}/02_performance_metrics.png')
    plot_risk_distribution(metrics, f'{output_dir}/03_risk_distribution.png')
    plot_validation_label_distribution(data, f'{output_dir}/04_validation_labels.png')
    plot_error_analysis_by_risk(data, f'{output_dir}/05_error_by_risk.png')
    plot_precision_recall_curve(metrics, f'{output_dir}/06_precision_recall.png')
    plot_metrics_comparison(metrics, f'{output_dir}/07_metrics_radar.png')
    generate_summary_stats(metrics, f'{output_dir}/08_summary_stats.png')
    
    print()
    print("=" * 60)
    print("✅ All visualizations generated successfully!")
    print(f"📁 Output directory: {output_dir}")
    print("=" * 60)
    print()
    
    # Print metrics summary
    cm = metrics['confusion_matrix']
    m = metrics['metrics']
    print("📈 Metrics Summary:")
    print(f"   Precision:    {m['precision']:.1%}")
    print(f"   Recall:       {m['recall']:.1%}")
    print(f"   F1 Score:     {m['f1']:.1%}")
    print(f"   Accuracy:     {m['accuracy']:.1%}")
    print(f"   Specificity:  {m['specificity']:.1%}")
    print()
    print(f"📊 Confusion Matrix:")
    print(f"   TP: {cm['tp']:2d}  FP: {cm['fp']:2d}")
    print(f"   FN: {cm['fn']:2d}  TN: {cm['tn']:2d}")
    print()


if __name__ == '__main__':
    main()
