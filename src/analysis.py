"""
Analysis and visualization of stream-jacking detection results
"""

import json
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List
import statistics


class DetectionAnalyzer:
    """Analyze detection results and generate metrics"""
    
    def __init__(self, results_file: str):
        """Load detection results"""
        with open(results_file, 'r') as f:
            data = json.load(f)
            # Handle both formats: {"results": [...]} or [...]
            if isinstance(data, dict) and 'results' in data:
                self.results = data['results']
            elif isinstance(data, list):
                self.results = data
            else:
                raise ValueError("Invalid JSON format. Expected either a list or {'results': [...]}")
    
    def calculate_metrics(self) -> Dict:
        """Calculate key detection metrics"""
        if not self.results:
            return {}
        
        # Risk score statistics
        risk_scores = [r['total_risk_score'] for r in self.results]
        video_scores = [r['video_risk_score'] for r in self.results]
        channel_scores = [r['channel_risk_score'] for r in self.results]
        
        # Risk categories
        high_risk = sum(1 for s in risk_scores if s >= 70)
        medium_risk = sum(1 for s in risk_scores if 40 <= s < 70)
        low_risk = sum(1 for s in risk_scores if s < 40)
        
        # Live vs recorded
        live_count = sum(1 for r in self.results if r.get('is_live', False))
        
        # Unique channels
        unique_channels = len(set(r['channel_id'] for r in self.results))
        
        metrics = {
            'total_detections': len(self.results),
            'unique_channels': unique_channels,
            'live_streams': live_count,
            'recorded_videos': len(self.results) - live_count,
            'risk_distribution': {
                'high': high_risk,
                'medium': medium_risk,
                'low': low_risk
            },
            'risk_score_stats': {
                'mean': statistics.mean(risk_scores),
                'median': statistics.median(risk_scores),
                'stdev': statistics.stdev(risk_scores) if len(risk_scores) > 1 else 0,
                'min': min(risk_scores),
                'max': max(risk_scores)
            },
            'video_score_stats': {
                'mean': statistics.mean(video_scores),
                'median': statistics.median(video_scores)
            },
            'channel_score_stats': {
                'mean': statistics.mean(channel_scores),
                'median': statistics.median(channel_scores)
            }
        }
        
        return metrics
    
    def analyze_signals(self) -> Dict:
        """Analyze detection signals"""
        video_signals = []
        channel_signals = []
        
        for result in self.results:
            video_signals.extend(result.get('video_signals', []))
            channel_signals.extend(result.get('channel_signals', []))
        
        # Count signal types
        video_signal_counts = Counter(video_signals)
        channel_signal_counts = Counter(channel_signals)
        
        # Categorize signals
        signal_categories = defaultdict(int)
        
        for signal in video_signals:
            if 'impersonation' in signal.lower():
                signal_categories['impersonation'] += 1
            elif 'scam keyword' in signal.lower():
                signal_categories['scam_keywords'] += 1
            elif 'address' in signal.lower() or 'url' in signal.lower():
                signal_categories['malicious_links'] += 1
            elif 'comment' in signal.lower():
                signal_categories['restricted_comments'] += 1
            elif 'live' in signal.lower():
                signal_categories['live_streaming'] += 1
        
        for signal in channel_signals:
            if 'impersonation' in signal.lower():
                signal_categories['impersonation'] += 1
            elif 'hijack' in signal.lower():
                signal_categories['account_hijacking'] += 1
            elif 'subscriber' in signal.lower():
                signal_categories['suspicious_metrics'] += 1
            elif 'crypto' in signal.lower():
                signal_categories['crypto_indicators'] += 1
        
        return {
            'video_signals': dict(video_signal_counts.most_common(10)),
            'channel_signals': dict(channel_signal_counts.most_common(10)),
            'signal_categories': dict(signal_categories),
            'total_video_signals': len(video_signals),
            'total_channel_signals': len(channel_signals)
        }
    
    def identify_patterns(self) -> Dict:
        """Identify common attack patterns"""
        patterns = {
            'by_query': defaultdict(list),
            'high_risk': [],
            'medium_risk': [],
            'low_risk': [],
            'impersonation_targets': defaultdict(list)
        }
        
        for result in self.results:
            # Group by search query
            query = result.get('search_query', 'unknown')
            patterns['by_query'][query].append(result)
            
            # Group by risk level
            risk = result['total_risk_score']
            if risk >= 70:
                patterns['high_risk'].append(result)
            elif risk >= 40:
                patterns['medium_risk'].append(result)
            else:
                patterns['low_risk'].append(result)
            
            # Group by impersonation target
            for signal in result.get('video_signals', []) + result.get('channel_signals', []):
                if 'impersonation' in signal.lower():
                    target = signal.split(':')[-1].strip() if ':' in signal else 'unknown'
                    patterns['impersonation_targets'][target].append(result)
        
        # Convert defaultdicts to regular dicts with counts
        return {
            'by_query': {q: len(v) for q, v in patterns.get('by_query', {}).items()},
            'by_risk_level': {
                'high': len(patterns.get('high_risk', [])),
                'medium': len(patterns.get('medium_risk', [])),
                'low': len(patterns.get('low_risk', []))
            },
            'impersonation_targets': {
                t: len(v) for t, v in patterns.get('impersonation_targets', {}).items()
            }
        }
    
    def generate_report(self, output_file: str = None):
        """Generate comprehensive analysis report"""
        metrics = self.calculate_metrics()
        signals = self.analyze_signals()
        patterns = self.identify_patterns()
        
        report = {
            'analysis_date': datetime.now().isoformat(),
            'dataset_size': len(self.results),
            'metrics': metrics,
            'signal_analysis': signals,
            'patterns': patterns
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Analysis report saved to {output_file}")
        
        return report
    
    def print_report(self):
        """Print formatted analysis report"""
        metrics = self.calculate_metrics()
        signals = self.analyze_signals()
        patterns = self.identify_patterns()
        
        print("\n" + "="*80)
        print("STREAM-JACKING DETECTION ANALYSIS REPORT")
        print("="*80)
        
        # Dataset overview
        print(f"\n📊 DATASET OVERVIEW")
        print(f"{'─'*80}")
        print(f"Total Detections:     {metrics['total_detections']}")
        print(f"Unique Channels:      {metrics['unique_channels']}")
        print(f"Live Streams:         {metrics['live_streams']}")
        print(f"Recorded Videos:      {metrics['recorded_videos']}")
        
        # Risk distribution
        print(f"\n⚠️  RISK DISTRIBUTION")
        print(f"{'─'*80}")
        risk_dist = metrics['risk_distribution']
        print(f"🔴 High Risk (≥70):   {risk_dist['high']:3d} ({risk_dist['high']/metrics['total_detections']*100:.1f}%)")
        print(f"🟡 Medium Risk (40-69): {risk_dist['medium']:3d} ({risk_dist['medium']/metrics['total_detections']*100:.1f}%)")
        print(f"🟢 Low Risk (30-39):  {risk_dist['low']:3d} ({risk_dist['low']/metrics['total_detections']*100:.1f}%)")
        
        # Risk statistics
        print(f"\n📈 RISK SCORE STATISTICS")
        print(f"{'─'*80}")
        stats = metrics['risk_score_stats']
        print(f"Mean Risk Score:      {stats['mean']:.2f}")
        print(f"Median Risk Score:    {stats['median']:.2f}")
        print(f"Std Deviation:        {stats['stdev']:.2f}")
        print(f"Range:                {stats['min']:.1f} - {stats['max']:.1f}")
        
        # Signal analysis
        print(f"\n🔍 TOP DETECTION SIGNALS")
        print(f"{'─'*80}")
        print("\nVideo Signals:")
        for signal, count in list(signals['video_signals'].items())[:5]:
            print(f"  • {signal}: {count}")
        
        print("\nChannel Signals:")
        for signal, count in list(signals['channel_signals'].items())[:5]:
            print(f"  • {signal}: {count}")
        
        print(f"\nSignal Categories:")
        for category, count in signals['signal_categories'].items():
            print(f"  • {category.replace('_', ' ').title()}: {count}")
        
        # Pattern analysis
        print(f"\n🎯 ATTACK PATTERNS")
        print(f"{'─'*80}")
        
        if patterns['impersonation_targets']:
            print("\nMost Impersonated Targets:")
            sorted_targets = sorted(
                patterns['impersonation_targets'].items(),
                key=lambda x: x[1],
                reverse=True
            )
            for target, count in sorted_targets[:5]:
                print(f"  • {target}: {count}")
        
        print("\nDetections by Search Query:")
        sorted_queries = sorted(
            patterns['by_query'].items(),
            key=lambda x: x[1],
            reverse=True
        )
        for query, count in sorted_queries[:5]:
            print(f"  • {query}: {count}")
        
        print("\n" + "="*80)
    
    def export_high_risk_channels(self, output_file: str):
        """Export list of high-risk channels for manual review"""
        high_risk = [
            {
                'channel_id': r['channel_id'],
                'channel_title': r['channel_title'],
                'video_id': r['video_id'],
                'video_title': r['video_title'],
                'risk_score': r['total_risk_score'],
                'signals': r['video_signals'] + r['channel_signals'],
                'youtube_url': f"https://youtube.com/watch?v={r['video_id']}",
                'channel_url': f"https://youtube.com/channel/{r['channel_id']}"
            }
            for r in self.results
            if r['total_risk_score'] >= 70
        ]
        
        # Sort by risk score
        high_risk.sort(key=lambda x: x['risk_score'], reverse=True)
        
        with open(output_file, 'w') as f:
            json.dump(high_risk, f, indent=2)
        
        print(f"\nExported {len(high_risk)} high-risk channels to {output_file}")
        
        return high_risk


def main():
    """Main analysis function"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python analysis.py <results_file.json>")
        return
    
    results_file = sys.argv[1]
    
    print(f"Loading results from {results_file}...")
    analyzer = DetectionAnalyzer(results_file)
    
    # Print formatted report
    analyzer.print_report()
    
    # Generate JSON report
    analyzer.generate_report('/data/outputs/analysis_report.json')
    
    # Export high-risk channels
    analyzer.export_high_risk_channels('/data/outputs/high_risk_channels.json')
    
    print("\n✅ Analysis complete!")


if __name__ == "__main__":
    main()
