# Quick Reference
## Stream-Jacking Detection System

## Running Analysis

We have collected data from YouTube. To analyze it:

```bash
python src/analysis.py src/data/results/streamjacking_detection_results.json
```

Output shows statistics, common signals, and pattern analysis.

## Collecting New Data

Need YouTube API key from Google Cloud Console (enable YouTube Data API v3):

```bash
export YOUTUBE_API_KEY='your-api-key'
python src/youtube_streamjacking_detector_enhanced.py
```

Keep in mind the 10,000 units/day quota limit.

## Current Status

Detection system: 16 signals implemented (enhanced version)
Dataset: 500+ videos from 150+ channels (collected Nov 8)
Analysis: Pending - need to run full analysis on collected data

Common patterns observed so far:
- Celebrity impersonation (Elon Musk, Tesla, SpaceX)
- Live trading signal scams
- Crypto giveaway streams
- Some false positives on legitimate finance channels

## Detection Signals

The enhanced detector checks 16 signals:

Channel-level:
- Character substitution (l→I, O→0)
- Account age vs activity
- Subscriber/content mismatch
- Handle-name mismatch
- Hidden subscriber count
- Crypto-heavy description

Video-level:
- Title impersonation
- Scam keywords
- Crypto addresses
- Urgency language
- High-confidence scam phrases
- Disabled comments
- Live stream status
- Engagement anomalies
- Suspicious domains

Risk scores: 0-100 scale
- High risk: ≥70
- Medium risk: 40-69
- Low risk: <40

---

Last updated: November 11, 2025
