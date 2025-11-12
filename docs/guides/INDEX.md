# Project Documentation Index
## Stream-Jacking Detection System

**Last Updated:** November 11, 2025  
**Team:** Aninda Ghosh & Dhari Alshammari  
**Course:** Trust and Safety (CS-UY 3943)

---

## Overview

This document provides an overview of the project files and their purposes. The system is designed to detect stream-jacking attacks on YouTube by analyzing channel and video metadata through the YouTube Data API v3.

---

## Core System Files

### src/youtube_streamjacking_detector_enhanced.py
Main detection system with 16 detection signals. Includes YouTube API integration, risk scoring algorithm, and automated monitoring. Run with:
```bash
export YOUTUBE_API_KEY='your-key'
python src/youtube_streamjacking_detector_enhanced.py
```

### src/analysis.py
Analysis framework for calculating metrics from detection results. Fixed JSON parsing issue on Nov 11. Run with:
```bash
python src/analysis.py src/data/results/streamjacking_detection_results.json
```

### src/test_data_generator.py
Creates synthetic test data for validation. Useful for testing detection logic before using real API quota.

### requirements.txt
Python dependencies. Install with:
```bash
pip install -r requirements.txt
```

---

## Data Files

### src/data/results/streamjacking_detection_results.json
Full detection results from November 8 data collection run. Contains 500+ analyzed videos from 150+ channels.

### src/data/results/high_risk_channels.json
Filtered results showing only high-risk detections (score ≥70). These need manual review.

---

## Running the System

### Analyzing Existing Data
We already have collected data from November 8. To analyze it:
```bash
python src/analysis.py src/data/results/streamjacking_detection_results.json
```

This will output statistics, signal frequencies, and pattern analysis.

### Collecting New Data
Requires YouTube API key from Google Cloud Console:
```bash
export YOUTUBE_API_KEY='your-key-here'
python src/youtube_streamjacking_detector_enhanced.py
```

Note: API quota is 10,000 units/day. Each query uses ~100 units, each channel/video analysis uses ~5 units.

---

## Current Status

### Completed Work
- Detection system with 16 signals (expanded from 11)
- YouTube API integration with quota tracking
- Analysis framework for metrics calculation
- Data collection run (Nov 8): 500+ videos, 150+ channels
- Bug fix (Nov 11): JSON parsing in analysis module

### Dataset Overview
From the November 8 collection:
- 500+ total detections
- 150+ unique channels
- 20+ search queries
- Mix of high/medium/low risk channels

### Known Issues
- Some false positives on legitimate channels (LabPadre, Bloomberg)
- Need manual validation to calculate precision/recall
- Analysis on collected data still pending

---

## Next Steps

### Immediate (Week of Nov 11)
1. Run full analysis on collected data
2. Manual review of 50-100 high-risk channels
3. Calculate precision/recall metrics
4. Document attack patterns observed

### Week of Nov 18
1. Continue manual validation
2. Refine detection thresholds based on false positives
3. Collect additional data if needed
4. Start drafting final report

### Remaining Timeline
- Week 5 (Dec 1-7): Metrics calculation and validation
- Week 6 (Dec 8-14): Final report writing
- Week 7 (Dec 15-18): Presentation preparation and submission

---

## Technical Notes

### Detection Signals
The system uses 16 signals across channel and video metadata:
- Character substitution impersonation
- Scam keywords ("giveaway", "double", "send")
- Crypto addresses in descriptions
- Engagement anomalies (high views, disabled comments)
- Handle-name mismatches
- Account age vs. activity patterns
- Urgency language
- Known scam domains

See README.md for full list with weights.

### API Quota Usage
- YouTube Data API v3: 10,000 units/day default
- Search query: 100 units
- Channel/video metadata: 5 units each
- Our Nov 8 collection used ~5,000 units for 500+ videos

Can request quota increase from Google if needed for larger datasets.

### Known Limitations
- Some legitimate channels get flagged (e.g., legitimate SpaceX fan streams with crypto links)
- No image analysis (QR codes in thumbnails not detected)
- Point-in-time data only (no historical tracking)
- Limited by API quota for large-scale analysis

---

## Contact

Aninda Ghosh: ag10293@nyu.edu  
Dhari Alshammari: da3974@nyu.edu

---

Last updated: November 11, 2025
