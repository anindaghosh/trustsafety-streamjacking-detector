# YouTube Streamjacking Detection System - Project Context Guide
**For LLM Context Understanding**

**Last Updated:** December 9, 2025  
**Project Deadline:** December 18, 2025  
**Team:** Aninda Ghosh (ag10293) & Dhari Alshammari (da3974)  
**Course:** Trust and Safety (CS-UY 3943), NYU

---

## Executive Summary

This is a **YouTube livestream scam detection system** that identifies crypto-related streamjacking attacks using signal-based risk scoring. The system analyzes channel and video metadata via YouTube Data API v3 to detect hijacked accounts broadcasting fake crypto giveaway scams.

**Current Status (Dec 9, 2025):**
- Enhanced detector with 11 signals implemented
- MongoDB integration for validation tracking
- 52 manually validated samples in database
- **Current Performance:** 4 TP, 2 FP, 13 TN, 2 FN (based on validated HIGH-risk detections)
- **Known Issue:** Educational intent penalty causing false negatives on celebrity impersonation scams
- **Recent Additions:** QR code detection, scam domain patterns, suspicious tag combinations, live chat analysis

---

## System Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                    YouTube Data API v3                      │
│              (10,000 units/day quota limit)                 │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│         youtube_streamjacking_detector_enhanced.py          │
│                                                             │
│  ┌─────────────────┐    ┌──────────────────┐              │
│  │ API Client      │───▶│ Detection Engine │              │
│  │ - Search        │    │ - 11 Signals     │              │
│  │ - Metadata      │    │ - Risk Scoring   │              │
│  │ - Chat Messages │    │ - Classification │              │
│  └─────────────────┘    └──────────────────┘              │
│                                │                            │
│                                ▼                            │
│                    ┌──────────────────────┐                │
│                    │  Risk Categorization │                │
│                    │  - CRITICAL: 95%     │                │
│                    │  - HIGH: ≥70 points  │                │
│                    │  - MEDIUM: 40-69     │                │
│                    │  - LOW: <40          │                │
│                    └──────────────────────┘                │
└────────────────────────────┬───────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    MongoDB Storage                          │
│          Database: streamjacking                            │
│          Collection: detection_results_v2                   │
│                                                             │
│  Document Schema:                                           │
│  {                                                          │
│    video_id, channel_id, risk_score, risk_category,        │
│    signals: [...],                                          │
│    validation: {                                            │
│      label: "true_positive" | "false_positive" |           │
│              "true_negative" | "false_negative",            │
│      reasoning: [...],                                      │
│      reviewed_at, reviewer                                  │
│    }                                                        │
│  }                                                          │
└────────────────────────────┬───────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│              calculate_metrics.py                           │
│                                                             │
│  Calculates from validation.label field:                   │
│  - Confusion Matrix (TP/FP/TN/FN)                          │
│  - Precision, Recall, F1 Score, Accuracy                   │
│  - Risk category distribution of errors                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Detection Methodology

### Signal-Based Risk Scoring

The detector uses **additive risk scoring** where each suspicious signal contributes points. Videos are classified based on total risk score:

```
Total Risk Score = Σ (triggered signal weights) - educational penalty
```

**Thresholds:**
- **HIGH risk (scam):** ≥70 points
- **MEDIUM risk:** 40-69 points  
- **LOW risk:** <40 points

### 11 Detection Signals

#### **Video-Level Signals** (analyzed in `analyze_video_enhanced()`)

| Signal | Weight | Description | Code Line |
|--------|--------|-------------|-----------|
| **1. Title Impersonation** | +25 | Character substitution in video title (e.g., "Tesla" → "Tеsla") | ~824 |
| **2. Multiple Scam Keywords** | +15 | 2+ scam words: "giveaway", "double", "send", "free" | ~837 |
| **3. Urgency Language** | +10 | "act now", "limited time", "hurry", "ending soon" | ~844 |
| **4. Crypto Address** | +25 | BTC/ETH addresses in description | ~850 |
| **5. High-Confidence Scam Phrase** | +35 | Explicit scam patterns: "send X get 2X back" | ~856 |
| **5b. QR Code Mention** | +30 | "QR code", "scan code" in title/description | ~774 |
| **6. Chat Disabled** | +30/+20 | Live chat disabled (+30 if crypto content, +20 otherwise) | ~780 |
| **7. Low Engagement** | +15 | High views but very low likes/comments ratio | ~863 |
| **8. Topic Mismatch** | +50 | Channel topic unrelated to video content (hijacked channel) | ~680 |
| **9. Scam Domain Patterns** | +40/+15 | Pattern-based: gift-trump.com, bitcoin-mena.today (+40); URL shorteners (+15) | ~893 |
| **10. Suspicious Tag Combinations** | +35 | Political figure/celebrity + crypto keywords (Trump + bitcoin) | ~910 |
| **11. Live Chat Scam Content** | +45/+35 | Scam links in chat messages (+45 if pinned Super Chat, +35 otherwise) | ~918 |

#### **Channel-Level Signals** (analyzed in `analyze_channel_enhanced()`)

| Signal | Weight | Description |
|--------|--------|-------------|
| **1. Name Impersonation** | +30 | Character substitution in channel name |
| **2. Handle-Name Mismatch** | +25 | Channel name has crypto brand, handle doesn't |
| **3. Account Age vs Activity** | +20 | Old account with sudden recent activity spike |
| **4. Hidden Subscribers** | +15 | Subscriber count hidden (common for hacked accounts) |
| **5. Scam Domains** | +25 | Scam links in channel description |

#### **Special Modifiers**

- **Educational Intent Penalty:** -30 points if content appears educational/news-like
- **Trusted Channel Whitelist:** Forces risk_score = 0 for known legitimate channels

---

## Data Flow & Validation

### 1. Data Collection
```bash
cd src
export YOUTUBE_API_KEY='your-key'
python youtube_streamjacking_detector_enhanced.py
```

**Process:**
1. Searches 70 crypto-related queries ("bitcoin live", "ethereum giveaway", etc.)
2. For each video found:
   - Fetches video metadata (5 quota units)
   - Fetches channel metadata (5 quota units)
   - Samples live chat messages if active (5 quota units)
   - Analyzes with 11 signals
   - Calculates risk score and category
3. **Upserts** to MongoDB (updates existing, inserts new)

**Quota Usage:** ~7,000-7,500 units per full run (70 queries × ~100 units/query)

### 2. Manual Validation

**Approach:** Human review of detected videos to label ground truth

**Validation Labels** (stored in `validation.label` field):
- `true_positive`: Scam correctly flagged as HIGH risk
- `false_positive`: Legitimate video incorrectly flagged as HIGH risk
- `true_negative`: Legitimate video correctly scored LOW/MEDIUM risk
- `false_negative`: Scam incorrectly scored LOW/MEDIUM risk (missed)

**Tools:**
- Interactive validator UI (validates and syncs to MongoDB in real-time)
- `correct_validations.py` for bulk label corrections
- `backup_mongodb.py` for collection exports

### 3. Metrics Calculation
```bash
python calculate_metrics.py  # Reads from MongoDB by default
```

**Calculates:**
- **Confusion Matrix:** TP, FP, TN, FN counts
- **Precision:** TP / (TP + FP)
- **Recall:** TP / (TP + FN)
- **F1 Score:** 2 × (Precision × Recall) / (Precision + Recall)
- **Accuracy:** (TP + TN) / Total

**Current Metrics (52 validated samples, Dec 9):**
- **HIGH-risk only:** 4 TP, 2 FP, 13 TN, 2 FN
- **Precision:** 66.7% (4/6 HIGH-risk detections are real scams)
- **Recall:** 66.7% (4/6 actual scams caught)
- **F1 Score:** 0.67

---

## Technical Stack

### Core Technologies
- **Python 3.12**
- **YouTube Data API v3** - Video/channel metadata retrieval
- **MongoDB 7.0** - Validation tracking and results storage
- **pymongo 4.6.1** - MongoDB Python driver
- **google-api-python-client** - YouTube API client
- **python-dotenv** - Environment variable management

### Key Files & Locations

```
streamjacking-detector/
├── src/
│   ├── youtube_streamjacking_detector_enhanced.py  # Main detector (~1,448 lines)
│   ├── calculate_metrics.py                        # Metrics calculator (~643 lines)
│   ├── analyze_sample_channels.py                  # Sample analysis tool
│   ├── validation_helper.py                        # Interactive validator
│   ├── correct_validations.py                      # Bulk label updater
│   ├── backup_mongodb.py                           # MongoDB export utility
│   └── data/
│       └── results/
│           ├── streamjacking_detection_results.json  # Latest results
│           └── high_risk_channels.json               # Filtered HIGH risk
├── data/
│   ├── analysis/
│   │   ├── mongodb_validation_metrics.json          # Latest metrics
│   │   ├── validation_sample.csv                    # Manual validation dataset
│   │   └── high_risk_channels.json                  # Analysis results
│   └── results/
│       └── streamjacking_detection_results.json     # Full detection results
├── docs/
│   └── guides/
│       ├── INDEX.md                                 # Project overview
│       ├── QUICK_START.md                           # Setup instructions
│       ├── VALIDATION_GUIDE.md                      # Validation methodology
│       └── PROJECT_CONTEXT.md                       # This file
├── requirements.txt                                 # Python dependencies
└── README.md                                        # Main documentation
```

### MongoDB Schema

**Database:** `streamjacking`  
**Collection:** `detection_results_v2`

**Document Structure:**
```javascript
{
  "_id": ObjectId("..."),
  "video_id": "abc123",
  "channel_id": "UC...",
  "channel_title": "Example Channel",
  "video_title": "LIVE Bitcoin Giveaway",
  "risk_score": 75.0,
  "risk_category": "HIGH",  // CRITICAL | HIGH | MEDIUM | LOW
  "confidence_score": 0.80,
  "signals": [
    "Multiple scam keywords: giveaway, free",
    "Chat disabled",
    "QR code mentioned (common scam tactic)"
  ],
  "channel_signals": [
    "Topic Mismatch (Possible Hijack)"
  ],
  "video_url": "https://youtube.com/watch?v=abc123",
  "channel_url": "https://youtube.com/channel/UC...",
  "detected_at": "2025-12-09T13:45:00Z",
  
  // Validation data (added manually)
  "validation": {
    "label": "true_positive",  // TP | FP | TN | FN
    "reasoning": [
      "Hacked channel/Unrelated content",
      "Pre-recorded video footage",
      "QR Code in video"
    ],
    "scam_type": "impersonation",
    "reviewed_at": "2025-12-09T14:00:00Z",
    "reviewer": "ag10293"
  }
}
```

**Indexes:**
- `video_id` (unique)
- `risk_category`
- `validation.label`

---

## Current Challenges & Known Issues

### 1. Educational Intent Penalty Problem ⚠️

**Issue:** Detector applies -30 point penalty to videos with "prediction", "analysis" keywords, causing false negatives

**Example:** 
- Video: "Michael Saylor: BITCOIN BULL RUN READY TO BE CONFIRMED! BTC PRICE PREDICTION"
- Channel: "Serapodcast" (hijacked music podcast)
- Signals triggered: +70 points (celebrity tags +35, scam keywords +15, low engagement +15, live +5)
- Educational penalty: -30 points
- **Final score: 40 (MEDIUM)** - Should be HIGH (≥70)

**Root Cause:**
```python
# Line ~841-845 in detector
educational_score = sum(1 for kw in EDUCATIONAL_KEYWORDS if kw in combined)
scam_score = sum(1 for kw in SCAM_KEYWORDS if kw in combined)
is_educational = educational_score > scam_score or is_crypto_native
```

The logic is too permissive - "PREDICTION" counts as educational even when used in scam context.

**Impact:** 2 false negatives out of 6 actual scams (reduces recall from 100% to 66.7%)

**Proposed Fix:**
```python
# More restrictive educational classification
is_educational = (
    educational_score > scam_score + 2 and  # Clear educational dominance
    is_crypto_native and                    # Must be crypto-native channel
    not any(celebrity in combined for celebrity in CRYPTO_CELEBRITIES) and
    not video.comments_disabled
)
```

### 2. Channel Analysis Gaps

**Issue:** Some videos don't have channel-level signals, missing potential +40-60 points

**Example:** False negatives showed `"channel_signals": []` - no channel analysis performed

**Causes:**
- API quota concerns (channel metadata costs 5 units)
- Error handling skipping channel fetch
- Rate limiting

**Impact:** Missing critical "Topic Mismatch" signal (+50 points) that detects hijacked channels

### 3. Chat Analysis Limitations

**Issue:** Live chat sampling only works for currently active streams

**Limitations:**
- Cannot analyze chat for ended streams (chat data expires)
- Requires additional API quota (5 units per chat sample)
- Scam links often only appear in chat, not description

**Current Implementation:** Signal 11 samples 20 recent messages, checks for:
- Scam domain links
- Pinned Super Chats with scam content
- Bot spam patterns (same message 3+ times)

### 4. False Positive Sources

**Known false positives:**
- Legitimate crypto news channels with urgency language ("BREAKING NEWS")
- Crypto-native channels with giveaways (some legitimate)
- News broadcasts mentioning political figures + crypto

**Example:** CNBC-TV18 business news stream flagged as HIGH risk (false positive)

---

## Validation Methodology

### Dataset Composition

**Total Validated:** 52 samples (as of Dec 9, 2025)

**Distribution:**
- 6 actual scams (ground truth positives)
- 46 legitimate videos (ground truth negatives)

**Selection Criteria:**
1. All HIGH-risk detections (≥70 points) reviewed
2. Random sample of MEDIUM-risk (40-69 points) for false negative analysis
3. Known legitimate channels for false positive testing

### Validation Process

1. **Video Review:** Watch first 1-2 minutes of stream
2. **Channel Inspection:** Check channel history, subscriber count, content type
3. **Scam Indicators:** Look for:
   - QR codes in video
   - Crypto addresses displayed
   - Bot spam in chat
   - Hijacked channel signs (unrelated previous content)
   - Fake celebrity impersonation
4. **Label Assignment:** Choose TP/FP/TN/FN based on:
   - Is it actually a scam? (ground truth)
   - Did detector flag it as HIGH risk? (prediction)
5. **MongoDB Update:** Store label in `validation.label` field

### Confusion Matrix Interpretation

```
                    Predicted
                 HIGH  |  LOW/MED
              --------|----------
Actual  SCAM   |  TP   |   FN
        LEGIT  |  FP   |   TN
```

**Labels map directly to confusion matrix:**
- `true_positive`: Scam + detected HIGH
- `false_positive`: Legitimate + detected HIGH
- `true_negative`: Legitimate + detected LOW/MEDIUM
- `false_negative`: Scam + detected LOW/MEDIUM

---

## Recent Enhancements (Dec 2025)

### 1. QR Code Detection (Signal 5b, +30 points)
**Added:** Dec 9, 2025  
**Rationale:** 79% of false negatives (19/24 missed scams) mentioned QR codes  
**Keywords:** "qr code", "qr-code", "scan code", "scan qr", "scan the code", "use qr", "qrcode", "barcode", "scan to", "code to scan"

### 2. Scam Domain Pattern Detection (Signal 9, enhanced)
**Added:** Dec 9, 2025  
**Rationale:** Scammers use pattern-based domains like gift-trump.com, bitcoin-mena.today  
**Patterns:**
```python
# Detects: [keyword]-[anything].com or [crypto]-[keyword].[suspicious-tld]
# Examples: gift-trump.com, bitcoin-mena.today, crypto-bonus.live
```
**Weight:** +40 for pattern domains, +15 for URL shorteners

### 3. Suspicious Tag Combinations (Signal 10, +35 points)
**Added:** Dec 9, 2025  
**Rationale:** Hijacked channels show political figure/celebrity + crypto tag combinations  
**Detection:** Checks for tags/description containing:
- Political figures (Trump, Biden, etc.) + crypto keywords
- Crypto celebrities (Elon Musk, Michael Saylor) + crypto keywords

### 4. Live Chat Scam Analysis (Signal 11, +45/+35 points)
**Added:** Dec 9, 2025  
**Rationale:** Scam links often only appear in chat (pinned Super Chats)  
**Features:**
- Samples 20 recent chat messages via API
- Detects pinned Super Chats with scam content (+45 points)
- Identifies bot spam patterns (3+ identical messages)
- Checks for scam domain links in chat text

---

## Performance Metrics

### Current Results (Dec 9, 2025)

**Dataset:** 52 manually validated samples

**Overall Metrics:**
- **Accuracy:** 73.1% (38 correct / 52 total)
- **Precision:** 66.7% (4 TP / 6 HIGH-risk detections)
- **Recall:** 66.7% (4 TP / 6 actual scams)
- **F1 Score:** 0.67
- **Specificity:** 91.3% (42 TN / 46 legitimate videos)

**Confusion Matrix:**
```
                Predicted
            HIGH | LOW/MED | Total
          ------|---------|-------
SCAM        4   |    2    |   6
LEGIT       2   |   44    |  46
          ------|---------|-------
Total       6   |   46    |  52
```

**Error Analysis:**
- **False Positives (2):**
  - Didi Random: German Bitcoin news channel (urgency language)
  - CNBC-TV18: Business news channel (crypto market coverage)
- **False Negatives (2):**
  - Serapodcast: Michael Saylor impersonation (educational penalty applied)
  - HopeLyrics: Michael Saylor impersonation (educational penalty applied)

### Target Metrics (Project Goal)

- **Precision:** ≥80% (minimize false alarms)
- **Recall:** ≥85% (catch most scams)
- **F1 Score:** ≥0.82

---

## API Quota Management

### YouTube Data API v3 Limits

**Default Quota:** 10,000 units/day  
**Quota Increase:** Can request up to 1,000,000 units/day from Google

**Operation Costs:**
| Operation | Quota Units |
|-----------|-------------|
| `search().list()` | 100 units |
| `videos().list()` | 1 unit |
| `channels().list()` | 1 unit |
| `liveChatMessages().list()` | 5 units |

**Typical Run Costs:**
```
Full detector run (70 queries):
  70 queries × 100 units        = 7,000 units
  ~50 videos × 1 unit           =    50 units
  ~50 channels × 1 unit         =    50 units
  ~20 active chats × 5 units    =   100 units
                           Total ≈ 7,200 units
```

**Rate Limiting:**
- 100 requests per 100 seconds per user
- Built-in delays in detector: `time.sleep(0.5)` between videos

---

## Common Commands

### Running Detection
```bash
cd src
export YOUTUBE_API_KEY='your-api-key-here'
python youtube_streamjacking_detector_enhanced.py
```

### Calculating Metrics
```bash
cd src
python calculate_metrics.py  # Reads from MongoDB
```

### MongoDB Operations
```bash
# Backup collection
python backup_mongodb.py

# Connect to MongoDB
mongosh
use streamjacking
db.detection_results_v2.find({risk_category: "HIGH"}).count()

# Query validated samples
db.detection_results_v2.find({"validation.label": "false_negative"})
```

### Validation
```bash
# Interactive validator
python validation_helper.py

# Bulk label correction
python correct_validations.py
```

---

## Project Timeline

### Completed (Nov-Dec 2025)
- ✅ Detection system with 11 signals
- ✅ YouTube API integration
- ✅ MongoDB storage & validation tracking
- ✅ Metrics calculation framework
- ✅ Manual validation of 52 samples
- ✅ Enhanced signals (QR code, scam domains, chat analysis)

### Current Phase (Week of Dec 9)
- 🔄 Fixing educational intent penalty bug
- 🔄 Improving channel analysis reliability
- 🔄 Running enhanced detector on full query set
- 🔄 Validating improvements in metrics

### Remaining Work (Dec 10-18)
- ❌ Attack pattern documentation (3-5 common scam types)
- ❌ False positive/negative analysis writeup
- ❌ Final report writing (methodology, results, discussion)
- ❌ Presentation preparation

**Deadline:** December 18, 2025

---

## Key Insights for LLMs

### When Analyzing Detection Issues

1. **Check risk_score vs confidence_score:**
   - `risk_score`: Raw points from signals (e.g., 75.0)
   - `confidence_score`: Normalized 0-1 value based on category (e.g., 0.80)
   - **Threshold for HIGH risk: risk_score ≥ 70**

2. **Educational penalty is suspect:**
   - If video has celebrity + crypto but scored MEDIUM
   - Check signals for "Educational/News intent detected (Risk reduced)"
   - This -30 penalty causes most false negatives

3. **Channel signals matter:**
   - Empty `channel_signals: []` means channel analysis skipped
   - Missing potential +40-60 points from hijack detection
   - Topic mismatch (Signal 8) is most valuable channel signal

4. **Validation labels ARE confusion matrix:**
   - Don't calculate predictions from scores
   - Labels directly map: `true_positive` = TP, `false_negative` = FN, etc.
   - Metrics calculator reads `validation.label` field, not `ground_truth_label`

### When Suggesting Improvements

1. **Weight adjustments are sensitive:**
   - Total system has ~200 points available
   - Threshold is 70 for HIGH risk
   - Changing weights by ±5-10 points significantly impacts classification

2. **API quota is limited:**
   - Don't suggest operations that require many API calls
   - Current system uses ~7,000 units per run (70% of daily quota)
   - Chat sampling is expensive (5 units × number of active streams)

3. **MongoDB is source of truth:**
   - All validation data lives in `detection_results_v2` collection
   - JSON files are exports/backups only
   - Metrics calculator reads directly from MongoDB

4. **False negatives > False positives:**
   - Project goal is high recall (catch scams)
   - Some false positives acceptable (can be manually filtered)
   - Missing real scams (false negatives) is worse

---

## Contact & Resources

**Team:**
- Aninda Ghosh: ag10293@nyu.edu
- Dhari Alshammari: da3974@nyu.edu

**Key Resources:**
- YouTube Data API: https://developers.google.com/youtube/v3
- MongoDB Python Driver: https://pymongo.readthedocs.io/
- Project Repository: `trustsafety-streamjacking-detector`

**Professor Feedback (Midpoint):**
- Score: 97/100
- Strengths: Thoughtful signal design, false positive consideration
- Areas to improve: Link papers to signal choices, clarify error analysis methodology

---

**Last Updated:** December 9, 2025  
**Document Version:** 1.0  
**Status:** Active Development (9 days until deadline)
