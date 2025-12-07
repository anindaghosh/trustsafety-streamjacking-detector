# MongoDB Setup Guide

## Overview

The detector now supports MongoDB for persistent storage of detections across multiple runs. This enables:

- **Deduplication**: Same video detected multiple times only stored once (with detection count)
- **Time-series analysis**: Track when scams first appeared and how long they persisted
- **Historical corpus**: Build a dataset over days/weeks without losing data
- **Better querying**: Filter by risk level, date range, channel, etc.

## Setup Options

### Option 1: Local MongoDB (Recommended for Development)

#### Install MongoDB

**macOS (Homebrew):**
```bash
brew tap mongodb/brew
brew install mongodb-community@7.0
brew services start mongodb-community@7.0
```

**Ubuntu/Debian:**
```bash
wget -qO - https://www.mongodb.org/static/pgp/server-7.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org
sudo systemctl start mongod
```

**Windows:**
Download installer from: https://www.mongodb.com/try/download/community

#### Verify Installation
```bash
mongosh
# Should connect to mongodb://localhost:27017
```

### Option 2: MongoDB Atlas (Cloud - Free Tier Available)

1. Go to: https://www.mongodb.com/cloud/atlas/register
2. Create a free M0 cluster
3. Create a database user (Database Access)
4. Whitelist your IP (Network Access → Add IP Address → Allow Access from Anywhere for testing)
5. Get connection string: Clusters → Connect → Connect your application
   - Example: `mongodb+srv://username:password@cluster0.xxxxx.mongodb.net/`

### Option 3: No MongoDB (Graceful Degradation)

If MongoDB is not installed or connection fails, the detector will:
- Print a warning
- Continue working normally
- Only save results to JSON files

## Configuration

### Method 1: Environment Variable (Recommended)

Add to `.env` file:
```bash
MONGODB_URI=mongodb://localhost:27017/
# or for Atlas:
# MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/
```

### Method 2: Default (No Configuration)

The detector defaults to `mongodb://localhost:27017/` if no configuration is provided.

## Install Python Dependencies

```bash
pip install pymongo python-dotenv
# or
pip install -r requirements.txt
```

## Database Schema

### Collection: `detection_results_v2`

```json
{
  "_id": ObjectId("..."),
  "video_id": "abc123",  // Unique identifier
  "video_title": "...",
  "channel_id": "UC...",
  "channel_title": "...",
  "is_live": true,
  "video_risk_score": 70.0,
  "channel_risk_score": 50.0,
  "total_risk_score": 95.0,
  "risk_category": "HIGH",
  "confidence_score": 0.85,
  "video_signals": [...],
  "channel_signals": [...],
  "detected_at": "2025-12-06T...",  // Latest detection time
  "first_detected": "2025-12-05T...",  // First time detected
  "detection_count": 3,  // Number of times detected
  "search_query": "crypto giveaway",
  "video_url": "https://youtube.com/...",
  "channel_url": "https://youtube.com/...",
  
  // Validation fields (added by interactive validator)
  "validation": {
    "label": "true_positive",  // or "false_positive", "uncertain"
    "reasoning": "Clear impersonation scam",
    "scam_type": "impersonation",
    "reviewed_at": "2025-12-06T...",
    "reviewer": "username"
  },
  "validated_at": "2025-12-06T...",
  "ground_truth_label": "true_positive",
  "validation_reasoning": "Clear impersonation scam",
  "scam_type": "impersonation"
}
```

### Indexes Created

- `video_id` (unique) - Fast lookups and upserts
- `channel_id` - Query all videos from a channel
- `detected_at` - Time-series queries
- `risk_category` - Filter by risk level
- `(video_id, detected_at)` - Compound index for historical tracking

## Usage

### Run Detector (Automatic MongoDB Integration)

```bash
export YOUTUBE_API_KEY='your-key'
export MONGODB_URI='mongodb://localhost:27017/'  # Optional
python src/youtube_streamjacking_detector_enhanced.py
```

The detector will:
1. Connect to MongoDB (or gracefully skip if unavailable)
2. Run detection as usual
3. **Upsert** each detection to MongoDB in real-time
4. Also save to JSON file as backup
5. Print MongoDB stats at the end

### Validate Detections (Interactive Validator with MongoDB Sync)

```bash
# Interactive validation automatically syncs labels to MongoDB
cd src
python interactive_validator.py data/results/streamjacking_detection_results.json

# Labels each detection and immediately syncs to MongoDB:
# - ground_truth_label
# - validation_reasoning
# - scam_type
# - validated_at
```

### Sync Existing Validations to MongoDB

If you already have validated detections in JSON format:

```bash
python sync_validations_to_mongodb.py data/results/streamjacking_detection_results_validated.json
```

### Query MongoDB Directly

```bash
mongosh

use streamjacking

// Count total detections
db.detection_results_v2.countDocuments()

// Find all CRITICAL risk
db.detection_results_v2.find({risk_category: "CRITICAL"})

// Find validated detections
db.detection_results_v2.find({ground_truth_label: {$exists: true}})

// Count true positives vs false positives
db.detection_results_v2.aggregate([
  {$match: {ground_truth_label: {$exists: true}}},
  {$group: {_id: "$ground_truth_label", count: {$sum: 1}}}
])

// Find detections from specific channel
db.detection_results_v2.find({channel_id: "UCxxxxx"})

// Calculate precision from validated data
db.detection_results_v2.aggregate([
  {$match: {ground_truth_label: {$in: ["true_positive", "false_positive"]}}},
  {$group: {
    _id: null,
    tp: {$sum: {$cond: [{$eq: ["$ground_truth_label", "true_positive"]}, 1, 0]}},
    total: {$sum: 1}
  }},
  {$project: {precision: {$divide: ["$tp", "$total"]}}}
])

// Find videos detected multiple times
db.detection_results_v2.find({detection_count: {$gt: 1}})

// Time-series: Detections in last 24 hours
db.detection_results_v2.find({
  detected_at: {$gte: new Date(Date.now() - 24*60*60*1000).toISOString()}
})

// Get validation progress
db.detection_results_v2.aggregate([
  {$group: {
    _id: null,
    total: {$sum: 1},
    validated: {$sum: {$cond: [{$ne: ["$ground_truth_label", null]}, 1, 0]}}
  }}
])
```

## Benefits for Your Project

### 1. Multi-Day Corpus Building
Run the detector daily for a week:
```bash
# Day 1
python src/youtube_streamjacking_detector_enhanced.py

# Day 2 (same command - will update existing, add new)
python src/youtube_streamjacking_detector_enhanced.py

# Result: Single corpus with all unique videos across both runs
```

### 2. Track Scam Persistence
```javascript
// Find scams that persisted for 3+ days
db.detections.find({detection_count: {$gte: 3}})
```

### 3. Channel-Level Analysis
```javascript
// Find all detections from a specific hijacked channel
db.detections.find({channel_id: "UCxxxxx"}).sort({detected_at: -1})
```

### 4. Export for Analysis
```bash
# Export to JSON for manual review
mongoexport --db=streamjacking_detector --collection=detections \
  --query='{"risk_category":"HIGH"}' --out=high_risk_export.json

# Export to CSV
mongoexport --db=streamjacking_detector --collection=detections \
  --type=csv --fields=video_id,channel_id,risk_category,detected_at \
  --out=detections.csv
```

## Troubleshooting

### "Connection refused" Error
- MongoDB not running: `brew services start mongodb-community` (macOS)
- Wrong connection string: Check MONGODB_URI

### "Authentication failed"
- For Atlas: Check username/password in connection string
- For local: MongoDB by default has no authentication

### "Database/Collection not found"
- Normal! MongoDB creates them automatically on first write

### Detector still works without MongoDB
- This is intentional! The detector will save to JSON and continue normally

## Advanced: Custom Database Name

```python
# In your code
mongo_manager = MongoDBManager(database_name='my_custom_db')
```

Or modify `main()` in the detector script.
