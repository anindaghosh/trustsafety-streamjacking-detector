# MongoDB + Validation Integration - Quick Reference

## What Changed?

✅ **Detections are now stored in MongoDB** (`streamjacking.detection_results_v2`)  
✅ **Validation labels are synced to MongoDB** in real-time  
✅ **Query detections and validations** directly from MongoDB  

---

## Workflow

### 1. Run Detector (Auto-saves to MongoDB)

```bash
cd src
export MONGODB_URI='mongodb://localhost:27017/'  # Optional, defaults to localhost
python youtube_streamjacking_detector_enhanced.py
```

**What happens:**
- Searches YouTube for scam patterns
- Analyzes each video/channel
- **Upserts** to MongoDB (deduplicates by `video_id`)
- Also saves to `data/results/streamjacking_detection_results.json`

---

### 2. Validate Detections (Auto-syncs to MongoDB)

```bash
python interactive_validator.py data/results/streamjacking_detection_results.json
```

**What happens:**
- Shows you each detection
- You label: `[1]` TP, `[2]` FP, `[3]` Uncertain
- **Immediately syncs** label to MongoDB
- Also saves to `data/results/streamjacking_detection_results_validated.json`

**MongoDB fields updated:**
- `validation` (full object)
- `ground_truth_label`
- `validation_reasoning`
- `scam_type`
- `validated_at`

---

### 3. Calculate Metrics (From JSON or MongoDB)

```bash
# From validated JSON file
python calculate_metrics.py data/results/streamjacking_detection_results_validated.json

# Or query MongoDB directly (see below)
```

---

## Why This Matters

### Before (JSON only):
- 33 detections → 19 unique videos saved (deduplication only at end)
- No persistent corpus across runs
- Validation labels only in separate JSON file
- Hard to query historical data

### After (MongoDB + Validation Sync):
- **Real-time deduplication** by `video_id`
- **Persistent corpus** across multiple detector runs
- **Validation labels stored with detections** in MongoDB
- **Easy querying** for analysis, reporting, metrics

---

## MongoDB Queries - Copy/Paste Ready

```bash
mongosh
use streamjacking
```

### Check Validation Progress
```javascript
db.detection_results_v2.aggregate([
  {$group: {
    _id: null,
    total: {$sum: 1},
    validated: {$sum: {$cond: [{$ne: ["$ground_truth_label", null]}, 1, 0]}},
    true_positives: {$sum: {$cond: [{$eq: ["$ground_truth_label", "true_positive"]}, 1, 0]}},
    false_positives: {$sum: {$cond: [{$eq: ["$ground_truth_label", "false_positive"]}, 1, 0]}}
  }},
  {$project: {
    total: 1,
    validated: 1,
    true_positives: 1,
    false_positives: 1,
    precision: {$divide: ["$true_positives", {$add: ["$true_positives", "$false_positives"]}]}
  }}
])
```

### Find All Validated Detections
```javascript
db.detection_results_v2.find({ground_truth_label: {$exists: true}})
```

### Get Scam Type Breakdown
```javascript
db.detection_results_v2.aggregate([
  {$match: {scam_type: {$exists: true}}},
  {$group: {_id: "$scam_type", count: {$sum: 1}}},
  {$sort: {count: -1}}
])
```

### Find False Positives by Risk Category
```javascript
db.detection_results_v2.aggregate([
  {$match: {ground_truth_label: "false_positive"}},
  {$group: {_id: "$risk_category", count: {$sum: 1}}},
  {$sort: {count: -1}}
])
```

### Export Validated Data to CSV
```bash
mongoexport --db=streamjacking --collection=detection_results_v2 \
  --query='{"ground_truth_label": {"$exists": true}}' \
  --type=csv --fields=video_id,channel_id,video_title,channel_title,risk_category,total_risk_score,ground_truth_label,scam_type,validation_reasoning \
  --out=validated_detections.csv
```

---

## Sync Existing Validations to MongoDB

If you have already validated detections in JSON but haven't synced to MongoDB:

```bash
python sync_validations_to_mongodb.py data/results/streamjacking_detection_results_validated.json
```

**Output:**
```
Loading validated data from ...
Found 53 validated detections

Connecting to MongoDB...
✅ Connected to MongoDB

Syncing validation labels to streamjacking.detection_results_v2...
   Synced 10/53...
   Synced 20/53...
   ...

SYNC SUMMARY
═══════════════════════════════════════════════════════════
Total validated detections: 53
✅ Synced successfully:     48
⚠️  Not found in database:  5
❌ Failed to sync:          0
```

---

## Troubleshooting

### "MongoDB not available"
- **Local**: `brew services start mongodb-community` (macOS)
- **Check**: `mongosh` should connect
- **Alternative**: Use MongoDB Atlas (cloud free tier)

### "Not found in database" during sync
- The video isn't in MongoDB yet
- Solution: Re-run the detector to populate MongoDB

### View MongoDB data in GUI
```bash
# Install MongoDB Compass (free GUI)
# Connect to: mongodb://localhost:27017
# Database: streamjacking
# Collection: detection_results_v2
```

---

## Database Info

- **Database**: `streamjacking`
- **Collection**: `detection_results_v2`
- **Unique Key**: `video_id`
- **Indexes**: 
  - `video_id` (unique)
  - `channel_id`
  - `detected_at`
  - `risk_category`
  - `ground_truth_label` (for validation queries)

---

## File Locations

- **Detector**: `src/youtube_streamjacking_detector_enhanced.py`
- **Interactive Validator**: `src/interactive_validator.py`
- **Sync Tool**: `src/sync_validations_to_mongodb.py`
- **Metrics Calculator**: `src/calculate_metrics.py`
- **Detection Results**: `data/results/streamjacking_detection_results.json`
- **Validated Results**: `data/results/streamjacking_detection_results_validated.json`

---

## Benefits for Your Project

1. ✅ **Multi-day corpus**: Run detector daily, builds comprehensive dataset
2. ✅ **Validation tracking**: Know exactly what you've labeled
3. ✅ **Real-time metrics**: Query precision/recall anytime from MongoDB
4. ✅ **Pattern analysis**: Group by scam type, risk category, channel
5. ✅ **Report data**: Easy exports for final report tables/charts
6. ✅ **No data loss**: Everything persisted in database + JSON backups

---

## Next Steps

1. **Start MongoDB**: `brew services start mongodb-community`
2. **Run detector**: Populates MongoDB with detections
3. **Validate 50+**: Use interactive validator (auto-syncs to MongoDB)
4. **Query metrics**: Use MongoDB queries above
5. **Write report**: Export data for tables/charts
