# Validation Workflow Quick Start

This guide walks you through manually validating your detections and calculating precision/recall metrics.

## Overview

You have **three validation tools** to choose from:

1. **Interactive Terminal Validator** (Recommended) - Step through detections one by one
2. **Manual CSV Review** - Export to spreadsheet, label offline
3. **Manual JSON Review** - For programmatic workflows

## Option 1: Interactive Terminal Validator (Recommended)

### Step 1: Run Interactive Validator

```bash
cd src
python interactive_validator.py data/results/streamjacking_detection_results.json
```

### Step 2: Label Detections

For each detection, you'll see:
- Video and channel info
- Risk score
- Triggered signals

Then choose:
- `[1]` True Positive - Definitely stream-jacking/scam
- `[2]` False Positive - Legitimate content  
- `[3]` Uncertain - Unclear
- `[o]` Open URL - Opens video/channel in browser
- `[s]` Skip - Skip for now
- `[b]` Back - Go to previous detection
- `[q]` Quit - Save and exit (resume later)

### Step 3: Auto-Save Progress

Progress is **automatically saved** every 5 detections to:
```
data/results/streamjacking_detection_results_validated.json
```

You can quit anytime with `[q]` and resume later by running the same command again!

### Step 4: Calculate Metrics

Once you've labeled 50+ detections:

```bash
python calculate_metrics.py data/results/streamjacking_detection_results_validated.json
```

Output:
```
📊 VALIDATION METRICS
═══════════════════════════════════════════════════════════════════════════════

🎯 OVERALL PERFORMANCE:
   Total Labeled: 53
   ✅ True Positives:  38
   ❌ False Positives: 12
   ❓ Uncertain:       3

📈 PRECISION: 76.00%

📊 BY RISK CATEGORY:
   HIGH: Precision=85.00% (TP:17, FP:3)
   MEDIUM: Precision=70.00% (TP:21, FP:9)

🎯 SCAM TYPES:
   • giveaway_scam: 22
   • impersonation: 14
   • hijacked_channel: 2
```

## Option 2: Manual CSV Review

### Step 1: Generate CSV Template

```bash
cd src
python validation_helper.py data/results/streamjacking_detection_results.json
```

This creates:
- `data/analysis/validation_sample.csv` - Stratified sample for labeling
- `data/analysis/validation_sample.json` - JSON version

### Step 2: Open in Spreadsheet

```bash
open data/analysis/validation_sample.csv
```

Or use Google Sheets, Excel, etc.

### Step 3: Fill in Labels

For each row:
1. Click the video URL to review
2. Fill in "Ground Truth Label" column:
   - `true_positive`
   - `false_positive`
   - `uncertain`
3. Add notes in "Notes" column

### Step 4: Calculate Metrics

```bash
python calculate_metrics.py data/analysis/validation_sample.csv
```

## Option 3: Manual JSON Review

Edit `data/analysis/validation_sample.json` and fill in the `ground_truth` fields:

```json
{
  "id": 1,
  "video_id": "abc123",
  "ground_truth": {
    "label": "true_positive",
    "reasoning": "Fake Elon Musk giveaway scam",
    "actual_scam_type": "impersonation",
    "reviewed_by": "your_name",
    "review_date": "2025-12-06"
  }
}
```

Then calculate:
```bash
python calculate_metrics.py data/analysis/validation_sample.json
```

## Labeling Guidelines

### 🔴 True Positive (Stream-Jacking/Scam)

Look for:
- **Impersonation**: Pretending to be celebrity/brand/official
- **Giveaway scams**: "Send 1 BTC get 2 BTC back"
- **Hijacked accounts**: Old legitimate channel now posting scams
- **Fake live events**: "Elon speaking LIVE" with scam links
- **Urgent language**: "ENDING SOON", "LAST CHANCE"
- **Scam URLs**: bit.ly links, suspicious domains
- **Crypto addresses**: In description/comments/video

### 🟢 False Positive (Legitimate)

Common patterns:
- **News channels**: Bloomberg, CNBC, Reuters (even if crypto content)
- **Educational content**: Tutorials, trading education, technical analysis
- **Space enthusiasts**: LabPadre, SpaceX fans (even if live)
- **Official channels**: Verified company channels
- **Legitimate events**: Real conferences, interviews

### ❓ Uncertain

Use when:
- Video no longer available
- Context unclear
- Mixed signals (some scam indicators, but might be legitimate)
- Need more investigation

## How Many to Validate?

**Minimum**: 50 detections (for 95% confidence)
**Recommended**: 100 detections (for better precision estimate)
**Target**: Cover all risk categories (HIGH, MEDIUM, LOW)

### Stratified Sampling

The validation helper automatically creates a stratified sample:
- 25 from HIGH risk (≥70 score)
- 20 from MEDIUM risk (40-69 score)  
- 5 from LOW risk (<40 score)

This ensures you test the full range of detector performance.

## Tips for Efficient Validation

### 1. Use Interactive Validator for Speed
- Opens URLs with one keystroke `[o]`
- Auto-saves progress
- Resume anytime
- No spreadsheet switching

### 2. Batch Review in Sessions
- Review 10-15 at a time
- Take breaks to avoid fatigue
- Maintain consistency within sessions

### 3. Document Patterns
Keep notes on:
- Common false positives (to refine detector)
- New scam patterns (to add signals)
- Edge cases (to improve whitelist)

### 4. Review Channel History
Don't just look at one video:
- Check channel's other videos
- Look at "About" section
- Check subscriber count trends
- Read comments section

### 5. Search for Context
If uncertain:
- Google the channel name
- Search "[channel] scam" on Reddit/Twitter
- Check if others reported it
- Look for official social media

## Example Workflow

**Day 1: Quick batch (30 mins)**
```bash
cd src
python interactive_validator.py data/results/streamjacking_detection_results.json
# Label 15-20 detections
# Press [q] to quit and save
```

**Day 2: Continue (30 mins)**
```bash
# Same command - automatically resumes!
python interactive_validator.py data/results/streamjacking_detection_results.json
# Label 15-20 more
```

**Day 3: Finish & Calculate (30 mins)**
```bash
# Label remaining detections
python interactive_validator.py data/results/streamjacking_detection_results.json

# Calculate metrics
python calculate_metrics.py data/results/streamjacking_detection_results_validated.json
```

**Total time**: ~90 minutes for 50-60 validations

## Expected Precision Targets

Based on your detector's risk categories:

| Risk Category | Target Precision | Acceptable Range |
|--------------|------------------|------------------|
| HIGH         | ≥80%            | 75-90%          |
| MEDIUM       | ≥70%            | 65-80%          |
| LOW          | ≥50%            | 40-70%          |
| **Overall**  | **≥75%**        | **70-85%**      |

For academic projects, **70-80% precision** is excellent for a prototype.

## Troubleshooting

### "No module named 'webbrowser'"
The `webbrowser` module is built-in to Python. If it doesn't work, manually copy URLs.

### "Progress file not found"
First run creates the file. If you see this error, check:
```bash
ls data/results/*_validated.json
```

### "Can't open URLs"
On some systems, `webbrowser.open()` might not work. Use the CSV method instead:
```bash
python validation_helper.py data/results/streamjacking_detection_results.json
open data/analysis/validation_sample.csv
```

### "Too many uncertain labels"
If >20% are uncertain:
- Review guidelines again
- Take longer time per video
- Focus on clear TP/FP cases first
- Come back to uncertain ones later

## Next Steps After Validation

1. **Calculate metrics**: Run `calculate_metrics.py`
2. **Analyze false positives**: Look for patterns to fix
3. **Refine detector**: Update whitelist, signals, thresholds
4. **Re-run detection**: Test improvements
5. **Document findings**: Write up in final report

## Questions?

Check the full documentation:
- `docs/guides/VALIDATION_GUIDE.md` - Detailed validation methodology
- `docs/guides/QUICK_START.md` - Project overview
- `README.md` - Main documentation
