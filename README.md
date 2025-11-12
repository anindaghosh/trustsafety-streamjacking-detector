# YouTube Stream-Jacking Detection System

## Setup Instructions

### 1. Get YouTube Data API Key

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select existing)
3. Enable YouTube Data API v3:
   - Go to "APIs & Services" > "Library"
   - Search for "YouTube Data API v3"
   - Click "Enable"
4. Create credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "API Key"
   - Copy your API key

### 2. Install Dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

### 3. Set API Key

```bash
export YOUTUBE_API_KEY='your-api-key-here'
```

### 4. Run the Detector

```bash
python youtube_streamjacking_detector.py
```

## System Architecture

### Core Components

1. **YouTubeAPIClient**: Handles all YouTube API interactions
   - Search for livestreams
   - Retrieve channel metadata
   - Retrieve video metadata
   - Track API quota usage

2. **StreamJackingDetector**: Implements detection logic
   - Character substitution detection
   - Channel analysis (metadata signals)
   - Video analysis (content signals)
   - Risk scoring

3. **StreamJackingMonitor**: Orchestrates monitoring process
   - Manages search queries
   - Coordinates detection workflow
   - Saves results
   - Generates reports

## Detection Signals

### Channel-Level Signals

1. **Character Substitution Impersonation**
   - Detects names using l -> I, O -> 0, etc.
   - Targets: Crypto figures, tech brands, crypto projects
   - Weight: 30 points

2. **Account Age vs Activity Mismatch**
   - Old account with minimal content
   - Weight: 15 points

3. **Subscriber-Content Disparity**
   - High subscribers, few videos
   - Weight: 20 points

4. **Crypto-Heavy Description**
   - Non-crypto channel with crypto keywords
   - Weight: 10 points

5. **Topic Category Mismatch**
   - Content doesn't match channel topics
   - Weight: 10 points

### Video-Level Signals

1. **Title Impersonation**
   - Character substitution in video title
   - Weight: 25 points

2. **Scam Keywords**
   - "giveaway", "double", "send", etc.
   - Weight: 20 points

3. **Crypto Addresses/URLs**
   - Contains wallet addresses or suspicious links
   - Weight: 25 points

4. **Live Stream Status**
   - Currently broadcasting
   - Weight: 5 points

5. **Engagement Anomalies**
   - High views, restricted comments
   - Weight: 15 points

6. **Crypto Tags**
   - Multiple crypto-related tags
   - Weight: 10 points

## Risk Scoring

- **High Risk (≥70)**: Strong indicators of stream-jacking
- **Medium Risk (40-69)**: Suspicious activity, requires review
- **Low Risk (30-39)**: Minor concerns, monitor

Total risk = Video risk + (Channel risk × 0.5)

## API Quota Management

YouTube Data API v3 has a default quota of **10,000 units per day**.

### Operation Costs:
- Search: 100 units
- Videos.list: 5 units (with multiple parts)
- Channels.list: 5 units (with multiple parts)

### Estimated Usage:
- Monitoring 10 queries × 10 results = ~1,500 units
- Full dataset (500-1000 channels) = ~5,000-10,000 units

### Optimization Strategies:
1. Cache channel data to avoid duplicate requests
2. Batch API calls where possible
3. Apply for quota increase if needed
4. Focus on high-value targets first

## Output Format

Results are saved as JSON with the following structure:

```json
{
  "video_id": "abc123",
  "video_title": "Elon Musk ETH Giveaway",
  "channel_id": "UC...",
  "channel_title": "Tesl@ Official",
  "is_live": true,
  "video_risk_score": 70.0,
  "channel_risk_score": 50.0,
  "total_risk_score": 95.0,
  "video_signals": [
    "Title impersonation: tesla",
    "Multiple scam keywords: giveaway, eth, send"
  ],
  "channel_signals": [
    "Name impersonation: tesla",
    "High subscribers, minimal content"
  ],
  "detected_at": "2025-11-07T10:30:00",
  "search_query": "Tesla crypto giveaway"
}
```

## Troubleshooting

### Common Issues:

**API Key Error**
```
Error: The request cannot be completed because you have exceeded your quota
```
Solution: Wait for quota reset (daily) or apply for increase

**Import Error**
```
ModuleNotFoundError: No module named 'googleapiclient'
```
Solution: `pip install google-api-python-client --break-system-packages`

**No Results Found**
- Adjust search queries
- Lower risk threshold
- Check if streams are actually live

## Contact

For questions about implementation:
- Aninda Ghosh: ag10293@nyu.edu
- Dhari Alshammari: da3974@nyu.edu

Course: Trust and Safety (CS-UY 3943)  
Instructor: Prof. Rosanna Bellini
