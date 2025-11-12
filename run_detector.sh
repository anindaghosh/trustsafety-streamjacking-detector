#!/bin/bash

# Quick start script for detector

# Check API key
if [ -z "$YOUTUBE_API_KEY" ]; then
    echo "❌ Error: YOUTUBE_API_KEY not set"
    echo "Run: export YOUTUBE_API_KEY='your-key-here'"
    exit 1
fi

# Set Python path
export PYTHONPATH="${PYTHONPATH}:${PWD}/src"

# Run detector
echo "🔍 Starting stream-jacking detector..."
python src/youtube_streamjacking_detector_enhanced.py

# Check if results were created
if [ -f "data/results/streamjacking_detection_results.json" ]; then
    echo "✅ Detection complete!"
    echo "📊 Running analysis..."
    python src/analysis.py data/results/streamjacking_detection_results.json
else
    echo "⚠️  No results file found"
fi
