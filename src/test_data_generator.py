"""
Generate synthetic test data for detector validation
Useful for testing without consuming API quota
"""

import json
import random
from datetime import datetime, timedelta
from typing import List, Dict


class TestDataGenerator:
    """Generate realistic test data for stream-jacking detection"""
    
    # Legitimate channel names
    LEGITIMATE_CHANNELS = [
        "Tech Reviews Daily",
        "Gaming Central",
        "Cooking Adventures",
        "Travel Vlogs HD",
        "Music Producer Tips",
        "Fitness Journey",
        "DIY Projects"
    ]
    
    # Impersonation variations
    IMPERSONATION_PATTERNS = [
        ("Tesla", ["Tеsla", "TesIa", "T3sla", "Tes1a"]),  # Note: first 'e' is Cyrillic
        ("Elon Musk", ["EIon Musk", "Elon Μusk", "Ε1on Musk"]),
        ("SpaceX", ["SpaceΧ", "Space X Official", "SpасeX"]),
        ("Ethereum", ["Ethеreum", "Ethеrеum", "Eth3reum"]),
        ("Vitalik Buterin", ["VitaIik Buterin", "Vitalik Butеrin"]),
        ("Apple", ["AppIe", "Αpple", "App1e"])
    ]
    
    SCAM_TITLES = [
        "{target} LIVE: ETH 2.0 Giveaway - Send 1 ETH, Get 2 ETH Back!",
        "{target} Bitcoin Announcement - Limited Time Double Your BTC",
        "EXCLUSIVE: {target} Crypto Event LIVE NOW - Scan QR for Bonus",
        "{target} Ethereum Giveaway 2024 - Official Livestream",
        "Send 0.1 BTC to {target} Wallet - Receive 1 BTC Back INSTANTLY"
    ]
    
    LEGITIMATE_TITLES = [
        "Daily Tech News Update - {date}",
        "Product Review: Latest Smartphone",
        "How To Tutorial: Web Development",
        "Gaming Stream - Playing New Release",
        "Q&A Session with Viewers"
    ]
    
    SCAM_DESCRIPTIONS = [
        """🎉 OFFICIAL GIVEAWAY 🎉
Send ETH to: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb
Get 2X back instantly!
⏰ Limited time only
📱 Scan QR code in stream
        """,
        """💰 EXCLUSIVE CRYPTOCURRENCY EVENT
Ethereum 2.0 Launch Celebration
Send 1-10 ETH, receive double instantly
Trusted by millions worldwide
        """,
        """🚀 CRYPTO DOUBLING EVENT
Official partnership announcement
Guaranteed returns within 24 hours
Join thousands of successful participants
        """
    ]
    
    def __init__(self, seed: int = 42):
        """Initialize generator with seed for reproducibility"""
        random.seed(seed)
    
    def generate_channel_id(self) -> str:
        """Generate realistic YouTube channel ID"""
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        return "UC" + ''.join(random.choices(chars, k=22))
    
    def generate_video_id(self) -> str:
        """Generate realistic YouTube video ID"""
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        return ''.join(random.choices(chars, k=11))
    
    def generate_legitimate_detection(self) -> Dict:
        """Generate a legitimate channel detection (false positive test)"""
        channel_name = random.choice(self.LEGITIMATE_CHANNELS)
        video_title = random.choice(self.LEGITIMATE_TITLES).format(
            date=datetime.now().strftime("%Y-%m-%d")
        )
        
        return {
            'video_id': self.generate_video_id(),
            'video_title': video_title,
            'channel_id': self.generate_channel_id(),
            'channel_title': channel_name,
            'is_live': random.random() < 0.2,
            'video_risk_score': random.uniform(0, 25),
            'channel_risk_score': random.uniform(0, 15),
            'total_risk_score': random.uniform(0, 30),
            'video_signals': [],
            'channel_signals': [],
            'detected_at': datetime.now().isoformat(),
            'search_query': random.choice(['tech news', 'gaming', 'tutorials'])
        }
    
    def generate_suspicious_detection(self, risk_level: str = 'high') -> Dict:
        """
        Generate a suspicious channel detection
        
        Args:
            risk_level: 'low', 'medium', or 'high'
        """
        # Choose impersonation target
        target_original, variations = random.choice(self.IMPERSONATION_PATTERNS)
        target_fake = random.choice(variations)
        
        # Generate title and description
        video_title = random.choice(self.SCAM_TITLES).format(target=target_fake)
        video_description = random.choice(self.SCAM_DESCRIPTIONS)
        
        # Generate signals based on risk level
        video_signals = []
        channel_signals = []
        
        if risk_level in ['medium', 'high']:
            video_signals.append(f"Title impersonation: {target_original}")
            channel_signals.append(f"Name impersonation: {target_original}")
        
        if risk_level == 'high':
            video_signals.extend([
                "Multiple scam keywords: giveaway, send, double",
                "Contains crypto address or suspicious URL"
            ])
            channel_signals.extend([
                "High subscribers, minimal content",
                "Old account with little content (possible hijack)"
            ])
        elif risk_level == 'medium':
            video_signals.append("Multiple scam keywords: giveaway, crypto")
            channel_signals.append("Crypto-heavy description (3 keywords)")
        
        # Adjust risk scores
        if risk_level == 'high':
            video_risk = random.uniform(65, 90)
            channel_risk = random.uniform(45, 70)
        elif risk_level == 'medium':
            video_risk = random.uniform(35, 55)
            channel_risk = random.uniform(25, 40)
        else:  # low
            video_risk = random.uniform(25, 40)
            channel_risk = random.uniform(15, 25)
        
        total_risk = video_risk + (channel_risk * 0.5)
        
        # Add live streaming signals if applicable
        is_live = random.random() < 0.7  # 70% of scams are live
        if is_live:
            video_signals.append("Currently live streaming")
            if random.random() < 0.6:
                video_signals.append("High views but restricted comments")
        
        return {
            'video_id': self.generate_video_id(),
            'video_title': video_title,
            'channel_id': self.generate_channel_id(),
            'channel_title': target_fake,
            'is_live': is_live,
            'video_risk_score': round(video_risk, 1),
            'channel_risk_score': round(channel_risk, 1),
            'total_risk_score': round(total_risk, 1),
            'video_signals': video_signals,
            'channel_signals': channel_signals,
            'detected_at': (datetime.now() - timedelta(
                hours=random.randint(0, 48)
            )).isoformat(),
            'search_query': random.choice([
                'crypto giveaway live',
                'ethereum event',
                'bitcoin doubling',
                f'{target_original} crypto'
            ])
        }
    
    def generate_dataset(
        self,
        num_high_risk: int = 20,
        num_medium_risk: int = 15,
        num_low_risk: int = 10,
        num_legitimate: int = 5
    ) -> List[Dict]:
        """
        Generate complete test dataset
        
        Args:
            num_high_risk: Number of high-risk detections
            num_medium_risk: Number of medium-risk detections
            num_low_risk: Number of low-risk detections
            num_legitimate: Number of legitimate channels (false positives)
        """
        dataset = []
        
        # Generate high-risk detections
        for _ in range(num_high_risk):
            dataset.append(self.generate_suspicious_detection('high'))
        
        # Generate medium-risk detections
        for _ in range(num_medium_risk):
            dataset.append(self.generate_suspicious_detection('medium'))
        
        # Generate low-risk detections
        for _ in range(num_low_risk):
            dataset.append(self.generate_suspicious_detection('low'))
        
        # Generate legitimate channels
        for _ in range(num_legitimate):
            dataset.append(self.generate_legitimate_detection())
        
        # Shuffle to mix risk levels
        random.shuffle(dataset)
        
        return dataset
    
    def save_dataset(self, filename: str, **kwargs):
        """Generate and save test dataset"""
        dataset = self.generate_dataset(**kwargs)
        
        with open(filename, 'w') as f:
            json.dump(dataset, f, indent=2)
        
        print(f"Generated {len(dataset)} test samples")
        print(f"Saved to {filename}")
        
        return dataset


def main():
    """Generate test datasets"""
    generator = TestDataGenerator()
    
    print("="*70)
    print("TEST DATA GENERATOR")
    print("="*70)
    
    # Generate small test dataset
    print("\n📊 Generating small test dataset...")
    generator.save_dataset(
        '/mnt/user-data/outputs/test_data_small.json',
        num_high_risk=10,
        num_medium_risk=8,
        num_low_risk=5,
        num_legitimate=2
    )
    
    # Generate medium test dataset
    print("\n📊 Generating medium test dataset...")
    generator.save_dataset(
        '/mnt/user-data/outputs/test_data_medium.json',
        num_high_risk=30,
        num_medium_risk=25,
        num_low_risk=15,
        num_legitimate=5
    )
    
    # Generate large test dataset
    print("\n📊 Generating large test dataset...")
    generator.save_dataset(
        '/mnt/user-data/outputs/test_data_large.json',
        num_high_risk=100,
        num_medium_risk=75,
        num_low_risk=50,
        num_legitimate=25
    )
    
    print("\n✅ Test data generation complete!")
    print("\nYou can now test the analysis script:")
    print("  python analysis.py /mnt/user-data/outputs/test_data_small.json")


if __name__ == "__main__":
    main()
