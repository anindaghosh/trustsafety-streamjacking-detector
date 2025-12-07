"""
Enhanced YouTube Stream-Jacking Detection System
Incorporates composite rules and additional detection signals

This version adds:
- Urgency language detection
- Handle-name mismatch
- Disabled chat detection
- Composite risk scoring (Critical/High/Medium)
- Known scam domain checking
- Enhanced confidence scoring
"""

import os
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import json
from dotenv import load_dotenv

load_dotenv()

try:
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print("Please install: pip install google-api-python-client --break-system-packages")
    exit(1)

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure, OperationFailure
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False
    print("⚠️  Warning: pymongo not installed. MongoDB storage disabled.")
    print("   Install with: pip install pymongo")


@dataclass
class EnhancedChannelMetadata:
    """Extended channel metadata with additional fields"""
    channel_id: str
    channel_title: str
    custom_url: Optional[str]
    handle: Optional[str]
    description: str
    subscriber_count: int
    video_count: int
    view_count: int
    published_at: str
    country: Optional[str]
    thumbnail_url: str
    
    # Additional metadata
    topic_categories: List[str] = field(default_factory=list)
    branding_settings: Dict = field(default_factory=dict)
    hidden_subscriber_count: bool = False
    default_language: Optional[str] = None
    
    # Detection results
    suspicious_signals: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    confidence_score: float = 0.0
    risk_category: str = "unknown"  # critical, high, medium, low


@dataclass
class EnhancedVideoMetadata:
    """Extended video metadata"""
    video_id: str
    title: str
    description: str
    channel_id: str
    channel_title: str
    published_at: str
    is_live: bool
    live_streaming_details: Optional[Dict]
    view_count: int
    like_count: int
    comment_count: int
    tags: List[str] = field(default_factory=list)
    
    # Additional fields
    comments_disabled: bool = False
    live_chat_id: Optional[str] = None
    default_language: Optional[str] = None
    
    # Detection results
    suspicious_signals: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    confidence_score: float = 0.0


class MongoDBManager:
    """Manages MongoDB connection and upsert operations for detection results"""
    
    def __init__(self, connection_string: Optional[str] = None, database_name: str = 'streamjacking_detector'):
        """
        Initialize MongoDB connection
        
        Args:
            connection_string: MongoDB connection URI (defaults to env var MONGODB_URI or localhost)
            database_name: Name of database to use
        """
        if not MONGODB_AVAILABLE:
            self.client = None
            self.db = None
            self.collection = None
            return
            
        try:
            # Get connection string from parameter, env var, or default to localhost
            conn_str = connection_string or os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
            
            self.client = MongoClient(conn_str, serverSelectionTimeoutMS=5000)
            # Test connection
            self.client.admin.command('ping')
            
            self.db = self.client[database_name]
            self.collection = self.db['detection_results_v2']
            
            # Create indexes for efficient querying
            self.collection.create_index('video_id', unique=True)
            self.collection.create_index('channel_id')
            self.collection.create_index('detected_at')
            self.collection.create_index('risk_category')
            self.collection.create_index([('video_id', 1), ('detected_at', -1)])
            
            print("✅ MongoDB connected successfully")
            
        except (ConnectionFailure, OperationFailure) as e:
            print(f"⚠️  MongoDB connection failed: {e}")
            print("   Detections will only be saved to JSON file")
            self.client = None
            self.db = None
            self.collection = None
    
    def upsert_detection(self, detection: Dict) -> bool:
        """
        Upsert a detection record (insert or update if video_id exists)
        
        Args:
            detection: Detection dictionary with video_id as unique identifier
            
        Returns:
            True if successful, False otherwise
        """
        if self.collection is None:
            return False
            
        try:
            # Add first_detected timestamp if new record
            detection_copy = detection.copy()
            
            # Use video_id as unique identifier
            result = self.collection.update_one(
                {'video_id': detection['video_id']},
                {
                    '$set': detection_copy,
                    '$setOnInsert': {'first_detected': detection['detected_at']},
                    '$inc': {'detection_count': 1}
                },
                upsert=True
            )
            
            return True
            
        except Exception as e:
            print(f"   ⚠️  MongoDB upsert failed: {e}")
            return False
    
    def bulk_upsert_detections(self, detections: List[Dict]) -> int:
        """
        Bulk upsert multiple detections
        
        Args:
            detections: List of detection dictionaries
            
        Returns:
            Number of successfully upserted records
        """
        if not self.collection or not detections:
            return 0
            
        success_count = 0
        for detection in detections:
            if self.upsert_detection(detection):
                success_count += 1
        
        return success_count
    
    def get_detection_stats(self) -> Dict:
        """Get statistics about stored detections"""
        if self.collection is None:
            return {}
            
        try:
            total = self.collection.count_documents({})
            critical = self.collection.count_documents({'risk_category': 'CRITICAL'})
            high = self.collection.count_documents({'risk_category': 'HIGH'})
            medium = self.collection.count_documents({'risk_category': 'MEDIUM'})
            
            return {
                'total_detections': total,
                'critical': critical,
                'high': high,
                'medium': medium
            }
        except Exception as e:
            print(f"   ⚠️  Error fetching stats: {e}")
            return {}
    
    def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()


class EnhancedYouTubeAPIClient:
    """Enhanced API client with additional metadata fields"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.youtube = build('youtube', 'v3', developerKey=api_key)
        self.quota_used = 0
        
    def get_channel_metadata(self, channel_id: str) -> Optional[EnhancedChannelMetadata]:
        """Retrieve comprehensive channel metadata with enhanced fields"""
        try:
            request = self.youtube.channels().list(
                part="snippet,statistics,contentDetails,topicDetails,brandingSettings,status",
                id=channel_id
            )
            response = request.execute()
            self.quota_used += 5
            
            if not response.get('items'):
                return None
                
            item = response['items'][0]
            snippet = item.get('snippet', {})
            statistics = item.get('statistics', {})
            branding = item.get('brandingSettings', {})
            topics = item.get('topicDetails', {})
            
            return EnhancedChannelMetadata(
                channel_id=channel_id,
                channel_title=snippet.get('title', ''),
                custom_url=snippet.get('customUrl'),
                handle=branding.get('channel', {}).get('unsubscribedTrailer'),
                description=snippet.get('description', ''),
                subscriber_count=int(statistics.get('subscriberCount', 0)),
                video_count=int(statistics.get('videoCount', 0)),
                view_count=int(statistics.get('viewCount', 0)),
                published_at=snippet.get('publishedAt', ''),
                country=snippet.get('country'),
                thumbnail_url=snippet.get('thumbnails', {}).get('high', {}).get('url', ''),
                topic_categories=topics.get('topicCategories', []),
                branding_settings=branding,
                hidden_subscriber_count=statistics.get('hiddenSubscriberCount', False),
                default_language=snippet.get('defaultLanguage')
            )
            
        except HttpError as e:
            print(f"API Error: {e}")
            return None
    
    def get_video_metadata(self, video_id: str) -> Optional[EnhancedVideoMetadata]:
        """Retrieve comprehensive video metadata with enhanced fields"""
        try:
            request = self.youtube.videos().list(
                part="snippet,statistics,liveStreamingDetails,contentDetails,status",
                id=video_id
            )
            response = request.execute()
            self.quota_used += 5
            
            if not response.get('items'):
                return None
                
            item = response['items'][0]
            snippet = item.get('snippet', {})
            statistics = item.get('statistics', {})
            live_details = item.get('liveStreamingDetails')
            status = item.get('status', {})
            
            is_live = live_details is not None and live_details.get('actualEndTime') is None
            
            return EnhancedVideoMetadata(
                video_id=video_id,
                title=snippet.get('title', ''),
                description=snippet.get('description', ''),
                channel_id=snippet.get('channelId', ''),
                channel_title=snippet.get('channelTitle', ''),
                published_at=snippet.get('publishedAt', ''),
                is_live=is_live,
                live_streaming_details=live_details,
                view_count=int(statistics.get('viewCount', 0)),
                like_count=int(statistics.get('likeCount', 0)),
                comment_count=int(statistics.get('commentCount', 0)),
                tags=snippet.get('tags', []),
                comments_disabled=not status.get('publicStatsViewable', True),
                live_chat_id=live_details.get('activeLiveChatId') if live_details else None,
                default_language=snippet.get('defaultLanguage')
            )
            
        except HttpError as e:
            print(f"API Error: {e}")
            return None
    
    def search_livestreams(self, query: str, max_results: int = 50) -> List[Dict]:
        """Search for active livestreams"""
        try:
            request = self.youtube.search().list(
                part="snippet",
                q=query,
                type="video",
                eventType="live",
                maxResults=min(max_results, 50),
                relevanceLanguage="en",
                safeSearch="none"
            )
            response = request.execute()
            self.quota_used += 100
            
            return response.get('items', [])
            
        except HttpError as e:
            print(f"API Error: {e}")
            return []


class EnhancedStreamJackingDetector:
    """
    Enhanced detector with composite rules and additional signals
    """
    
    # Character substitution patterns
    CHAR_SUBSTITUTIONS = {
        'l': ['I', '1', '|', 'ı'],
        'I': ['l', '1', '|', 'ı'],
        'O': ['0', 'Ο', 'О'],  # Latin, Greek, Cyrillic
        '0': ['O', 'Ο', 'О'],
        'a': ['@', 'α', 'а'],  # Greek alpha, Cyrillic a
        'e': ['3', 'ε', 'е'],  # Greek epsilon, Cyrillic e
        'A': ['Α', 'А'],  # Greek, Cyrillic
        'E': ['Ε', 'Е'],
    }
    
    # Impersonation targets
    CRYPTO_FIGURES = [
        'elon musk', 'vitalik buterin', 'michael saylor', 'cz', 'changpeng zhao',
        'brian armstrong', 'cathie wood', 'vitalik', 'buterin'
    ]
    
    TECH_BRANDS = [
        'tesla', 'spacex', 'apple', 'microsoft', 'nvidia', 'google', 'meta',
        'amazon', 'openai'
    ]
    
    CRYPTO_PROJECTS = [
        'ethereum', 'bitcoin', 'binance', 'coinbase', 'ripple', 'cardano',
        'solana', 'polygon'
    ]
    
    # Short crypto terms that need whole-word matching to avoid false positives
    SHORT_CRYPTO_TERMS = ['eth', 'btc', 'bnb', 'ada', 'sol', 'xrp']
    
    # Scam keywords
    SCAM_KEYWORDS = [
        'giveaway', 'double', 'send', 'receive', 'btc', 'eth', 'cryptocurrency',
        'free crypto', 'investment', 'wallet', 'airdrop', 'bonus'
    ]
    
    # NEW: Urgency keywords (from teammate's document)
    URGENCY_KEYWORDS = [
        'live now', 'ending soon', 'limited time', 'hurry', 'last chance',
        'only today', 'expires', 'don\'t miss', 'act now', 'urgent'
    ]
    
    # NEW: High-confidence scam phrases
    HIGH_CONFIDENCE_SCAM_PHRASES = [
        r'send\s+\d+.*get\s+\d+.*back',
        r'double\s+your\s+(btc|eth|crypto)',
        r'guaranteed\s+returns?',
        r'limited\s+time\s+crypto\s+giveaway',
        r'elon\s+musk\s+(live\s+)?giveaway',
        r'send\s+\d+\s+(btc|eth).*receive\s+\d+',
    ]
    
    # NEW: Known scam domains (expand this list)
    # Only flag if combined with other signals - these are too generic alone
    KNOWN_SCAM_DOMAINS = [
        'telegra.ph', 'tiny.cc', 'is.gd' # Less common shorteners often used by scammers
    ]
    
    # Generic promotional domains - only flag if combined with impersonation
    PROMO_DOMAINS = ['gift', 'bonus', 'promo']

    # NEW: Trusted channels (whitelist) to prevent false positives
    TRUSTED_CHANNELS = [
        'UCUMZ7gohGI9pU35BDk8lfVA', # Bloomberg Markets and Finance
        'UCEAZeUIeJs0IjQiqTCdVSIg', # Yahoo Finance
        'UC4R8DWoMoI7CAwX8_LjQHig', # LiveNOW from FOX
        'UCW39zufHfsuGgpLviKh297Q', # DW News
        'UCvJJ_dzjViJCoLf5uKUTwoA', # CNBC
        'UCBi2mrWuNuyYy4gbM6fU18Q', # ABC News
        'UCXIJgqnII2ZOINSWNOGFThg', # Fox News
        'UC16niRr50-MSBwiO3YDb3RA', # BBC News
        'UChOcfkM4395an2d_i539-HQ', # CoinDesk
        'UCFwMITSkc1Fms6PoJoh1OUQ', # LabPadre Space
        'UCWCEYVwSqr7Epo6sSCfUgiw', # MIRROR NOW
        'UC9-uZt8l6LaZUKuuEz6VF6w', # Day Trading with Matt
    ]

    # NEW: Educational/News intent keywords (reduces risk)
    EDUCATIONAL_KEYWORDS = [
        'analysis', 'market update', 'trading strategy', 'technical analysis',
        'chart', 'forecast', 'prediction', 'news', 'interview', 'documentary',
        'review', 'tutorial', 'explained', 'breakdown', 'discussion', 'panel',
        'conference', 'summit', 'podcast', 'signals', 'liquidation', 'watchlist',
        'trader', 'trading', 'ta ', 'swing', 'day trading', 'price action'
    ]
    
    # Crypto-native channel indicators (channels naturally focused on crypto)
    CRYPTO_NATIVE_INDICATORS = [
        'crypto', 'bitcoin', 'ethereum', 'blockchain', 'trading', 'trader',
        'defi', 'nft', 'altcoin', 'hodl'
    ]
    
    # NEW: Topic categories mapping (Wikipedia URL suffix -> Category)
    TOPIC_MAPPING = {
        'Video_game_culture': 'Gaming',
        'Action_game': 'Gaming',
        'Role-playing_video_game': 'Gaming',
        'Strategy_video_game': 'Gaming',
        'Music': 'Music',
        'Pop_music': 'Music',
        'Rock_music': 'Music',
        'Hip_hop_music': 'Music',
        'Film': 'Entertainment',
        'Entertainment': 'Entertainment',
        'Lifestyle_(sociology)': 'Lifestyle',
        'Fashion': 'Lifestyle',
        'Beauty': 'Lifestyle',
        'Food': 'Lifestyle',
        'Technology': 'Tech',
        'Society': 'Society',
        'Knowledge': 'Education'
    }
    
    def __init__(self, api_client: EnhancedYouTubeAPIClient):
        self.api = api_client
        
    def detect_character_substitution(self, text: str, target_names: List[str]) -> List[str]:
        """Enhanced character substitution detection with whole-word matching for short terms"""
        detections = []
        text_lower = text.lower()
        
        for target in target_names:
            target_lower = target.lower()
            
            if target_lower in text_lower:
                detections.append(f"Exact match: {target}")
                continue
            
            variations = self._generate_substitution_variations(target_lower)
            
            for variation in variations:
                if variation in text_lower:
                    detections.append(f"Substitution impersonation: {target}")
                    break
        
        # Check short crypto terms with whole-word boundary
        import re
        for term in self.SHORT_CRYPTO_TERMS:
            # Match only as complete word (surrounded by non-alphanumeric)
            pattern = r'\b' + re.escape(term) + r'\b'
            if re.search(pattern, text_lower, re.IGNORECASE):
                detections.append(f"Exact match: {term}")
        
        return detections
    
    def _generate_substitution_variations(self, text: str, max_variations: int = 100) -> Set[str]:
        """Generate character substitution variations"""
        variations = {text}
        
        for char, substitutes in self.CHAR_SUBSTITUTIONS.items():
            if char in text:
                new_variations = set()
                for variation in list(variations):
                    for substitute in substitutes:
                        new_var = variation.replace(char, substitute)
                        new_variations.add(new_var)
                        if len(variations) + len(new_variations) >= max_variations:
                            return variations.union(new_variations)
                variations.update(new_variations)
        
        return variations
    
    def detect_urgency_language(self, text: str) -> Tuple[bool, List[str]]:
        """NEW: Detect urgency/pressure language"""
        text_lower = text.lower()
        found_keywords = [kw for kw in self.URGENCY_KEYWORDS if kw in text_lower]
        return len(found_keywords) > 0, found_keywords
    
    def detect_high_confidence_scam_phrases(self, text: str) -> Tuple[bool, List[str]]:
        """NEW: Detect high-confidence scam phrases"""
        text_lower = text.lower()
        found_phrases = []
        
        for pattern in self.HIGH_CONFIDENCE_SCAM_PHRASES:
            if re.search(pattern, text_lower):
                found_phrases.append(pattern)
        
        return len(found_phrases) > 0, found_phrases
    
    def check_handle_name_mismatch(self, channel_title: str, custom_url: Optional[str]) -> bool:
        """NEW: Check if handle doesn't match channel name"""
        if not custom_url:
            return False
        
        # Extract handle from custom URL
        handle = custom_url.lower().replace('@', '').replace('/', '')
        title_normalized = channel_title.lower().replace(' ', '').replace('-', '')
        
        # Check if they're significantly different
        # Using simple string similarity
        if handle not in title_normalized and title_normalized not in handle:
            # Check if both contain brand names
            all_brands = self.CRYPTO_FIGURES + self.TECH_BRANDS + self.CRYPTO_PROJECTS
            handle_has_brand = any(brand.replace(' ', '') in handle for brand in all_brands)
            title_has_brand = any(brand.replace(' ', '') in title_normalized for brand in all_brands)
            
            # Mismatch is suspicious if title has brand but handle doesn't
            if title_has_brand and not handle_has_brand:
                return True
        
        return False
    
    def check_known_scam_domains(self, text: str) -> Tuple[bool, List[str]]:
        """NEW: Check for known scam domains"""
        found_domains = []
        text_lower = text.lower()
        
        for domain in self.KNOWN_SCAM_DOMAINS:
            if domain in text_lower:
                found_domains.append(domain)
        
        return len(found_domains) > 0, found_domains
    
    def _map_topic_url(self, url: str) -> str:
        """Map Wikipedia topic URL to simple category"""
        if not url:
            return 'Unknown'
        
        # Extract the last part of the URL
        topic = url.split('/')[-1]
        return self.TOPIC_MAPPING.get(topic, topic)

    def analyze_channel_enhanced(self, channel: EnhancedChannelMetadata) -> EnhancedChannelMetadata:
        """Enhanced channel analysis with composite scoring"""
        signals = []
        risk_score = 0.0
        
        # NEW: Whitelist check
        if channel.channel_id in self.TRUSTED_CHANNELS:
            channel.suspicious_signals = ["Trusted Channel (Whitelisted)"]
            channel.risk_score = 0.0
            channel.risk_category = "LOW"
            return channel
        
        all_targets = self.CRYPTO_FIGURES + self.TECH_BRANDS + self.CRYPTO_PROJECTS
        
        # Signal 1: Character substitution (weight: 30)
        impersonations = self.detect_character_substitution(channel.channel_title, all_targets)
        if impersonations:
            signals.append(f"Name impersonation: {', '.join(impersonations)}")
            risk_score += 30.0
        
        # Signal 2: Handle-name mismatch (NEW - weight: 25)
        if self.check_handle_name_mismatch(channel.channel_title, channel.custom_url):
            signals.append("Handle-name mismatch (possible hijack)")
            risk_score += 25.0
        
        # Signal 3: Account age vs. activity (weight: 20)
        account_age_days = self._calculate_account_age(channel.published_at)
        
        if account_age_days > 365 and channel.video_count < 10:
            signals.append(f"Old account ({account_age_days} days) with minimal content")
            risk_score += 20.0
        
        # Signal 4: High subscribers, low content (weight: 20)
        if channel.subscriber_count > 10000 and channel.video_count < 5:
            signals.append(f"High subscribers ({channel.subscriber_count:,}) but minimal content")
            risk_score += 20.0
        
        # Signal 5: Subscriber count hiding (NEW - weight: 10)
        if channel.hidden_subscriber_count:
            signals.append("Subscriber count hidden")
            risk_score += 10.0
        
        # Signal 6: Crypto-heavy description (weight: 10)
        desc_lower = channel.description.lower()
        crypto_keywords = ['crypto', 'bitcoin', 'ethereum', 'wallet', 'giveaway', 'btc', 'eth']
        crypto_mentions = sum(1 for kw in crypto_keywords if kw in desc_lower)
        
        if crypto_mentions >= 3:
            signals.append(f"Crypto-heavy description ({crypto_mentions} keywords)")
            risk_score += 10.0
        
        # Signal 7: Known scam domains (NEW - weight: 15)
        # Only flag generic promo domains if there's also impersonation
        has_scam_domain, domains = self.check_known_scam_domains(channel.description)
        has_promo_domain = any(d in channel.description.lower() for d in self.PROMO_DOMAINS)
        
        if has_scam_domain:
            signals.append(f"Known scam domain(s): {', '.join(domains)}")
            risk_score += 15.0
        elif has_promo_domain and impersonations:  # Only flag promo if also impersonating
            signals.append(f"Promotional domain with impersonation")
            risk_score += 10.0
            
        # Signal 8: Topic Consistency / Hijack Detection (NEW - weight: 40)
        # Check if a non-tech/finance channel is posting crypto content WITH impersonation
        channel_topics = [self._map_topic_url(t) for t in channel.topic_categories]
        safe_topics = {'Gaming', 'Music', 'Entertainment', 'Lifestyle'}
        
        # Only flag topic mismatch if there's ALSO impersonation (indicates hijack vs natural giveaway)
        if channel_topics and any(t in safe_topics for t in channel_topics) and \
           not any(t in {'Tech', 'Society', 'Knowledge'} for t in channel_topics) and \
           impersonations:  # CRITICAL: Require impersonation to confirm hijack
            signals.append(f"Topic Mismatch (Possible Hijack): {', '.join(channel_topics)} channel streaming crypto")
            risk_score += 40.0
        
        channel.suspicious_signals = signals
        channel.risk_score = min(risk_score, 100.0)
        
        return channel
    
    def analyze_video_enhanced(self, video: EnhancedVideoMetadata) -> EnhancedVideoMetadata:
        """Enhanced video analysis with composite scoring"""
        signals = []
        risk_score = 0.0
        
        all_targets = self.CRYPTO_FIGURES + self.TECH_BRANDS + self.CRYPTO_PROJECTS
        
        # NEW: Intent Classification
        title_lower = video.title.lower()
        desc_lower = video.description.lower()
        combined = title_lower + ' ' + desc_lower
        channel_lower = video.channel_title.lower()
        
        educational_score = sum(1 for kw in self.EDUCATIONAL_KEYWORDS if kw in combined)
        scam_score = sum(1 for kw in self.SCAM_KEYWORDS if kw in combined)
        
        # Check if channel is crypto-native (naturally uses crypto terms)
        is_crypto_native = any(indicator in channel_lower for indicator in self.CRYPTO_NATIVE_INDICATORS)
        
        is_educational = educational_score > scam_score or is_crypto_native
        # Signal 1: Title impersonation (weight: 25)
        # REFINED: Only flag if exact match is NOT just a subject mention
        # e.g. "SpaceX Launch" is fine, but "SpaceX Official" is suspicious
        title_impersonations = self.detect_character_substitution(video.title, all_targets)
        if title_impersonations:
            # Check if it's likely just a subject mention
            is_subject_mention = False
            for imp in title_impersonations:
                if "Exact match" in imp:
                    # If it's an exact match, check for "Official" or "Live" claims to confirm impersonation
                    if not any(kw in video.title.lower() for kw in ['official', 'giveaway', 'gift']):
                        is_subject_mention = True
            
            if not is_subject_mention:
                signals.append(f"Title impersonation: {', '.join(title_impersonations)}")
                risk_score += 25.0
        
        # Signal 2: High-confidence scam phrases (NEW - weight: 35)
        has_scam_phrase, phrases = self.detect_high_confidence_scam_phrases(video.title + ' ' + video.description)
        if has_scam_phrase:
            signals.append(f"High-confidence scam phrase detected")
            risk_score += 35.0
        
        # Signal 3: Scam keywords (weight: 15)
        # Filter out 'btc'/'eth' if channel is crypto-native
        scam_matches = [kw for kw in self.SCAM_KEYWORDS if kw in combined]
        if is_crypto_native:
            # Remove generic crypto terms for crypto-native channels
            scam_matches = [kw for kw in scam_matches if kw not in ['btc', 'eth', 'cryptocurrency']]
        
        if len(scam_matches) >= 2:
            signals.append(f"Multiple scam keywords: {', '.join(scam_matches[:3])}")
            risk_score += 15.0
        
        # Signal 4: Urgency language (NEW - weight: 10)
        has_urgency, urgency_words = self.detect_urgency_language(combined)
        if has_urgency and len(urgency_words) >= 2:
            # Only penalize urgency if not educational
            if not is_educational:
                signals.append(f"Urgency language: {', '.join(urgency_words[:2])}")
                risk_score += 10.0
        
        # Signal 5: Crypto addresses/URLs (weight: 25)
        if self._contains_crypto_address(video.description) or self._contains_suspicious_url(video.description):
            signals.append("Contains crypto address or suspicious URL")
            risk_score += 25.0
        
        # Signal 6: Disabled comments (NEW - weight: 20)
        if video.comments_disabled:
            signals.append("Comments disabled or restricted")
            risk_score += 20.0
        
        # Signal 7: Live stream status (weight: 5)
        if video.is_live:
            signals.append("Currently live streaming")
            risk_score += 5.0
        
        # Signal 8: Engagement anomalies (weight: 15)
        # REFINED: Exception for 24/7 cams
        is_247_cam = any(kw in video.title.lower() for kw in ['cam', '24/7', 'sentinel', 'rover', 'live view'])
        if video.view_count > 1000 and video.comment_count < 10 and not is_247_cam:
            signals.append(f"High views ({video.view_count:,}) but very low engagement")
            risk_score += 15.0
        
        # Signal 9: Known scam domains (NEW - weight: 15)
        has_scam_domain, domains = self.check_known_scam_domains(video.description)
        has_promo_domain = any(d in video.description.lower() for d in self.PROMO_DOMAINS)
        
        if has_scam_domain:
            signals.append(f"Suspicious domain(s): {', '.join(domains)}")
            risk_score += 15.0
        elif has_promo_domain and not is_crypto_native:  # Only flag promo for non-crypto channels
            signals.append(f"Promotional domain (unusual for channel type)")
            risk_score += 10.0
            
        # NEW: Educational Intent Bonus
        if is_educational:
            signals.append(f"Educational/News intent detected (Risk reduced)")
            risk_score = max(0.0, risk_score - 30.0)
        
        video.suspicious_signals = signals
        video.risk_score = min(risk_score, 100.0)
        
        return video
    def apply_composite_rules(
        self,
        video: EnhancedVideoMetadata,
        channel: Optional[EnhancedChannelMetadata]
    ) -> Dict[str, any]:
        """
        NEW: Apply composite detection rules for categorization
        Based on teammate's document section 6
        """
        # NEW: Whitelist check
        if channel and channel.channel_id in self.TRUSTED_CHANNELS:
             return {
                'risk_category': "LOW",
                'confidence_score': 1.0,
                'total_risk_score': 0.0,
                'critical_checks_passed': 0,
                'meets_critical_criteria': False
            }

        # Calculate combined risk
        total_risk = video.risk_score
        if channel:
            total_risk += (channel.risk_score * 0.5)
        
        total_risk = min(total_risk, 100.0)
        
        # Check critical risk criteria (all must be true)
        critical_checks = [
            video.is_live,  # Currently live
            self._contains_crypto_address(video.description),  # Wallet address
            len(self.detect_character_substitution(
                channel.channel_title if channel else '', 
                self.CRYPTO_FIGURES + self.TECH_BRANDS + self.CRYPTO_PROJECTS
            )) > 0,  # Channel impersonation
            video.comments_disabled,  # Comments disabled
            any(kw in video.title.lower() + video.description.lower() 
                for kw in ['crypto', 'giveaway', 'double', 'send'])  # Scam keywords
        ]
        
        # Determine risk category
        if all(critical_checks):
            risk_category = "CRITICAL"
            confidence = 0.95
        elif total_risk >= 70:
            risk_category = "HIGH"
            confidence = 0.75 + (total_risk - 70) / 100  # 0.75-0.90
        elif total_risk >= 40:
            risk_category = "MEDIUM"
            confidence = 0.50 + (total_risk - 40) / 100  # 0.50-0.75
        else:
            risk_category = "LOW"
            confidence = total_risk / 100  # 0.00-0.40
        
        return {
            'risk_category': risk_category,
            'confidence_score': round(confidence, 2),
            'total_risk_score': round(total_risk, 1),
            'critical_checks_passed': sum(critical_checks),
            'meets_critical_criteria': all(critical_checks)
        }
    
    def _calculate_account_age(self, published_at: str) -> int:
        """Calculate account age in days"""
        try:
            pub_date = datetime.fromisoformat(published_at.replace('Z', '+00:00'))
            age = datetime.now(pub_date.tzinfo) - pub_date
            return age.days
        except:
            return 0
    
    def _contains_crypto_address(self, text: str) -> bool:
        """Check for cryptocurrency addresses"""
        # BTC, ETH, and other common patterns
        patterns = [
            r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}',  # BTC
            r'0x[a-fA-F0-9]{40}',  # ETH
            r'bc1[a-z0-9]{39,59}',  # BTC Bech32
        ]
        
        for pattern in patterns:
            if re.search(pattern, text):
                return True
        return False
    def _contains_suspicious_url(self, text: str) -> bool:
        """Check for suspicious URLs"""
        # Only flag if combined with scam keywords in the same text block
        suspicious_patterns = [
            r'bit\.ly',
            r'tinyurl',
            r'goo\.gl',
            r't\.co',
            r'ow\.ly',
        ]
        
        text_lower = text.lower()
        has_shortener = any(re.search(p, text, re.IGNORECASE) for p in suspicious_patterns)
        
        if not has_shortener:
            return False
            
        # Only return True if shortener is present AND scam keywords are nearby
        scam_context = any(kw in text_lower for kw in ['giveaway', 'double', 'free', 'bonus', 'elon', 'tesla'])
        return scam_context


def main():
    """Run the enhanced detector"""
    print("="*70)
    print("ENHANCED STREAM-JACKING DETECTION SYSTEM")
    print("With Composite Rules & Additional Signals")
    print("="*70)
    
    api_key = os.environ.get('YOUTUBE_API_KEY')
    if not api_key:
        print("\n❌ Error: YOUTUBE_API_KEY environment variable not set")
        print("Please set your API key: export YOUTUBE_API_KEY='your-key-here'")
        print("\nGet your key from: https://console.cloud.google.com")
        return
    
    # Initialize enhanced system
    api_client = EnhancedYouTubeAPIClient(api_key)
    detector = EnhancedStreamJackingDetector(api_client)
    
    # Initialize MongoDB (optional - will gracefully degrade if unavailable)
    mongo_manager = MongoDBManager(database_name='streamjacking') if MONGODB_AVAILABLE else None
    
    print("\n✅ Enhanced detector initialized (16 signals)")
    print("\nNew features vs original:")
    print("  • Urgency language detection")
    print("  • High-confidence scam phrase matching")
    print("  • Handle-name mismatch detection")
    print("  • Disabled comments checking")
    print("  • Known scam domain database")
    print("  • Composite risk scoring (Critical/High/Medium/Low)")
    
    # Define search queries targeting common scam patterns
    search_queries = [
        # Elon Musk (6 queries)
        "Elon Musk crypto live",
        "Elon Musk Bitcoin giveaway",
        "Elon Musk Bitcoin live",
        "Elon Musk ETH giveaway",
        "Elon Musk Dogecoin",
        "Elon Musk cryptocurrency",
        
        # Tesla/SpaceX (5 queries)
        "Tesla crypto live",
        "Tesla Bitcoin giveaway",
        "Tesla crypto event",
        "SpaceX Bitcoin live",
        "SpaceX crypto event",
        
        # Generic giveaways (7 queries)
        "crypto giveaway live",
        "Bitcoin giveaway live",
        "Ethereum giveaway live",
        "cryptocurrency giveaway",
        "BTC giveaway live",
        "ETH giveaway live",
        "crypto live giveaway",
        
        # Bitcoin specific (6 queries)
        "Bitcoin live",
        "Bitcoin doubling",
        "Bitcoin investment live",
        "send BTC receive double",
        "BTC live event",
        "double your Bitcoin",
        
        # Ethereum (6 queries)
        "Ethereum live",
        "Ethereum giveaway",
        "ETH doubling event",
        "Vitalik Buterin ethereum",
        "Vitalik ethereum giveaway",
        "Vitalik Buterin live",
        
        # Crypto figures (10 queries)
        "Michael Saylor Bitcoin",
        "Michael Saylor crypto live",
        "Cathie Wood Bitcoin",
        "Cathie Wood crypto live",
        "CZ Binance live",
        "Changpeng Zhao crypto",
        "Brad Garlinghouse XRP",
        "Charles Hoskinson Cardano",
        "Jack Dorsey Bitcoin",
        "Do Kwon Terra",
        
        # Crypto exchanges (6 queries)
        "Coinbase giveaway live",
        "Binance live event",
        "Kraken crypto giveaway",
        "Crypto.com giveaway",
        "Bybit giveaway live",
        "Gemini crypto live",
        
        # Other cryptos (10 queries)
        "Dogecoin live",
        "Ripple XRP giveaway",
        "Cardano ADA live",
        "Solana SOL giveaway",
        "Shiba Inu giveaway",
        "Binance BNB live",
        "Polygon MATIC giveaway",
        "Avalanche AVAX giveaway",
        "Chainlink LINK giveaway",
        "Polkadot DOT giveaway",
        
        # DeFi/NFT/Web3 (5 queries)
        "crypto airdrop live",
        "NFT giveaway live",
        "DeFi giveaway live",
        "token airdrop live",
        "Web3 giveaway",
        
        # News channels for FP testing (5 queries)
        "Bloomberg crypto live",
        "CNBC Bitcoin live",
        "CoinDesk live",
        "Cointelegraph live",
        "Fox Business crypto",
        
        # Urgency patterns (5 queries)
        "crypto ending soon",
        "limited time crypto",
        "exclusive crypto event",
        "last chance Bitcoin",
        "crypto presale live"
    ]
    
    print(f"\n📊 Monitoring {len(search_queries)} search queries...")
    print(f"⚠️  This will use approximately {len(search_queries) * 100 + 500} API quota units")
    print("⏱️  Estimated time: 15-30 minutes\n")
    
    # Collect all results
    all_results = []
    failed_queries = []
    processed_videos = 0
    failed_videos = 0

    for query_idx, query in enumerate(search_queries, 1):
        try:
            print(f"\n🔍 [{query_idx}/{len(search_queries)}] Searching for: '{query}'")

            # Search for live streams
            try:
                livestreams = api_client.search_livestreams(query, max_results=10)
                
                print(f"   Found {len(livestreams)} live streams")
            except Exception as e:
                print(f"   ⚠️  Search failed: {str(e)}")
                failed_queries.append({'query': query, 'error': str(e)})
                continue

            if not livestreams:
                continue

            for stream_idx, stream in enumerate(livestreams, 1):
                try:
                    # Extract video ID safely
                    if 'id' not in stream or 'videoId' not in stream['id']:
                        print(f"   ⚠️  Stream {stream_idx}: Missing video ID, skipping")
                        failed_videos += 1
                        continue

                    video_id = stream['id']['videoId']

                    # Get detailed metadata
                    try:
                        video_meta = api_client.get_video_metadata(video_id)
                        if not video_meta:
                            print(f"   ⚠️  Stream {stream_idx}: Could not fetch video metadata for {video_id}")
                            failed_videos += 1
                            continue
                    except Exception as e:
                        print(f"   ⚠️  Stream {stream_idx}: Error fetching video metadata: {str(e)}")
                        failed_videos += 1
                        continue

                    # Get channel metadata
                    channel_meta = None
                    try:
                        channel_meta = api_client.get_channel_metadata(video_meta.channel_id)
                        if not channel_meta:
                            print(f"   ⚠️  Stream {stream_idx}: Could not fetch channel metadata, continuing without it")
                    except Exception as e:
                        print(f"   ⚠️  Stream {stream_idx}: Error fetching channel metadata: {str(e)}, continuing without it")

                    # Analyze video
                    try:
                        analyzed_video = detector.analyze_video_enhanced(video_meta)
                    except Exception as e:
                        print(f"   ⚠️  Stream {stream_idx}: Error analyzing video: {str(e)}")
                        failed_videos += 1
                        continue

                    # Analyze channel
                    analyzed_channel = None
                    if channel_meta:
                        try:
                            analyzed_channel = detector.analyze_channel_enhanced(channel_meta)
                        except Exception as e:
                            print(f"   ⚠️  Stream {stream_idx}: Error analyzing channel: {str(e)}, continuing without channel analysis")

                    # Apply composite rules
                    try:
                        composite = detector.apply_composite_rules(analyzed_video, analyzed_channel)
                    except Exception as e:
                        print(f"   ⚠️  Stream {stream_idx}: Error applying composite rules: {str(e)}")
                        failed_videos += 1
                        continue

                    processed_videos += 1

                    # Store results if suspicious (risk >= 30)
                    if composite['total_risk_score'] >= 30:
                        result = {
                            'video_id': video_id,
                            'video_title': analyzed_video.title,
                            'channel_id': video_meta.channel_id,
                            'channel_title': video_meta.channel_title,
                            'is_live': analyzed_video.is_live,
                            'video_risk_score': analyzed_video.risk_score,
                            'channel_risk_score': analyzed_channel.risk_score if analyzed_channel else 0,
                            'total_risk_score': composite['total_risk_score'],
                            'risk_category': composite['risk_category'],
                            'confidence_score': composite['confidence_score'],
                            'video_signals': analyzed_video.suspicious_signals,
                            'channel_signals': analyzed_channel.suspicious_signals if analyzed_channel else [],
                            'detected_at': datetime.now().isoformat(),
                            'search_query': query,
                            'video_url': f"https://youtube.com/watch?v={video_id}",
                            'channel_url': f"https://youtube.com/channel/{video_meta.channel_id}"
                        }

                        all_results.append(result)
                        
                        # Upsert to MongoDB
                        if mongo_manager:
                            mongo_manager.upsert_detection(result)

                        # Show in terminal
                        risk_emoji = "🔴" if composite['risk_category'] in ['CRITICAL', 'HIGH'] else "🟡" if composite['risk_category'] == 'MEDIUM' else "🟢"
                        print(f"\n   {risk_emoji} {composite['risk_category']}: {video_meta.title[:60]}...")
                        print(f"       Risk Score: {composite['total_risk_score']:.1f} (Confidence: {composite['confidence_score']:.2f})")
                        print(f"       Channel: {video_meta.channel_title}")
                        print(f"       Signals: {len(analyzed_video.suspicious_signals) + (len(analyzed_channel.suspicious_signals) if analyzed_channel else 0)}")

                    # Rate limiting
                    time.sleep(0.5)

                except Exception as e:
                    print(f"   ⚠️  Stream {stream_idx}: Unexpected error: {str(e)}")
                    failed_videos += 1
                    continue

        except Exception as e:
            print(f"   ❌ Query failed with unexpected error: {str(e)}")
            failed_queries.append({'query': query, 'error': str(e)})
            continue
    
    # Save results - ensure directory exists
    output_file = 'data/results/streamjacking_detection_results.json'
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    try:
        with open(output_file, 'w') as f:
            json.dump({
                'results': all_results,
                'metadata': {
                    'total_queries': len(search_queries),
                    'failed_queries': len(failed_queries),
                    'processed_videos': processed_videos,
                    'failed_videos': failed_videos,
                    'total_detections': len(all_results),
                    'api_quota_used': api_client.quota_used,
                    'scan_completed_at': datetime.now().isoformat()
                },
                'failed_queries': failed_queries
            }, f, indent=2)
        print(f"\n💾 Results saved to {output_file}")
    except Exception as e:
        print(f"\n❌ Error saving results to {output_file}: {str(e)}")
        # Try to save to backup location
        backup_file = 'streamjacking_results_backup.json'
        try:
            with open(backup_file, 'w') as f:
                json.dump({
                    'results': all_results,
                    'metadata': {
                        'total_queries': len(search_queries),
                        'failed_queries': len(failed_queries),
                        'processed_videos': processed_videos,
                        'failed_videos': failed_videos,
                        'total_detections': len(all_results),
                        'api_quota_used': api_client.quota_used,
                        'scan_completed_at': datetime.now().isoformat()
                    },
                    'failed_queries': failed_queries
                }, f, indent=2)
            print(f"💾 Results saved to backup location: {backup_file}")
        except Exception as e2:
            print(f"❌ Could not save to backup location either: {str(e2)}")
            print(f"\nResults summary: {len(all_results)} detections found")
    
    # Print summary
    print("\n" + "="*70)
    print("DETECTION SUMMARY")
    print("="*70)
    print(f"Total queries attempted: {len(search_queries)}")
    print(f"Failed queries: {len(failed_queries)}")
    print(f"Videos processed successfully: {processed_videos}")
    print(f"Videos failed to process: {failed_videos}")
    print(f"Total suspicious detections: {len(all_results)}")
    print(f"API quota used: {api_client.quota_used} units")
    
    if all_results:
        # Risk distribution
        critical = sum(1 for r in all_results if r['risk_category'] == 'CRITICAL')
        high = sum(1 for r in all_results if r['risk_category'] == 'HIGH')
        medium = sum(1 for r in all_results if r['risk_category'] == 'MEDIUM')
        low = sum(1 for r in all_results if r['risk_category'] == 'LOW')
        
        print(f"\nRisk Distribution:")
        print(f"  🔴 CRITICAL: {critical}")
        print(f"  🔴 HIGH:     {high}")
        print(f"  🟡 MEDIUM:   {medium}")
        print(f"  🟢 LOW:      {low}")
        
        # Most common signals
        all_signals = []
        for result in all_results:
            all_signals.extend(result['video_signals'])
            all_signals.extend(result['channel_signals'])
        
        if all_signals:
            from collections import Counter
            signal_counts = Counter(all_signals)
            print(f"\nMost Common Signals:")
            for signal, count in signal_counts.most_common(5):
                print(f"  • {signal}: {count}")
        
        # Save high-risk channels separately
        high_risk = [r for r in all_results if r['risk_category'] in ['CRITICAL', 'HIGH']]
        if high_risk:
            high_risk_file = 'data/results/high_risk_channels.json'
            try:
                os.makedirs(os.path.dirname(high_risk_file), exist_ok=True)
                with open(high_risk_file, 'w') as f:
                    json.dump(high_risk, f, indent=2)
                print(f"\n💾 High-risk channels saved to {high_risk_file}")
            except Exception as e:
                print(f"\n⚠️  Could not save high-risk channels: {str(e)}")
    
    # Print MongoDB stats if available
    if mongo_manager:
        print("\n" + "="*70)
        print("MONGODB STORAGE")
        print("="*70)
        stats = mongo_manager.get_detection_stats()
        if stats:
            print(f"Total detections in database: {stats.get('total_detections', 0)}")
            print(f"  🔴 CRITICAL: {stats.get('critical', 0)}")
            print(f"  🔴 HIGH:     {stats.get('high', 0)}")
            print(f"  🟡 MEDIUM:   {stats.get('medium', 0)}")
        mongo_manager.close()
    
    print("\n✅ Detection complete!")
    print("\nNext step: Run analysis")
    print(f"  python analysis.py {output_file}")
    print("="*70)


if __name__ == "__main__":
    main()