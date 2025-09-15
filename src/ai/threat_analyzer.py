"""
AI-Powered Threat Analysis Engine
Uses machine learning to classify, predict, and analyze cybersecurity threats
"""

import asyncio
import logging
import pickle
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

from ..core.database import DatabaseManager
from ..utils.feature_extractor import FeatureExtractor

class ThreatAnalyzer:
    """AI-powered threat analysis and prediction system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.db = DatabaseManager(config)
        self.feature_extractor = FeatureExtractor()
        
        # ML Models
        self.attack_classifier = None
        self.anomaly_detector = None
        self.threat_predictor = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        # Model paths
        self.model_dir = Path("models")
        self.model_dir.mkdir(exist_ok=True)
        
        # Analysis cache
        self.recent_attacks = []
        self.threat_scores = {}
        
        # Load pre-trained models if available
        self._load_models()
        
    async def start(self):
        """Start the threat analyzer"""
        self.logger.info("🤖 Starting AI Threat Analyzer...")
        
        # Start background analysis tasks
        asyncio.create_task(self._continuous_analysis())
        asyncio.create_task(self._model_retraining())
        
        self.logger.info("✅ AI Threat Analyzer started")
        
    async def stop(self):
        """Stop the threat analyzer"""
        self.logger.info("🛑 Stopping AI Threat Analyzer...")
        
    async def analyze_attack(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single attack event"""
        try:
            # Extract features
            features = self.feature_extractor.extract_features(attack_data)
            
            # Classify attack type
            attack_type = self._classify_attack(features)
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(features, attack_data)
            
            # Detect anomalies
            is_anomaly = self._detect_anomaly(features)
            
            # Generate insights
            insights = self._generate_insights(attack_data, features, attack_type)
            
            analysis_result = {
                'attack_id': attack_data.get('id'),
                'timestamp': datetime.utcnow().isoformat(),
                'attack_type': attack_type,
                'threat_score': threat_score,
                'is_anomaly': is_anomaly,
                'confidence': self._get_confidence_score(features),
                'insights': insights,
                'recommendations': self._get_recommendations(attack_type, threat_score),
                'features': features
            }
            
            # Store analysis
            await self.db.store_analysis(analysis_result)
            
            # Update threat intelligence
            self._update_threat_intelligence(attack_data, analysis_result)
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error analyzing attack: {e}")
            return {'error': str(e)}
    
    def _classify_attack(self, features: np.ndarray) -> str:
        """Classify attack type using ML models"""
        if self.attack_classifier is None:
            return "unknown"
            
        try:
            # Scale features
            features_scaled = self.scaler.transform([features])
            
            # Predict attack type
            prediction = self.attack_classifier.predict(features_scaled)[0]
            
            # Convert back from encoded label
            attack_type = self.label_encoder.inverse_transform([prediction])[0]
            
            return attack_type
            
        except Exception as e:
            self.logger.error(f"Error classifying attack: {e}")
            return "unknown"
    
    def _calculate_threat_score(self, features: np.ndarray, attack_data: Dict) -> float:
        """Calculate threat score (0-100)"""
        try:
            base_score = 50.0
            
            # Factor in attack type severity
            attack_type_scores = {
                'brute_force': 70,
                'malware_download': 90,
                'privilege_escalation': 85,
                'data_exfiltration': 95,
                'reconnaissance': 40,
                'dos': 60,
                'injection': 80
            }
            
            attack_type = attack_data.get('type', 'unknown')
            base_score = attack_type_scores.get(attack_type, 50)
            
            # Factor in source reputation
            source_ip = attack_data.get('source_ip', '')
            if source_ip in self.threat_scores:
                reputation_modifier = self.threat_scores[source_ip] * 0.3
                base_score += reputation_modifier
            
            # Factor in attack frequency
            recent_count = len([a for a in self.recent_attacks 
                              if a.get('source_ip') == source_ip])
            frequency_modifier = min(recent_count * 5, 30)
            base_score += frequency_modifier
            
            # Factor in payload complexity
            payload = attack_data.get('payload', '')
            if len(payload) > 100:
                base_score += 10
            if any(keyword in payload.lower() for keyword in 
                   ['wget', 'curl', 'nc', 'bash', 'python', 'perl']):
                base_score += 15
            
            return min(max(base_score, 0), 100)
            
        except Exception as e:
            self.logger.error(f"Error calculating threat score: {e}")
            return 50.0
    
    def _detect_anomaly(self, features: np.ndarray) -> bool:
        """Detect if attack pattern is anomalous"""
        if self.anomaly_detector is None:
            return False
            
        try:
            features_scaled = self.scaler.transform([features])
            prediction = self.anomaly_detector.predict(features_scaled)[0]
            return prediction == -1  # -1 indicates anomaly
            
        except Exception as e:
            self.logger.error(f"Error detecting anomaly: {e}")
            return False
    
    def _generate_insights(self, attack_data: Dict, features: np.ndarray, 
                          attack_type: str) -> List[str]:
        """Generate human-readable insights about the attack"""
        insights = []
        
        try:
            # Source analysis
            source_ip = attack_data.get('source_ip', 'unknown')
            insights.append(f"Attack originated from {source_ip}")
            
            # Attack pattern analysis
            if attack_type != "unknown":
                insights.append(f"Classified as {attack_type} attack")
            
            # Timing analysis
            timestamp = attack_data.get('timestamp')
            if timestamp:
                hour = datetime.fromisoformat(timestamp.replace('Z', '')).hour
                if 22 <= hour or hour <= 6:
                    insights.append("Attack occurred during off-hours (suspicious)")
            
            # Payload analysis
            payload = attack_data.get('payload', '')
            if payload:
                if 'password' in payload.lower():
                    insights.append("Attack involves password-related activity")
                if any(cmd in payload.lower() for cmd in ['rm', 'del', 'format']):
                    insights.append("Potentially destructive commands detected")
                if 'http' in payload.lower():
                    insights.append("Network communication attempt detected")
            
            # Frequency analysis
            recent_count = len([a for a in self.recent_attacks 
                              if a.get('source_ip') == source_ip])
            if recent_count > 5:
                insights.append(f"Repeated attacks from same source ({recent_count} recent)")
            
            return insights
            
        except Exception as e:
            self.logger.error(f"Error generating insights: {e}")
            return ["Analysis insights unavailable"]
    
    def _get_recommendations(self, attack_type: str, threat_score: float) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if threat_score > 80:
            recommendations.append("🚨 HIGH THREAT: Immediate action required")
            recommendations.append("Block source IP immediately")
            recommendations.append("Review and strengthen security controls")
        elif threat_score > 60:
            recommendations.append("⚠️ MEDIUM THREAT: Monitor closely")
            recommendations.append("Consider rate limiting for source IP")
        else:
            recommendations.append("ℹ️ LOW THREAT: Continue monitoring")
        
        # Attack-specific recommendations
        attack_recommendations = {
            'brute_force': [
                "Implement account lockout policies",
                "Enable multi-factor authentication",
                "Use strong password policies"
            ],
            'malware_download': [
                "Scan systems for malware",
                "Update antivirus definitions",
                "Block malicious domains"
            ],
            'privilege_escalation': [
                "Review user permissions",
                "Audit system configurations",
                "Monitor privileged accounts"
            ],
            'reconnaissance': [
                "Review exposed services",
                "Implement network segmentation",
                "Monitor for follow-up attacks"
            ]
        }
        
        if attack_type in attack_recommendations:
            recommendations.extend(attack_recommendations[attack_type])
        
        return recommendations
    
    def _get_confidence_score(self, features: np.ndarray) -> float:
        """Calculate confidence score for the analysis"""
        if self.attack_classifier is None:
            return 0.5
            
        try:
            features_scaled = self.scaler.transform([features])
            probabilities = self.attack_classifier.predict_proba(features_scaled)[0]
            return float(np.max(probabilities))
        except:
            return 0.5
    
    def _update_threat_intelligence(self, attack_data: Dict, analysis: Dict):
        """Update threat intelligence database"""
        source_ip = attack_data.get('source_ip')
        if source_ip:
            current_score = self.threat_scores.get(source_ip, 0)
            new_score = analysis.get('threat_score', 0)
            
            # Update with weighted average
            self.threat_scores[source_ip] = (current_score * 0.7) + (new_score * 0.3)
        
        # Keep recent attacks for pattern analysis
        self.recent_attacks.append(attack_data)
        if len(self.recent_attacks) > 1000:
            self.recent_attacks = self.recent_attacks[-500:]  # Keep last 500
    
    async def _continuous_analysis(self):
        """Continuously analyze incoming attack data"""
        while True:
            try:
                # Get new attacks from database
                new_attacks = await self.db.get_unanalyzed_attacks()
                
                for attack in new_attacks:
                    await self.analyze_attack(attack)
                
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Error in continuous analysis: {e}")
                await asyncio.sleep(30)
    
    async def _model_retraining(self):
        """Periodically retrain models with new data"""
        while True:
            try:
                await asyncio.sleep(3600)  # Retrain every hour
                
                # Get training data
                training_data = await self.db.get_training_data()
                
                if len(training_data) > 100:  # Minimum data for training
                    await self._train_models(training_data)
                    self.logger.info("🔄 Models retrained with new data")
                
            except Exception as e:
                self.logger.error(f"Error in model retraining: {e}")
    
    async def _train_models(self, training_data: List[Dict]):
        """Train ML models with attack data"""
        try:
            # Prepare training data
            X, y = self._prepare_training_data(training_data)
            
            if len(X) == 0:
                return
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Encode labels
            y_train_encoded = self.label_encoder.fit_transform(y_train)
            
            # Train attack classifier (ensemble)
            rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
            mlp_classifier = MLPClassifier(hidden_layer_sizes=(100, 50), random_state=42)
            
            rf_classifier.fit(X_train_scaled, y_train_encoded)
            mlp_classifier.fit(X_train_scaled, y_train_encoded)
            
            # Use the better performing model
            rf_score = rf_classifier.score(X_test_scaled, self.label_encoder.transform(y_test))
            mlp_score = mlp_classifier.score(X_test_scaled, self.label_encoder.transform(y_test))
            
            self.attack_classifier = rf_classifier if rf_score > mlp_score else mlp_classifier
            
            # Train anomaly detector
            self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
            self.anomaly_detector.fit(X_train_scaled)
            
            # Save models
            self._save_models()
            
            self.logger.info(f"Models trained - Accuracy: {max(rf_score, mlp_score):.3f}")
            
        except Exception as e:
            self.logger.error(f"Error training models: {e}")
    
    def _prepare_training_data(self, training_data: List[Dict]) -> tuple:
        """Prepare data for ML training"""
        X = []
        y = []
        
        for attack in training_data:
            features = self.feature_extractor.extract_features(attack)
            attack_type = attack.get('type', 'unknown')
            
            if features is not None and attack_type != 'unknown':
                X.append(features)
                y.append(attack_type)
        
        return np.array(X), np.array(y)
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            joblib.dump(self.attack_classifier, self.model_dir / "attack_classifier.pkl")
            joblib.dump(self.anomaly_detector, self.model_dir / "anomaly_detector.pkl")
            joblib.dump(self.scaler, self.model_dir / "scaler.pkl")
            joblib.dump(self.label_encoder, self.model_dir / "label_encoder.pkl")
            
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")
    
    def _load_models(self):
        """Load pre-trained models from disk"""
        try:
            classifier_path = self.model_dir / "attack_classifier.pkl"
            anomaly_path = self.model_dir / "anomaly_detector.pkl"
            scaler_path = self.model_dir / "scaler.pkl"
            encoder_path = self.model_dir / "label_encoder.pkl"
            
            if all(p.exists() for p in [classifier_path, anomaly_path, scaler_path, encoder_path]):
                self.attack_classifier = joblib.load(classifier_path)
                self.anomaly_detector = joblib.load(anomaly_path)
                self.scaler = joblib.load(scaler_path)
                self.label_encoder = joblib.load(encoder_path)
                
                self.logger.info("✅ Pre-trained models loaded")
            else:
                self.logger.info("No pre-trained models found, will train on first data")
                
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
    
    async def get_threat_summary(self) -> Dict[str, Any]:
        """Get current threat landscape summary"""
        try:
            # Get recent attack statistics
            recent_attacks = await self.db.get_recent_attacks(hours=24)
            
            # Calculate statistics
            total_attacks = len(recent_attacks)
            unique_sources = len(set(a.get('source_ip') for a in recent_attacks))
            
            # Attack type distribution
            attack_types = {}
            for attack in recent_attacks:
                attack_type = attack.get('type', 'unknown')
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            # Top threat sources
            source_counts = {}
            for attack in recent_attacks:
                source = attack.get('source_ip', 'unknown')
                source_counts[source] = source_counts.get(source, 0) + 1
            
            top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Average threat score
            threat_scores = [self.threat_scores.get(a.get('source_ip'), 0) for a in recent_attacks]
            avg_threat_score = np.mean(threat_scores) if threat_scores else 0
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'total_attacks_24h': total_attacks,
                'unique_sources': unique_sources,
                'attack_types': attack_types,
                'top_threat_sources': top_sources,
                'average_threat_score': float(avg_threat_score),
                'models_trained': self.attack_classifier is not None
            }
            
        except Exception as e:
            self.logger.error(f"Error generating threat summary: {e}")
            return {'error': str(e)}