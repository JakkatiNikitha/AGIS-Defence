import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import joblib
from typing import Dict, List, Optional, Tuple, Union
import logging
from pathlib import Path
import json
from datetime import datetime

from ..config import ML_CONFIG

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """Anomaly detection model using multiple algorithms."""

    def __init__(self, model_dir: str = "models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize models
        self.isolation_forest = IsolationForest(
            **ML_CONFIG['anomaly_detection']['isolation_forest']
        )
        self.one_class_svm = OneClassSVM(
            **ML_CONFIG['anomaly_detection']['one_class_svm']
        )
        self.scaler = StandardScaler()
        
        # Track training data statistics
        self.n_samples = 0
        self.feature_names = []

    def preprocess_data(self, data: List[Dict]) -> np.ndarray:
        """Convert raw data into feature matrix."""
        features = []
        for sample in data:
            feature_vector = [
                sample.get('packet_count', 0),
                sample.get('byte_count', 0),
                len(sample.get('ports', {})),
                len(sample.get('protocols', {})),
                # Add more features as needed
            ]
            features.append(feature_vector)
        
        return np.array(features)

    def fit(self, data: List[Dict]) -> None:
        """Train the anomaly detection models."""
        if not data:
            logger.warning("No data provided for training")
            return

        # Preprocess data
        X = self.preprocess_data(data)
        self.n_samples = X.shape[0]
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train models
        logger.info("Training Isolation Forest...")
        self.isolation_forest.fit(X_scaled)
        
        logger.info("Training One-Class SVM...")
        self.one_class_svm.fit(X_scaled)
        
        # Save models
        self.save_models()

    def predict(self, data: List[Dict]) -> Tuple[List[int], List[float]]:
        """
        Predict anomalies in new data.
        Returns:
            - List of predictions (-1 for anomaly, 1 for normal)
            - List of anomaly scores
        """
        # Preprocess data
        X = self.preprocess_data(data)
        X_scaled = self.scaler.transform(X)
        
        # Get predictions from both models
        if_pred = self.isolation_forest.predict(X_scaled)
        svm_pred = self.one_class_svm.predict(X_scaled)
        
        # Get anomaly scores
        if_scores = self.isolation_forest.score_samples(X_scaled)
        svm_scores = self.one_class_svm.score_samples(X_scaled)
        
        # Combine predictions (if either model detects anomaly, mark as anomaly)
        combined_pred = np.where((if_pred == -1) | (svm_pred == -1), -1, 1)
        
        # Average the scores
        combined_scores = (if_scores + svm_scores) / 2
        
        return combined_pred.tolist(), combined_scores.tolist()

    def save_models(self) -> None:
        """Save trained models to disk."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save models
        joblib.dump(self.isolation_forest, 
                   self.model_dir / f"isolation_forest_{timestamp}.joblib")
        joblib.dump(self.one_class_svm, 
                   self.model_dir / f"one_class_svm_{timestamp}.joblib")
        joblib.dump(self.scaler, 
                   self.model_dir / f"scaler_{timestamp}.joblib")
        
        # Save metadata
        metadata = {
            'timestamp': timestamp,
            'n_samples': self.n_samples,
            'feature_names': self.feature_names,
            'config': ML_CONFIG['anomaly_detection']
        }
        
        with open(self.model_dir / f"metadata_{timestamp}.json", 'w') as f:
            json.dump(metadata, f, indent=2)

    def load_models(self, timestamp: str) -> None:
        """Load models from disk by timestamp."""
        try:
            self.isolation_forest = joblib.load(
                self.model_dir / f"isolation_forest_{timestamp}.joblib"
            )
            self.one_class_svm = joblib.load(
                self.model_dir / f"one_class_svm_{timestamp}.joblib"
            )
            self.scaler = joblib.load(
                self.model_dir / f"scaler_{timestamp}.joblib"
            )
            
            # Load metadata
            with open(self.model_dir / f"metadata_{timestamp}.json", 'r') as f:
                metadata = json.load(f)
                self.n_samples = metadata['n_samples']
                self.feature_names = metadata['feature_names']
                
            logger.info(f"Successfully loaded models from timestamp {timestamp}")
            
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
            raise

    def get_latest_model(self) -> Optional[str]:
        """Get the timestamp of the latest saved model."""
        try:
            model_files = list(self.model_dir.glob("metadata_*.json"))
            if not model_files:
                return None
            
            # Extract timestamps and get the latest
            timestamps = [f.stem.split('_')[1] for f in model_files]
            return max(timestamps)
            
        except Exception as e:
            logger.error(f"Error getting latest model: {str(e)}")
            return None

    def explain_anomaly(self, data: Dict, score: float) -> str:
        """Generate human-readable explanation for an anomaly."""
        explanations = []
        
        # Check various anomaly indicators
        if data.get('packet_count', 0) > ML_CONFIG['anomaly_detection']['thresholds']['packet_count']:
            explanations.append("Unusually high packet count")
            
        if len(data.get('ports', {})) > ML_CONFIG['anomaly_detection']['thresholds']['port_count']:
            explanations.append("Access to unusually high number of ports")
            
        if score < -0.5:  # Arbitrary threshold
            explanations.append("Significant deviation from normal behavior")
            
        if not explanations:
            explanations.append("Unknown anomaly pattern")
            
        return " | ".join(explanations)


if __name__ == "__main__":
    # Example usage
    detector = AnomalyDetector()
    
    # Example data
    sample_data = [
        {
            'packet_count': 100,
            'byte_count': 1500,
            'ports': {'80': 50, '443': 30},
            'protocols': {'TCP': 80, 'UDP': 20}
        },
        # Add more samples...
    ]
    
    # Train
    detector.fit(sample_data)
    
    # Predict
    predictions, scores = detector.predict(sample_data)
    print(f"Predictions: {predictions}")
    print(f"Scores: {scores}") 