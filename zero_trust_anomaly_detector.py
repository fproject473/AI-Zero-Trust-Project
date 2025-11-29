"""
Zero Trust Anomaly Detection System
Simple Isolation Forest implementation for log analysis
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

class ZeroTrustAnomalyDetector:
    """
    Anomaly detection for Zero Trust security monitoring
    """

    def __init__(self, contamination=0.1, random_state=42):
        """
        Initialize the detector

        Args:
            contamination: Expected proportion of anomalies (default 0.1 = 10%)
            random_state: Random seed for reproducibility
        """
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def prepare_data(self, df):
        """
        Prepare data for anomaly detection
        """
        # Select numerical columns only
        numerical_cols = df.select_dtypes(include=[np.number]).columns

        if len(numerical_cols) == 0:
            raise ValueError("No numerical columns found in dataframe")

        return df[numerical_cols]

    def fit_predict(self, df):
        """
        Train model and predict anomalies

        Returns:
            DataFrame with anomaly scores and predictions
        """
        # Prepare data
        X = self.prepare_data(df)

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Fit and predict
        predictions = self.model.fit_predict(X_scaled)

        # Get anomaly scores (more negative = more anomalous)
        scores = self.model.score_samples(X_scaled)

        # Add results to dataframe
        result_df = df.copy()
        result_df['anomaly_score'] = scores
        result_df['is_anomaly'] = predictions  # -1 = anomaly, 1 = normal
        result_df['anomaly_label'] = r
