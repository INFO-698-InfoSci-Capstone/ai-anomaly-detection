
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.decomposition import PCA
import numpy as np

def pca_anomaly_detector(df, numerical_features, categorical_features, variance_retained=0.95, anomaly_percentile=95):
    df = df.copy()

    # Encode categorical features
    for col in categorical_features:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))

    # Combine all features for PCA
    all_features = numerical_features + categorical_features
    X = df[all_features]

    # Standardize the data
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Apply PCA
    pca = PCA(n_components=variance_retained)
    X_pca = pca.fit_transform(X_scaled)

    # Reconstruct the data
    X_reconstructed = pca.inverse_transform(X_pca)

    # Calculate reconstruction error
    reconstruction_error = np.mean((X_scaled - X_reconstructed) ** 2, axis=1)

    # Determine anomaly threshold
    threshold = np.percentile(reconstruction_error, anomaly_percentile)

    # Add results to the DataFrame
    df['pca_anomaly_score'] = reconstruction_error
    df['pca_anomaly_flag'] = (reconstruction_error > threshold).astype(int)

    return df[['pca_anomaly_score', 'pca_anomaly_flag'] + all_features]
