import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

def generate_synthetic_data(num_samples=1000):
    np.random.seed(42)
    
    # 1. Normal Activity (e.g. standard file saving)
    # Low frequency of creations/modifications, low renames
    normal_data = pd.DataFrame({
        'modifications_per_sec': np.random.poisson(0.5, num_samples),
        'creations_per_sec': np.random.poisson(0.1, num_samples),
        'deletions_per_sec': np.random.poisson(0.05, num_samples),
        'renames_per_sec': np.random.poisson(0.01, num_samples),
        'entropy_avg': np.random.normal(3.5, 0.5, num_samples) # normal text entropy
    })
    
    # 2. Ransomware Activity
    # High frequency of modifications, many renames (usually to add extension like .locked)
    # High entropy (encrypted data)
    attack_samples = int(num_samples * 0.1) # 10% anomalies
    attack_data = pd.DataFrame({
        'modifications_per_sec': np.random.poisson(15.0, attack_samples),
        'creations_per_sec': np.random.poisson(10.0, attack_samples),
        'deletions_per_sec': np.random.poisson(5.0, attack_samples),
        'renames_per_sec': np.random.poisson(20.0, attack_samples),
        'entropy_avg': np.random.normal(7.8, 0.1, attack_samples) # close to max entropy 8.0
    })
    
    # Combine the data
    data = pd.concat([normal_data, attack_data], ignore_index=True)
    return data

def train_isolation_forest():
    print("[*] Generating synthetic telemetry data...")
    df = generate_synthetic_data(num_samples=2000)
    
    print(f"[*] Training Isolation Forest on {len(df)} samples...")
    # Features
    X = df[['modifications_per_sec', 'creations_per_sec', 
            'deletions_per_sec', 'renames_per_sec', 'entropy_avg']]
    
    # Train Isolation Forest
    # contamination indicates the approximate ratio of outliers in the data
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model.fit(X)
    
    model_path = "edr_model.pkl"
    joblib.dump(model, model_path)
    print(f"[+] Isolation Forest model saved to {model_path}")

if __name__ == "__main__":
    train_isolation_forest()
