import sys 
sys.path.insert(0, '.') 
import pandas as pd 
import joblib 
 
# Load features 
df = pd.read_csv('data/generated_logs/features_layer2.csv') 
print('Features columns:', df.columns.tolist()) 
 
# Get Kali IP data 
kali = df[df['ip'] == '192.168.47.128'] 
print('\nKali IP data:') 
print(kali) 
 
# Load model 
rf = joblib.load('ml_models/saved_models/random_forest_layer2.joblib') 
scaler = joblib.load('ml_models/saved_models/scaler_layer2.joblib') 
 
# Prepare features 
feature_cols = ['req_per_min', 'failed_logins', 'login_success_ratio', 'new_accounts', 'scan_score', 'listing_reqs', 'error_ratio_4xx', 'ua_anomaly'] 
X = kali[feature_cols].fillna(0) 
X_scaled = scaler.transform(X) 
pred = rf.predict(X_scaled) 
proba = rf.predict_proba(X_scaled) 
 
print(f'\nPrediction: {pred[0]} (0=Benign, 1=Attack)') 
print(f'Attack probability: {proba[0][1]:.3f}') 
