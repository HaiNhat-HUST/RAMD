import argparse
import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix

import config
from src.model import RAMD

def train_mode():
    print("=== TRAIN MODE ===")
    # 1. Load Data
    if not os.path.exists(config.DATA_PATH):
        print(f"Error: Dataset not found at {config.DATA_PATH}")
        return

    df = pd.read_csv(config.DATA_PATH)
    # Lọc chỉ lấy Benign (Label = 1) để train
    benign_df = df[df['label'] == 1]
    X_benign = benign_df.drop(columns=['label']).values
    
    # Chia Train/Val (Ví dụ 70% Train, 30% Val để Pruning)
    X_train, X_val = train_test_split(X_benign, test_size=0.3, random_state=42)
    
    # 2. Init & Train Model
    model = RAMD(
        n_estimators=config.N_ESTIMATORS, 
        subspace_ratio=config.SUBSPACE_RATIO,
        nu=config.NU
    )
    
    model.fit(X_train, X_val)
    
    # 3. Save Model
    os.makedirs(os.path.dirname(config.MODEL_PATH), exist_ok=True)
    model.save(config.MODEL_PATH)

def test_mode(csv_file=None):
    print("=== TEST MODE ===")
    # 1. Load Model
    if not os.path.exists(config.MODEL_PATH):
        print("Error: Model not found. Please run 'train' first.")
        return
        
    model = RAMD.load(config.MODEL_PATH)
    print("Model loaded.")

    # 2. Load Test Data
    target_csv = csv_file if csv_file else config.DATA_PATH
    df = pd.read_csv(target_csv)
    
    X_test = df.drop(columns=['label']).values
    y_test = df['label'].values
    
    # 3. Predict
    print(f"Predicting on {len(X_test)} samples...")
    y_pred = model.predict(X_test)
    
    # 4. Metrics
    cm = confusion_matrix(y_test, y_pred, labels=[-1, 1])
    tn, fp, fn, tp = cm.ravel()
    # Mapping cho Anomaly Detection (Malware = -1 is Positive class detection goal)
    # Detected Malware (True Positive for detection) = TN của sklearn (-1 match -1)
    # False Alarm (False Positive for detection) = FN của sklearn (1 đoán nhầm thành -1)
    
    detected_malware = tn
    missed_malware = fp
    false_alarms = fn
    correct_benign = tp
    
    dr = detected_malware / (detected_malware + missed_malware + 1e-10)
    far = false_alarms / (false_alarms + correct_benign + 1e-10)
    acc = accuracy_score(y_test, y_pred)
    
    print("\n" + "="*30)
    print(f"RESULT FOR: {target_csv}")
    print("="*30)
    print(f"Detection Rate (DR)   : {dr*100:.2f}%")
    print(f"False Alarm Rate (FAR): {far*100:.2f}%")
    print(f"Accuracy              : {acc*100:.2f}%") 
    print("-" * 30)
    print(f"Confusion Matrix ([-1, 1]):\n{cm}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RAMD Malware Detection System")
    parser.add_argument('mode', choices=['train', 'test'], help="Chế độ hoạt động: train hoặc test")
    parser.add_argument('--model_name', choices=['train', 'test'], help="Lựa chọn model để sử dụng", default='ramd_model.pkl')
    parser.add_argument('--input', type=str, help="Đường dẫn file CSV để test (tùy chọn)", default=None)
    
    args = parser.parse_args()
    
    if args.mode == 'train':
        train_mode()
    elif args.mode == 'test':
        test_mode(args.input)