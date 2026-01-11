# train.py
import os
import argparse
from sklearn.model_selection import train_test_split
import config
from src.model import RAMD
from src.utils import calculate_metrics, load_dataset
import numpy as np

def main():

    parser = argparse.ArgumentParser(description="RAMD Training Module")
    parser.add_argument('--data', type=str, default=config.TRAIN_DATA_DEMO, help="Path to CSV file data for training")
    parser.add_argument('--model-name', type=str, default='ramd_demo_model.pkl', help="Custom name for saved model (without extension)")
    args = parser.parse_args()

    print("=== RAMD TRAINING MODULE ===")
    
    # 1. Load Data
    if args.data:
        train_data = os.path.join(config.BASE_DIR, 'data', 'processed', args.data)
        print(f"[1/5] Loading data from: {train_data}")
        X, y = load_dataset(train_data)
    else:
        print("[1/5] Error: No data path provided. Train model with built-in demo data. (train_demo_data.csv)")
        X, y = load_dataset(config.TRAIN_DATA_DEMO)
    if X is None: return

    # Chỉ lấy Benign (Label = 1) để train One-Class SVM
    # Lưu ý: X ở đây chưa scale, model.fit sẽ tự lo việc scale
    X_benign = X[y == 1]
    X_malware = X[y == -1]

    print(f"      Found: {len(X_benign)} Benign samples, {len(X_malware)} Malware samples.")

    print(f"Total Benign samples: {len(X_benign)}")

    # 2. Data Splitting Strategy (Anomaly Detection)
    # - Train Set: Chỉ chứa Benign (70% của tổng Benign)
    # - Validation Set: Chứa 30% Benign còn lại + TOÀN BỘ Malware (để đánh giá khả năng phát hiện)
    
    X_train_benign, X_val_benign = train_test_split(X_benign, test_size=0.3, random_state=42)
    

    # Tạo tập Validation hỗn hợp
    X_val_mixed = np.vstack([X_val_benign, X_malware])
    y_val_mixed = np.concatenate([np.ones(len(X_val_benign)), -1 * np.ones(len(X_malware))])
    
    print(f"[2/5] Splitting Data:")
    print(f"      Train Set (Pure Benign): {X_train_benign.shape[0]} samples")
    print(f"      Val Set (Mixed)        : {X_val_mixed.shape[0]} samples")


    # 3. Initialize Model
    print(f"[3/5] Initializing RAMD Model (Estimators={config.N_ESTIMATORS}, Subspace={config.SUBSPACE_RATIO})...")
    model = RAMD(
        n_estimators=config.N_ESTIMATORS,
        subspace_ratio=config.SUBSPACE_RATIO,
        nu=config.NU
    )
    
    # 4. Train & Prune
    print(f"[4/5] Training & Pruning...")
    # Lưu ý: fit() sẽ dùng X_val_mixed để chạy thuật toán MFECP (Pruning)
    try:
        model.fit(X_train_benign, X_val_mixed)
    except Exception as e:
        print(f"Training Failed: {e}")
        return

     # 5. Metadata Calculation & Saving
    print(f"[5/5] Calculating Metadata & Saving...")
    
    # a. Đánh giá lại hiệu năng cuối cùng
    y_pred = model.predict(X_val_mixed)
    metrics = calculate_metrics(y_val_mixed, y_pred)
    
    # b. Tính Feature Profile (Trung bình giá trị các đặc trưng) để vẽ Radar Chart
    # Cần transform dữ liệu về scale 0-1 (đã được model fit bên trong)
    # Chúng ta dùng scaler của model để transform dữ liệu gốc
    
    X_benign_scaled = model.scaler.transform(X_benign) # Toàn bộ benign
    X_malware_scaled = model.scaler.transform(X_malware) # Toàn bộ malware
    
    feat_mean_benign = np.mean(X_benign_scaled, axis=0).tolist()
    feat_mean_malware = np.mean(X_malware_scaled, axis=0).tolist()

    # c. Đóng gói Metadata
    model.training_metrics = {
        "accuracy": round(metrics['ACC'] * 100, 2),
        "dr": round(metrics['DR'] * 100, 2),
        "far": round(metrics['FAR'] * 100, 2),
    }
    
    model.dataset_meta = {
        "counts": {
            "train_benign": len(X_train_benign),
            "val_benign": len(X_val_benign),
            "val_malware": len(X_malware)
        },
        "feature_profile": {
            "benign": feat_mean_benign,
            "malware": feat_mean_malware
        },
        "confusion_matrix": metrics['CM'].tolist() # Chuyển numpy sang list
    }

    # 6. Save Model
    os.makedirs(os.path.dirname(config.MODEL_DEMO), exist_ok=True)

    if args.model_name:
        model_path = os.path.join(os.path.dirname(config.MODEL_DEMO), args.model_name + '.pkl')
    else:
        model_path = config.MODEL_DEMO
    
    model.save(model_path)
    print(f"Model saved to: {model_path}")
    print("Training finished successfully.")

if __name__ == "__main__":
    main()