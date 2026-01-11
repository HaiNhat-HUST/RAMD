# train.py
import os
import argparse
from sklearn.model_selection import train_test_split
import config
from src.model import RAMD
from src.utils import load_dataset

def main():
    parser = argparse.ArgumentParser(description="RAMD Training Module")
    parser.add_argument('--data', type=str, default=config.TRAIN_DATA_DEMO, help="Path to CSV file data for training")
    parser.add_argument('--model-name', type=str, default='ramd_demo_model.pkl', help="Custom name for saved model (without extension)")
    args = parser.parse_args()

    print("=== RAMD TRAINING MODULE ===")
    
    if args.data:
        train_data = os.path.join(config.BASE_DIR, 'data', 'processed', args.data)
        print(f"Loading data from: {train_data}")
        X, y = load_dataset(train_data)
    else:
        print("Error: No data path provided. Train model with built-in demo data. (train_demo_data.csv)")
        X, y = load_dataset(config.TRAIN_DATA_DEMO)
    if X is None: return

    # Chỉ lấy Benign (Label = 1) để train One-Class SVM
    # Lưu ý: X ở đây chưa scale, model.fit sẽ tự lo việc scale
    benign_indices = (y == 1)
    X_benign = X[benign_indices]
    
    print(f"Total Benign samples: {len(X_benign)}")

    # Chia Train (70%) / Val (30% - dùng để Pruning)
    X_train, X_val = train_test_split(X_benign, test_size=0.3, random_state=42)
    
    # 2. Initialize Model
    model = RAMD(
        n_estimators=config.N_ESTIMATORS,
        subspace_ratio=config.SUBSPACE_RATIO,
        nu=config.NU
    )
    
    # 3. Train & Prune
    try:
        model.fit(X_train, X_val)
    except Exception as e:
        print(f"Training Failed: {e}")
        return
    
    # 4. Save Model
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