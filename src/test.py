# test.py
import os
import argparse
import config
from src.model import RAMD
from src.utils import load_dataset, calculate_metrics

def main():
    parser = argparse.ArgumentParser(description="RAMD Testing Module")

    parser.add_argument('--input', type=str, default=config.TEST_DATA_DEMO, help="Path to CSV file for testing")
    parser.add_argument('--model', type=str, default=config.MODEL_DEMO, help="Path to the trained model file")
    args = parser.parse_args()

    print("=== RAMD TESTING MODULE ===")

    # 1. Load Model
    if args.model:
        if not os.path.exists(args.model):
            print(f"Error: Model not found at {args.model}. Please train model with 'python train.py' first.")
            return
        model = RAMD.load(os.path.join(config.BASE_DIR, 'models', args.model))
    else:
        print("Model path not provided, using built-in demo model.")
        model = RAMD.load(config.MODEL_DEMO)

    print("Model loaded successfully.")

    # 2. Load Test Data

    if args.input:
        input_path = os.path.join(config.BASE_DIR, 'data', 'processed', args.input)
        if not os.path.exists(input_path):
            print(f"Error: Input data file not found at {input_path}.")
            return
        
        input = args.input
    else:
        print("Error: No input data path provided. Test model with built-in demo test data. (demo_test_data.csv)")
        input = config.TEST_DATA_DEMO

    print(f"Testing on file: {input}")
    X_test, y_test = load_dataset(input)
    if X_test is None: return

    # 3. Predict
    print(f"Predicting {len(X_test)} samples...")
    y_pred = model.predict(X_test)

    # 4. Show Metrics
    metrics = calculate_metrics(y_test, y_pred)
    
    print("\n" + "="*30)
    print(f"Detection Rate (DR)   : {metrics['DR']*100:.2f}%")
    print(f"False Alarm Rate (FAR): {metrics['FAR']*100:.2f}%")
    print(f"Accuracy (ACC)        : {metrics['ACC']*100:.2f}%")
    print("-" * 30)
    print(f"Confusion Matrix ([-1, 1]):\n{metrics['CM']}")
    print("="*30)

if __name__ == "__main__":
    main()