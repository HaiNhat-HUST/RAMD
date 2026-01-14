# test.py
import os
import argparse
from ramd_implementation import config
from ramd_implementation.model import RAMD
from ramd_implementation.utils import load_dataset, calculate_metrics

def main():
    parser = argparse.ArgumentParser(description="RAMD Testing Module")

    parser.add_argument('--input', type=str, help="Path to CSV file for testing")
    parser.add_argument('--model', type=str, help="Path to the trained model file")
    args = parser.parse_args()

    print("=== RAMD TESTING MODULE ===")

    # 1. Load Model
    if args.model:
        model_path = os.path.abspath("models\\" + args.model)
        if not os.path.exists(model_path):
            print(f"Error: Model not found at {model_path}. Please train model with 'python train.py' first.")
            return
        model = RAMD.load(model_path)
    else:
        print(f"Model path not provided, using built-in demo model at {config.MODEL_DEMO}")
        model = RAMD.load(config.MODEL_DEMO)

    print("Model loaded successfully.")

    # 2. Load Test Data
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if args.input:
        input_path = os.path.abspath(os.path.join(current_dir, '..', 'data', 'processed', args.input))
        if not os.path.exists(input_path):
            print(f"Error: Input data file not found at {input_path}.")
            return
        
        input = input_path
    else:
        print("Error: No input data path provided. Test model with built-in demo test data. (demo_test_data.csv)")
        input = os.path.abspath(os.path.join(current_dir, '..', 'data', 'processed',config.TEST_DATA_DEMO))


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