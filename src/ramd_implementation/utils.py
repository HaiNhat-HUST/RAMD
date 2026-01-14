import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix


def load_dataset(csv_path):
    """Load và chuẩn hóa dữ liệu từ CSV"""
    try:
        df = pd.read_csv(csv_path)
        y = df['label'].values
        X = df.drop(columns=['label']).values
        return X, y
    except FileNotFoundError:
        print(f"Error: File not found at {csv_path}")
        return None, None
    

def calculate_metrics(y_true, y_pred):
    """Tính toán các chỉ số DR, FAR, ACC"""
    # Confusion Matrix với labels [-1, 1] (Malware, Benign)
    cm = confusion_matrix(y_true, y_pred, labels=[-1, 1])
    tn, fp, fn, tp = cm.ravel()
    
    # Mapping: 
    # -1 (Malware) là đối tượng cần phát hiện (Positive class trong ngữ cảnh detection)
    detected_malware = tn 
    missed_malware = fp
    false_alarms = fn
    correct_benign = tp
    
    dr = detected_malware / (detected_malware + missed_malware + 1e-10)
    far = false_alarms / (false_alarms + correct_benign + 1e-10)
    acc = accuracy_score(y_true, y_pred)
    
    return {
        "DR": dr,
        "FAR": far,
        "ACC": acc,
        "CM": cm
    }