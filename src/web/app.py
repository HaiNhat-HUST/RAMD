import sys
import os
from flask import Flask, render_template, request, jsonify
import numpy as np

# Thêm thư mục gốc vào path để import được src và config
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import config
# from src.model import RAMD
# from src.features import RAMDFeatureExtractor
from web.cuckoo_client import CuckooClient

app = Flask(__name__)

# Khởi tạo các thành phần
# Lưu ý: Sửa URL phù hợp với Cuckoo của bạn
cuckoo = CuckooClient(cuckoo_url="http://127.0.0.1:8090") 
# extractor = RAMDFeatureExtractor()

# Load Model một lần duy nhất khi khởi động App
print("Loading RAMD Model...")
try:
    model = RAMD.load(config.MODEL_PATH)
    print("Model loaded successfully!")
except Exception as e:
    print(f"Error loading model: {e}. Make sure you ran 'python main.py train' first.")
    model = None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # 1. Gửi file sang Cuckoo
    task_id = cuckoo.submit_file(file)
    if not task_id:
        return jsonify({'error': 'Failed to submit to Sandbox'}), 500
    
    return jsonify({'status': 'submitted', 'task_id': task_id})

@app.route('/check_result/<int:task_id>', methods=['GET'])
def check_result(task_id):
    """Client sẽ gọi API này liên tục để check trạng thái"""
    status = cuckoo.get_status(task_id)
    
    if status == 'reported':
        # 2. Lấy Report JSON
        report_json = cuckoo.get_report(task_id)
        if not report_json:
            return jsonify({'status': 'error', 'message': 'Could not retrieve report'})
        
        # 3. Trích xuất đặc trưng
        # features = extractor.extract_from_json(report_json)
        
        # Chuyển features thành mảng 2D (1 sample)
        features = features.reshape(1, -1)
        
        # 4. Dự đoán
        if model:
            # Predict: 1 (Benign), -1 (Malware)
            prediction = model.predict(features)[0]
            result_text = "BENIGN" if prediction == 1 else "MALICIOUS"
            return jsonify({
                'status': 'done',
                'result': result_text,
                'details': {
                    'task_id': task_id,
                    'features_extracted': features.tolist()
                }
            })
        else:
            return jsonify({'status': 'error', 'message': 'Model not loaded'})

    elif status in ['pending', 'processing', 'analyzing']:
        return jsonify({'status': 'processing'})
    else:
        return jsonify({'status': 'error', 'message': f'Cuckoo status: {status}'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)