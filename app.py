# app.py
import os
import glob
import sys
from flask import Flask, render_template, request, jsonify

# Setup paths
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import config
from src.model import RAMD
from src.features import RAMDFeatureExtractor
from web.cuckoo_client import CuckooClient

app = Flask(__name__, 
            template_folder='web/templates', 
            static_folder='web/static')

# Initialize Components
# LƯU Ý: Đảm bảo Cuckoo API đang chạy ở port này
cuckoo = CuckooClient(cuckoo_url="http://127.0.0.1:8090") 
extractor = RAMDFeatureExtractor()

# Global variable to hold the currently loaded model
ACTIVE_MODEL = None
ACTIVE_MODEL_NAME = ""

def load_model_from_disk(filename):
    """Helper to load model and update global state"""
    global ACTIVE_MODEL, ACTIVE_MODEL_NAME
    filepath = os.path.join("models", filename)
    
    if not os.path.exists(filepath):
        return False
    
    try:
        loaded_model = RAMD.load(filepath)
        ACTIVE_MODEL = loaded_model
        ACTIVE_MODEL_NAME = filename
        print(f"Web App: Switched to model {filename}")
        return True
    except Exception as e:
        print(f"Web App: Error loading {filename}: {e}")
        return False

# Auto-load the first available model on startup
existing_models = glob.glob(os.path.join("models", "*.pkl"))
if existing_models:
    first_model = os.path.basename(existing_models[0])
    load_model_from_disk(first_model)

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/models', methods=['GET'])
def list_models():
    """List all available .pkl models"""
    files = glob.glob(os.path.join("models", "*.pkl"))
    model_names = [os.path.basename(f) for f in files]
    # Sort models by creation time (newest first) or name
    model_names.sort() 
    return jsonify({
        'models': model_names,
        'active': ACTIVE_MODEL_NAME
    })

@app.route('/api/model_info', methods=['POST'])
def get_model_info():
    """Load a model (if needed) and return its metadata"""
    data = request.json
    model_name = data.get('model_name')
    
    if not model_name:
        return jsonify({'status': 'error', 'message': 'No model name provided'})

    # Try loading
    success = load_model_from_disk(model_name)
    if not success:
        return jsonify({'status': 'error', 'message': f'Could not load {model_name}'})

    # Extract metadata safely
    model = ACTIVE_MODEL
    info = {
        "params": {
            "n_estimators": model.n_estimators,
            "subspace_ratio": model.subspace_ratio,
            "nu": model.nu
        },
        "metrics": getattr(model, 'training_metrics', {}),
        "dataset": getattr(model, 'dataset_meta', {}),
        "pruning": {
            "original_size": len(model.pool),
            "pruned_size": len(model.selected_indices)
        }
    }
    return jsonify({'status': 'success', 'info': info})

@app.route('/analyze', methods=['POST'])
def analyze_file():
    """Handle file upload and Cuckoo submission"""
    if not ACTIVE_MODEL:
        return jsonify({'error': 'No model loaded. Select a model first.'}), 400

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Submit to Cuckoo
    task_id = cuckoo.submit_file(file)
    if not task_id:
        return jsonify({'error': 'Failed to submit file to Sandbox'}), 500
    
    return jsonify({'status': 'submitted', 'task_id': task_id})

@app.route('/check_result/<int:task_id>', methods=['GET'])
def check_result(task_id):
    """Poll status, extract features, and predict"""
    status = cuckoo.get_status(task_id)
    
    if status == 'reported':
        # 1. Get JSON Report
        report = cuckoo.get_report(task_id)
        if not report:
            return jsonify({'status': 'error', 'message': 'Report not found'})
        
        # 2. Extract Features
        features = extractor.extract_from_json(report)
        if features is None:
            return jsonify({'status': 'error', 'message': 'Feature extraction failed (Log empty?)'})
        
        # 3. Predict
        # Reshape for single sample prediction: (1, 16)
        features_reshaped = features.reshape(1, -1)
        
        try:
            prediction = ACTIVE_MODEL.predict(features_reshaped)[0] # 1 or -1
            result_text = "BENIGN" if prediction == 1 else "MALICIOUS"
            
            return jsonify({
                'status': 'done',
                'result': result_text,
                'model_used': ACTIVE_MODEL_NAME,
                'details': {
                    'task_id': task_id,
                    'features': features.tolist() # Return raw features for frontend chart
                }
            })
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})

    elif status in ['pending', 'processing', 'analyzing', 'completed']:
        return jsonify({'status': 'processing'})
    else:
        return jsonify({'status': 'error', 'message': f'Cuckoo Error Status: {status}'})

if __name__ == '__main__':
    # Ensure directories exist
    os.makedirs('models', exist_ok=True)
    os.makedirs('web/static', exist_ok=True)
    os.makedirs('web/templates', exist_ok=True)
    
    print("Starting Web App on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)