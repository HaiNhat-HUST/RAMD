import os

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Model Parameters
N_ESTIMATORS = 40          # Số lượng classifier ban đầu
SUBSPACE_RATIO = 0.6       # Tỷ lệ feature cho mỗi classifier
NU = 0.03                  # Outlier fraction cho OneClassSVM

# MFECP Parameters
POP_SIZE = 20
MAX_ITER = 20
GAMMA = 1.0

# Cuckoo
Cuckoo_url = "http://127.0.0.1:8090"

# built-in demo
TRAIN_DATA_DEMO = os.path.join(BASE_DIR, '..','data', 'processed', 'demo_train_data.csv')
TEST_DATA_DEMO = 'demo_test_data.csv'
MODEL_DEMO= os.path.join(BASE_DIR, '..', 'models', 'demo_model.pkl')
