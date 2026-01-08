import os

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRAIN_DATA_PATH = os.path.join(BASE_DIR, 'data', 'processed', 'train_dataset.csv')
TEST_DATA_PATH = os.path.join(BASE_DIR, 'data', 'processed', 'test_dataset_2.csv')
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'ramd_model.pkl')

# Model Parameters
N_ESTIMATORS = 40          # Số lượng classifier ban đầu
SUBSPACE_RATIO = 0.6       # Tỷ lệ feature cho mỗi classifier
NU = 0.03                  # Outlier fraction cho OneClassSVM

# MFECP Parameters
POP_SIZE = 20
MAX_ITER = 20
GAMMA = 1.0