import joblib
import numpy as np
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import MinMaxScaler
from .mfecp import MFECP
from .fsowa import FSOWA 

class RAMD:
    def __init__(self, n_estimators=40, subspace_ratio=0.6, nu=0.03):
        self.n_estimators = n_estimators
        self.subspace_ratio = subspace_ratio
        self.nu = nu
        
        self.pool = []              # Danh sách các bộ phân loại
        self.selected_indices = []  # Index các bộ được chọn sau khi prune
        self.scaler = MinMaxScaler() # Quan trọng: Phải lưu cả Scaler
        self.fsowa = FSOWA()
        
        # Mask cho features nhạy cảm (f8-f14)
        self.sec_mask = np.zeros(16, dtype=bool)
        self.sec_mask[7:14] = True

    def fit(self, X_train, X_val):
        """
        Quy trình huấn luyện toàn diện:
        1. Scale dữ liệu
        2. Train tập hợp OneClassSVM
        3. Cắt tỉa (Pruning)
        """
        # 1. Fit Scaler & Transform
        X_train_scaled = self.scaler.fit_transform(X_train)
        # Transform validation set bằng scaler của train set
        X_val_scaled = self.scaler.transform(X_val)

        # 2. Train Initial Pool
        print(f"[RAMD] Training initial pool ({self.n_estimators} classifiers)...")
        n_features = X_train_scaled.shape[1]
        n_subspace = int(n_features * self.subspace_ratio)
        
        for i in range(self.n_estimators):
            feature_indices = np.random.choice(range(n_features), n_subspace, replace=False)
            clf = OneClassSVM(kernel='rbf', gamma='scale', nu=self.nu)
            
            X_subset = X_train_scaled[:, feature_indices]
            clf.fit(X_subset)
            
            # Gắn thuộc tính feature_indices vào object clf để dùng lại sau này
            clf.feature_indices_ = feature_indices
            self.pool.append(clf)

        # 3. Pruning with MFECP
        print("[RAMD] Pruning ensemble with MFECP...")
        # Lưu ý: MFECP cần được import hoặc define ở đây
        mfecp = MFECP(self.pool, X_val_scaled, self.sec_mask)
        self.selected_indices = mfecp.run()
        print(f"[RAMD] Selected {len(self.selected_indices)} classifiers.")

    def predict(self, X):
        """Dự đoán trên dữ liệu mới"""
        # Quan trọng: Phải scale dữ liệu mới bằng scaler đã train
        X_scaled = self.scaler.transform(X)
        
        n_samples = X_scaled.shape[0]
        final_preds = []
        
        # Tính lại weights nếu cần
        self.fsowa.calculate_weights(len(self.selected_indices))
        
        for i in range(n_samples):
            scores = []
            for idx in self.selected_indices:
                clf = self.pool[idx]
                feat_idx = clf.feature_indices_
                sample_subset = X_scaled[i, feat_idx].reshape(1, -1)
                
                # Lấy raw score (distance to hyperplane)
                scores.append(clf.decision_function(sample_subset)[0])
            
            agg_score = self.fsowa.aggregate(scores)
            final_preds.append(1 if agg_score >= 0 else -1)
            
        return np.array(final_preds)

    def save(self, filepath):
        """Lưu toàn bộ object RAMD xuống ổ cứng"""
        print(f"[System] Saving model to {filepath}...")
        joblib.dump(self, filepath)
        print("[System] Model saved successfully.")

    @staticmethod
    def load(filepath):
        """Load object RAMD từ ổ cứng"""
        print(f"[System] Loading model from {filepath}...")
        return joblib.load(filepath)