import numpy as np
import math
import copy

class MFECP:
    """
    Memetic Firefly-based Ensemble Classifier Pruning
    """
    def __init__(self, pool_classifiers, X_val, security_features_mask, 
                 pop_size=20, max_iter=20, gamma=1.0, alpha_start=0.9, alpha_end=0.4):
        self.pool = pool_classifiers
        self.m = len(pool_classifiers) # Kích thước pool ban đầu
        self.X_val = X_val
        self.sec_mask = security_features_mask # Mảng boolean, True nếu là feature nhạy cảm
        self.pop_size = pop_size
        self.max_iter = max_iter
        self.gamma = gamma # Hệ số hấp thụ ánh sáng
        self.alpha_start = alpha_start
        self.alpha_end = alpha_end
        
        # Lambda weights cho hàm mục tiêu (Eq 12)
        self.lambda1 = 1/3
        self.lambda2 = 1/3
        self.lambda3 = 1/3
        
        # Pre-calculate predictions của pool trên tập validation để tối ưu tốc độ
        print("    [MFECP] Pre-calculating pool predictions...")
        self.pool_preds = np.zeros((self.X_val.shape[0], self.m))
        for i, clf in enumerate(self.pool):
            # OneClassSVM trả về 1 hoặc -1. Chuyển về 1 (benign) và 0 (malware/outlier) để dễ tính toán
            pred = clf.predict(self.X_val)
            self.pool_preds[:, i] = (pred == 1).astype(int) 

    def get_fitness(self, binary_vector):
        """
        Tính Light Intensity (I) dựa trên Eq 9, 10, 11, 12
        binary_vector: vector z (chọn classifier nào)
        """
        selected_indices = np.where(binary_vector == 1)[0]
        if len(selected_indices) == 0: return 0
        
        # 1. Consistency (Theta 1) - Dựa trên False Positive Rate (FPR) trên tập Validation (Benign)
        # Vì X_val toàn là benign, nên bất kỳ dự đoán nào là 0 (malware) đều là False Positive
        # Tuy nhiên, bài báo định nghĩa consistency hơi khác.
        # Đơn giản hóa: Càng nhiều Benign được đoán đúng (1) thì càng tốt.
        
        # Lấy dự đoán của các clf được chọn
        sub_preds = self.pool_preds[:, selected_indices]
        
        # Tỷ lệ đoán sai (FPR) của từng clf
        # Vì data là benign, đoán 0 là sai.
        fpr_k = 1.0 - np.mean(sub_preds, axis=0) # mảng FPR của từng thành viên
        
        # Eq 9: Min exponential consistency
        # Giả sử training rejection rate v_k ~ 0.05 (tham số nu)
        # v_hat_k là fpr thực tế.
        # Hàm exp(-|v_hat - v|) -> max khi v_hat gần v.
        # Ở đây ta đơn giản hóa: Càng ít lỗi càng tốt -> dùng 1 - mean(fpr)
        theta1 = np.mean(1.0 - fpr_k) # Simplified for implementation stability
        
        # 2. Security Feature Rate (Theta 2)
        # Tỷ lệ features nhạy cảm được sử dụng bởi các clf được chọn
        sec_rates = []
        for idx in selected_indices:
            # Lấy các features mà clf này sử dụng (do Random Subspace)
            # Trong code này ta giả định clf lưu `feature_indices_`
            used_feats = self.pool[idx].feature_indices_
            n_sec = np.sum(self.sec_mask[used_feats])
            sec_rates.append(n_sec / len(used_feats))
        theta2 = np.mean(sec_rates)
        
        # 3. Diversity (Theta 3) - Eq 11 (Entropy measure)
        # Số lượng thành viên đoán đúng cho mỗi mẫu x_j
        v_i = np.sum(sub_preds, axis=1) # Shape (N_val,)
        M_i = len(selected_indices)
        if M_i <= 1: 
            theta3 = 0
        else:
            # Tử số: Sum min(v_i, M_i - v_i)
            numerator = np.sum(np.minimum(v_i, M_i - v_i))
            # Mẫu số
            denominator = len(self.X_val) * (M_i - math.ceil(M_i/2))
            if denominator == 0: denominator = 1
            theta3 = numerator / denominator
            
        # Tổng hợp Light Intensity
        I = self.lambda1 * theta1 + self.lambda2 * theta2 + self.lambda3 * theta3
        return I

    def run(self):
        print("    [MFECP] Starting optimization...")
        # Khởi tạo quần thể: positions y (thực) và binary z (nhị phân)
        # y trong khoảng [-1, 1]
        population_y = np.random.uniform(-1, 1, (self.pop_size, self.m))
        population_z = np.zeros((self.pop_size, self.m))
        intensities = np.zeros(self.pop_size)
        
        # Đánh giá ban đầu
        for i in range(self.pop_size):
            # Sigmoid/Tanh để chuyển y -> xác suất -> z (Eq 8)
            probs = 0.5 * (1 + np.tanh(population_y[i]))
            rand_vals = np.random.rand(self.m)
            population_z[i] = (rand_vals < probs).astype(int)
            # Đảm bảo ít nhất 1 clf được chọn
            if np.sum(population_z[i]) == 0:
                population_z[i][np.random.randint(0, self.m)] = 1
            
            intensities[i] = self.get_fitness(population_z[i])
            
        best_I = -1
        best_z = None
        
        # Vòng lặp tối ưu
        for t in range(self.max_iter):
            alpha = self.alpha_start - (self.alpha_start - self.alpha_end) * (t / self.max_iter)
            
            for i in range(self.pop_size):
                for j in range(self.pop_size):
                    if intensities[j] > intensities[i]: # Firefly i di chuyển về j sáng hơn
                        r_ij = np.linalg.norm(population_y[i] - population_y[j]) # Khoảng cách Euclid
                        beta = math.exp(-self.gamma * (r_ij ** 2)) # Eq 7
                        
                        # Cập nhật vị trí y (Eq 5)
                        epsilon = np.random.uniform(-1, 1, self.m)
                        population_y[i] = population_y[i] + \
                                          beta * (population_y[j] - population_y[i]) + \
                                          alpha * epsilon
                                          
                        # Giới hạn y
                        population_y[i] = np.clip(population_y[i], -5, 5)
                        
                        # Cập nhật z và I
                        probs = 0.5 * (1 + np.tanh(population_y[i]))
                        rand_vals = np.random.rand(self.m)
                        population_z[i] = (rand_vals < probs).astype(int)
                        if np.sum(population_z[i]) == 0:
                            population_z[i][np.random.randint(0, self.m)] = 1
                            
                        new_I = self.get_fitness(population_z[i])
                        intensities[i] = new_I
                        
                        # Local Search (Memetic)
                        # Thử lật 1 bit ngẫu nhiên xem có tốt hơn không
                        temp_z = copy.deepcopy(population_z[i])
                        bit_to_flip = np.random.randint(0, self.m)
                        temp_z[bit_to_flip] = 1 - temp_z[bit_to_flip]
                        if np.sum(temp_z) > 0:
                            temp_I = self.get_fitness(temp_z)
                            if temp_I > intensities[i]:
                                population_z[i] = temp_z
                                intensities[i] = temp_I

            # Tìm best solution trong iter này
            current_best_idx = np.argmax(intensities)
            if intensities[current_best_idx] > best_I:
                best_I = intensities[current_best_idx]
                best_z = copy.deepcopy(population_z[current_best_idx])
            
            # print(f"Iter {t+1}/{self.max_iter}, Best Intensity: {best_I:.4f}, Ensemble Size: {np.sum(best_z)}")

        # Trả về danh sách index của các classifier được chọn
        selected_indices = np.where(best_z == 1)[0]
        return selected_indices