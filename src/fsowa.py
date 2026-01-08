import numpy as np


# đã kiểm tra chỗ thuật toán này oke nhé ae :vvvv

class FSOWA:
    """
    Fibonacci-based Superincreasing Ordered Weighted Averaging
    """
    def __init__(self):
        self.weights = []

    def calculate_weights(self, r):
        """
        Tính trọng số dựa trên Lemma 1, 2, 3 trong bài báo.
        r: Số lượng classifier trong tập hợp
        """
        if r <= 0: return []
        
        w_hat = [1, 3]
        for k in range(2, r):
            val = 3 * w_hat[k-1] - w_hat[k-2]
            w_hat.append(val)
            
        w_hat = np.array(w_hat[:r])
        w_r = w_hat[-1]
        w_r_minus_1 = w_hat[-2] if r > 1 else 0
        
        # Công thức (13): Normalization
        # Denominator = 2*w_r - w_{r-1} - 1
        denominator = 2 * w_r - w_r_minus_1 - 1
        if denominator == 0: denominator = 1 # Tránh chia cho 0
        
        weights = w_hat / denominator
        
        # Đảm bảo tổng trọng số = 1 (do sai số làm tròn số học)
        weights = weights / np.sum(weights)
        self.weights = weights
        return weights

    def aggregate(self, scores):
        """
        Thực hiện OWA:
        1. Sắp xếp scores tăng dần.
        2. Nhân vô hướng với weights.
        """
        sorted_scores = np.sort(scores) # Ascending order
        if len(sorted_scores) != len(self.weights):
            self.calculate_weights(len(sorted_scores))
            
        return np.dot(sorted_scores, self.weights)