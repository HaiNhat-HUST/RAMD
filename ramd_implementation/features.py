import json
import os
import re
import numpy as np
import pandas as pd

class RAMDFeatureExtractor:
    def __init__(self):
        # Định nghĩa các nhóm khóa Registry nhạy cảm (Security-sensitive keys)
        # Dựa trên 7 nhóm trong bài báo RAMD
        self.sensitive_patterns = [
            r"CurrentVersion\\Run",             # 1. Startup
            r"CurrentVersion\\RunOnce",         # 1. Startup
            r"Active Setup\\Installed Components", # 2. Active Setup
            r"CurrentControlSet\\Services",     # 3. Services
            r"AppInit_DLLs",                    # 4. DLL Injection
            r"Image File Execution Options",    # 4. DLL Injection / Debugging
            r"exefile\\shell\\open\\command",   # 5. Shell Spawning
            r"Internet Settings",               # 6. Internet Settings
            r"Browser Helper Objects",          # 7. BHO
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Policies", # Policies abuse
            r"Environment\\UserInitMprLogonScript"
        ]
        
        # Regex nhận diện đường dẫn hệ thống Windows (cho f7 và f14)
        self.sys_path_pattern = re.compile(r"[a-zA-Z]:\\(Windows|WINNT)\\(System32|SysWOW64)", re.IGNORECASE)
        
        # Regex nhận diện tên file hệ thống giả mạo (cho f16)
        # Ví dụ: svchost.exe, csrss.exe, winlogon.exe...
        self.sys_file_pattern = re.compile(r"(svchost|csrss|winlogon|lsass|services|explorer|smss)\.exe", re.IGNORECASE)

    def is_sensitive(self, key_path):
        """Kiểm tra xem key có thuộc nhóm nhạy cảm không"""
        if not key_path: return False
        for pattern in self.sensitive_patterns:
            if re.search(pattern, key_path, re.IGNORECASE):
                return True
        return False

    def is_sys_path(self, data_str):
        """Kiểm tra data ghi vào registry có chứa đường dẫn hệ thống không"""
        if not isinstance(data_str, str): return False
        return bool(self.sys_path_pattern.search(data_str))

    def is_sys_filename(self, data_str):
        """Kiểm tra data có chứa tên file hệ thống không"""
        if not isinstance(data_str, str): return False
        return bool(self.sys_file_pattern.search(data_str))

    def extract_from_json(self, json_path):
        """
        Input: Đường dẫn file JSON report của Cuckoo
        Output: Numpy array (16 features)
        """
        try:
            with open(json_path, 'r') as f:
                report = json.load(f)
        except Exception as e:
            print(f"Error reading {json_path}: {e}")
            return None

        # Khởi tạo vector đặc trưng
        # f1-f3: Success Read/Write/Delete
        # f4-f6: Failed Read/Write/Delete
        # f7: Write Sys Path
        # f8-f10: Sensitive Success R/W/D
        # f11-f13: Sensitive Failed R/W/D
        # f14: Sensitive Write Sys Path
        # f15: Distinct Ratio
        # f16: Sys Filename Write
        feats = np.zeros(16)
        
        # Truy cập phần behavior summary (Cuckoo report structure varies, check 'behavior' -> 'summary' or 'processes')
        # Thông thường Cuckoo gom nhóm trong behavior -> summary
        summary = report.get('behavior', {}).get('summary', {})
        
        # Nếu không có summary, thử duyệt qua từng process (chi tiết hơn nhưng nặng hơn)
        if not summary:
            # Fallback logic nếu cần (bỏ qua để đơn giản hóa)
            pass

        # Mapping hành vi Cuckoo sang loại operation
        # Cuckoo keys: 'regkey_opened', 'regkey_read', 'regkey_written', 'regkey_deleted'
        # Lưu ý: Cuckoo summary thường chỉ chứa danh sách key thành công. 
        # Để lấy failed/status code, cần đào sâu vào 'processes' -> 'calls'. 
        # Dưới đây là logic xấp xỉ dựa trên Summary (thường dùng cho Dataset lớn).
        
        # --- XỬ LÝ (GIẢ LẬP LOGIC TỪ SUMMARY) ---
        # Vì summary không phân biệt Success/Fail rõ ràng (thường chỉ log Success),
        # ta sẽ quét danh sách 'regkey_written', 'regkey_read', 'regkey_deleted'.
        
        distinct_ops = set()
        total_ops = 0

        # Helper function để duyệt list key
        def process_keys(key_list, op_type):
            nonlocal total_ops
            count_success = 0
            count_sensitive = 0
            count_sys_path = 0
            count_sensitive_sys_path = 0
            count_sys_filename = 0
            
            if not key_list: return 0, 0, 0, 0, 0

            for key in key_list:
                total_ops += 1
                distinct_ops.add(key)
                count_success += 1
                
                is_sens = self.is_sensitive(key)
                if is_sens:
                    count_sensitive += 1
                
                # Cuckoo summary 'regkey_written' đôi khi chỉ là list key, không có value.
                # Nếu muốn check value (f7, f14, f16), cần parse 'processes' -> 'calls' -> 'arguments'.
                # Ở đây ta giả định key chính chứa thông tin hoặc đếm số lượng key nhạy cảm.
                
                # Logic cho f7, f14, f16 (Write ops only)
                if op_type == 'write':
                    # Trong summary, ta không thấy value được ghi. 
                    # Ta tạm thời check chính cái key string (một số malware ghi vào key có tên file exe)
                    if self.is_sys_path(key):
                        count_sys_path += 1
                        if is_sens: count_sensitive_sys_path += 1
                    
                    if self.is_sys_filename(key):
                        count_sys_filename += 1

            return count_success, count_sensitive, count_sys_path, count_sensitive_sys_path, count_sys_filename

        # 1. READ Operations
        r_success, r_sens, _, _, _ = process_keys(summary.get('regkey_read', []), 'read')
        feats[0] = r_success       # f1
        feats[7] = r_sens          # f8 (Sensitive Read Success)
        
        # 2. WRITE Operations
        w_success, w_sens, w_sys, w_sens_sys, w_filename = process_keys(summary.get('regkey_written', []), 'write')
        feats[1] = w_success       # f2
        feats[6] = w_sys           # f7 (Write Sys Path)
        feats[8] = w_sens          # f9 (Sensitive Write Success)
        feats[13] = w_sens_sys     # f14 (Sensitive Write Sys Path)
        feats[15] = w_filename     # f16 (Sys Filename Write)

        # 3. DELETE Operations
        d_success, d_sens, _, _, _ = process_keys(summary.get('regkey_deleted', []), 'delete')
        feats[2] = d_success       # f3
        feats[9] = d_sens          # f10 (Sensitive Delete Success)

        # 4. FAILED Operations (f4, f5, f6, f11, f12, f13)
        # Summary của Cuckoo thường KHÔNG chứa failed ops.
        # Để lấy cái này, bạn phải parse `report['behavior']['processes'][...]['calls']`
        # và check `status` == 0 hoặc false.
        # Đoạn code dưới đây duyệt chi tiết (sẽ chậm hơn):
        
        failed_reads = 0
        failed_writes = 0
        failed_deletes = 0
        failed_sens_reads = 0
        failed_sens_writes = 0
        failed_sens_deletes = 0

        for proc in report.get('behavior', {}).get('processes', []):
            for call in proc.get('calls', []):
                cat = call.get('category')
                status = call.get('status') # 1=Success, 0=Fail
                api = call.get('api', '')
                
                if cat == 'registry' and status == 0: # Chỉ đếm Failed
                    # Lấy key từ arguments
                    args = call.get('arguments', {})
                    # Tên argument chứa key thường là 'regkey', 'key_handle', v.v.
                    # Đơn giản lấy value dài nhất trong args
                    key_val = ""
                    for v in args.values():
                        if isinstance(v, str) and ("HK" in v or "HKEY" in v):
                            key_val = v
                            break
                    
                    is_sens = self.is_sensitive(key_val)

                    if "QueryValue" in api or "OpenKey" in api:
                        failed_reads += 1
                        if is_sens: failed_sens_reads += 1
                    elif "SetValue" in api or "CreateKey" in api:
                        failed_writes += 1
                        if is_sens: failed_sens_writes += 1
                    elif "Delete" in api:
                        failed_deletes += 1
                        if is_sens: failed_sens_deletes += 1

        feats[3] = failed_reads      # f4
        feats[4] = failed_writes     # f5
        feats[5] = failed_deletes    # f6
        feats[10] = failed_sens_reads # f11
        feats[11] = failed_sens_writes # f12
        feats[12] = failed_sens_deletes # f13

        # f15: Fraction of distinct operations
        # (Số lượng key duy nhất / Tổng số thao tác)
        # Lưu ý: total_ops ở trên chỉ tính success từ summary.
        # Để chính xác phải cộng cả failed ops.
        grand_total = total_ops + failed_reads + failed_writes + failed_deletes
        if grand_total > 0:
            feats[14] = len(distinct_ops) / grand_total
        else:
            feats[14] = 0

        return feats

def process_dataset(benign_dir, malware_dir, output_file='data/processed/train_dataset.csv'):
    extractor = RAMDFeatureExtractor()
    data = []
    labels = [] # 1: Benign, -1: Malware

    print("Processing Benign samples...")
    for filename in os.listdir(benign_dir):
        if filename.endswith('.json'):
            path = os.path.join(benign_dir, filename)
            vec = extractor.extract_from_json(path)
            if vec is not None:
                data.append(vec)
                labels.append(1)

    print("Processing Malware samples...")
    for filename in os.listdir(malware_dir):
        if filename.endswith('.json'):
            path = os.path.join(malware_dir, filename)
            vec = extractor.extract_from_json(path)
            if vec is not None:
                data.append(vec)
                labels.append(-1)

    # Convert to DataFrame
    cols = [f'f{i+1}' for i in range(16)]
    df = pd.DataFrame(data, columns=cols)
    df['label'] = labels
    
    df.to_csv(output_file, index=False)
    print(f"Done! Saved dataset to {output_file} with shape {df.shape}")
    return df


# example usage
if __name__ == "__main__":
    # Giả sử cấu trúc thư mục:
    # ./data/benign/report1.json
    # ./data/malware/report1.json
    process_dataset('./data/ben_test', './data/mal_test', output_file='data/processed/test_dataset.csv')