import requests
import time

class CuckooClient:
    def __init__(self, cuckoo_url="http://127.0.0.1:8090"):
        self.base_url = cuckoo_url

    def submit_file(self, file_storage):
        """Gửi file lên Cuckoo để phân tích"""
        url = f"{self.base_url}/tasks/create/file"
        files = {'file': (file_storage.filename, file_storage.stream)}
        try:
            r = requests.post(url, files=files)
            r.raise_for_status()
            # Cuckoo trả về: {"task_id": 123}
            return r.json().get("task_id")
        except Exception as e:
            print(f"Cuckoo Submit Error: {e}")
            return None

    def get_status(self, task_id):
        """Kiểm tra trạng thái task"""
        url = f"{self.base_url}/tasks/view/{task_id}"
        try:
            r = requests.get(url)
            if r.status_code == 200:
                return r.json().get("task", {}).get("status") # 'reported', 'processing', 'pending'
            return "unknown"
        except:
            return "error"

    def get_report(self, task_id):
        """Tải report JSON khi đã xong"""
        url = f"{self.base_url}/tasks/report/{task_id}/json"
        try:
            r = requests.get(url)
            if r.status_code == 200:
                return r.json()
            return None
        except:
            return None