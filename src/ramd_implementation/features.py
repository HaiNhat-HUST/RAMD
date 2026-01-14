import json
import os
import re
import numpy as np
import pandas as pd
import Levenshtein

# =========================
# RAMD Feature Extractor
# =========================

class RAMDFeatureExtractor:
    def __init__(self):
        self.READ_APIS = [
            'RegQueryValue', 'RegEnumValue', 'RegOpenKey',
            'NtOpenKey', 'RegQueryInfoKey'
        ]

        self.WRITE_APIS = [
            'RegSetValue', 'RegCreateKey',
            'NtCreateKey', 'RegSetInfoKey'
        ]

        self.DELETE_APIS = [
            'RegDeleteKey', 'RegDeleteValue',
            'NtDeleteKey', 'NtDeleteValueKey'
        ]

        self.SENSITIVE_KEYS_REGEX = [
            r"\\CurrentVersion\\Run",
            r"\\CurrentVersion\\RunOnce",
            r"\\Active Setup\\Installed Components",
            r"\\CurrentControlSet\\Services",
            r"\\Windows\\AppInit_DLLs",
            r"\\Classes\\Exefile\\shell\\open\\command",
            r"\\Internet Settings",
            r"\\Browser Helper Objects",
            r"\\CurrentVersion\\Policies"
        ]

        self.SYSTEM_PATHS = [
            r"C:\\Windows",
            r"%SystemRoot%",
            r"System32",
            r"SysWOW64"
        ]

        self.SYSTEM_FILENAMES = [
            "svchost.exe", "lsass.exe", "explorer.exe",
            "winlogon.exe", "services.exe", "csrss.exe"
        ]

        self.INVALID_U = re.compile(rb'\\u(?![0-9a-fA-F]{4})')

    # =========================
    # Helpers
    # =========================

    def safe_json_load(self, path):
        with open(path, 'rb') as f:
            raw = f.read()
        raw = self.INVALID_U.sub(b'\\\\u', raw)
        text = raw.decode('utf-8', errors='ignore')
        return json.loads(text)

    def is_match_any(self, text, patterns):
        if not text:
            return False
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                return True
        return False

    def is_similar_filename(self, text):
        if not text:
            return False
        base = os.path.basename(text.replace("\\", "/")).lower()

        for sysf in self.SYSTEM_FILENAMES:
            if base == sysf:
                continue
            if 0 < Levenshtein.distance(base, sysf) <= 2:
                return True
        return False

    # =========================
    # CORE EXTRACTION (RAMD)
    # =========================

    def extract_from_json(self, json_path):
        try:
            data = self.safe_json_load(json_path)
        except Exception as e:
            print(f"[!] JSON error {json_path}: {e}")
            return None

        feats = np.zeros(16)
        total_ops = 0
        distinct_ops = set()

        for proc in data.get("behavior", {}).get("processes", []):
            for call in proc.get("calls", []):
                if call.get("category") != "registry":
                    continue

                api = call.get("api", "")
                args = call.get("arguments", {})
                key = args.get("regkey", "")
                value = str(args.get("value", ""))
                status = call.get("status", 0)

                total_ops += 1
                distinct_ops.add(f"{api}:{key}")

                is_read = self.is_match_any(api, self.READ_APIS)
                is_write = self.is_match_any(api, self.WRITE_APIS)
                is_delete = self.is_match_any(api, self.DELETE_APIS)
                is_sensitive = self.is_match_any(key, self.SENSITIVE_KEYS_REGEX)
                writes_sys = is_write and self.is_match_any(value, self.SYSTEM_PATHS)

                if status == 1:
                    if is_read: feats[0] += 1
                    if is_write: feats[1] += 1
                    if is_delete: feats[2] += 1

                    if is_sensitive:
                        if is_read: feats[7] += 1
                        if is_write: feats[8] += 1
                        if is_delete: feats[9] += 1
                else:
                    if is_read: feats[3] += 1
                    if is_write: feats[4] += 1
                    if is_delete: feats[5] += 1

                    if is_sensitive:
                        if is_read: feats[10] += 1
                        if is_write: feats[11] += 1
                        if is_delete: feats[12] += 1

                if writes_sys:
                    feats[6] += 1
                if writes_sys and is_sensitive:
                    feats[13] += 1
                if is_write and self.is_similar_filename(value):
                    feats[15] += 1

        feats[14] = len(distinct_ops) / total_ops if total_ops else 0
        return feats


# ===============
# DATASET DRIVER
# ===============

def process_dataset(benign_dir, malware_dir, output_file):
    extractor = RAMDFeatureExtractor()
    data = []
    labels = []

    print("Processing Benign samples...")
    for f in os.listdir(benign_dir):
        if f.endswith(".json"):
            vec = extractor.extract_from_json(os.path.join(benign_dir, f))
            if vec is not None:
                data.append(vec)
                labels.append(1)

    print("Processing Malware samples...")
    for f in os.listdir(malware_dir):
        if f.endswith(".json"):
            vec = extractor.extract_from_json(os.path.join(malware_dir, f))
            if vec is not None:
                data.append(vec)
                labels.append(-1)

    cols = [f"f{i+1}" for i in range(16)]
    df = pd.DataFrame(data, columns=cols)
    df["label"] = labels
    df.to_csv(output_file, index=False)

    print(f"[✓] Saved dataset {df.shape} → {output_file}")
    return df
