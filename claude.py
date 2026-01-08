import json
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score
import warnings
warnings.filterwarnings('ignore')


class CuckooReportParser:
    """Parse Cuckoo/CAPE sandbox JSON reports and extract registry features"""
    
    # Security-sensitive registry key patterns
    STARTUP_KEYS = [
        'Run', 'RunOnce', 'RunServices', 'RunServicesOnce'
    ]
    ACTIVE_SETUP_KEYS = ['ActiveSetup']
    SERVICES_KEYS = ['Services']
    DLL_INJECTION_KEYS = ['AppInit_DLLs', 'AppInitDLLs']
    SHELL_SPAWN_KEYS = ['shellex']
    INTERNET_SETTINGS = ['Internet Settings']
    BHO_KEYS = ['Browser Helper Objects']
    
    SECURITY_SENSITIVE_GROUPS = {
        'startup': STARTUP_KEYS,
        'active_setup': ACTIVE_SETUP_KEYS,
        'services': SERVICES_KEYS,
        'dll_injection': DLL_INJECTION_KEYS,
        'shell_spawn': SHELL_SPAWN_KEYS,
        'internet': INTERNET_SETTINGS,
        'bho': BHO_KEYS
    }
    
    WINDOWS_SYSTEM_PATHS = [
        'c:\\windows', 'c:\\winnt', 'c:\\program files',
        'c:\\programdata', 'c:\\system32', 'c:\\syswow64'
    ]
    
    def __init__(self):
        self.feature_names = [
            'f1_read_success', 'f2_write_success', 'f3_delete_success',
            'f4_read_failed', 'f5_write_failed', 'f6_delete_failed',
            'f7_write_system_paths', 'f8_sens_read_success', 'f9_sens_write_success',
            'f10_sens_delete_success', 'f11_sens_read_failed', 'f12_sens_write_failed',
            'f13_sens_delete_failed', 'f14_sens_write_system_paths',
            'f15_fraction_distinct', 'f16_similar_filenames'
        ]
    
    def is_security_sensitive(self, key_path):
        """Check if registry key is security-sensitive"""
        key_path_lower = key_path.lower() if isinstance(key_path, str) else ""
        
        for group_keys in self.SECURITY_SENSITIVE_GROUPS.values():
            for sensitive_key in group_keys:
                if sensitive_key.lower() in key_path_lower:
                    return True
        return False
    
    def is_system_path(self, value):
        """Check if value contains Windows system path"""
        if not isinstance(value, str):
            return False
        value_lower = value.lower()
        return any(sys_path in value_lower for sys_path in self.WINDOWS_SYSTEM_PATHS)
    
    def extract_features_from_report(self, report):
        """Extract 16 registry features from Cuckoo JSON report"""
        
        features = {
            'f1': 0,  # Successful read operations
            'f2': 0,  # Successful write operations
            'f3': 0,  # Successful delete operations
            'f4': 0,  # Failed read operations
            'f5': 0,  # Failed write operations
            'f6': 0,  # Failed delete operations
            'f7': 0,  # Write system paths
            'f8': 0,  # Sensitive read success
            'f9': 0,  # Sensitive write success
            'f10': 0,  # Sensitive delete success
            'f11': 0,  # Sensitive read failed
            'f12': 0,  # Sensitive write failed
            'f13': 0,  # Sensitive delete failed
            'f14': 0,  # Sensitive write system paths
            'distinct_ops': set(),
            'similar_filenames': 0
        }
        
        # Extract registry operations from behavior section
        if 'behavior' not in report:
            return self._compute_feature_vector(features)
        
        behavior = report['behavior']
        
        # Process apistats for registry calls
        if 'apistats' in behavior:
            for process in behavior['apistats'].values():
                if isinstance(process, list):
                    for call in process:
                        if not isinstance(call, dict):
                            continue
                        
                        api = call.get('api', '')
                        args = call.get('args', {})
                        status = call.get('status', -1)
                        
                        # Process RegOpen, RegSet, RegDelete, etc.
                        if 'RegOpen' in api or 'RegQuery' in api:
                            key = args.get('KeyName', '')
                            if status == 0:
                                features['f1'] += 1
                            else:
                                features['f4'] += 1
                            
                            if self.is_security_sensitive(key):
                                if status == 0:
                                    features['f8'] += 1
                                else:
                                    features['f11'] += 1
                            features['distinct_ops'].add(('read', key))
                        
                        elif 'RegSet' in api or 'RegWrite' in api:
                            key = args.get('KeyName', '')
                            value = args.get('Value', '')
                            
                            if status == 0:
                                features['f2'] += 1
                            else:
                                features['f5'] += 1
                            
                            if self.is_system_path(str(value)):
                                features['f7'] += 1
                            
                            if self.is_security_sensitive(key):
                                if status == 0:
                                    features['f9'] += 1
                                else:
                                    features['f12'] += 1
                                
                                if self.is_system_path(str(value)):
                                    features['f14'] += 1
                            
                            features['distinct_ops'].add(('write', key))
                            if self._is_similar_to_system_filename(value):
                                features['similar_filenames'] += 1
                        
                        elif 'RegDelete' in api:
                            key = args.get('KeyName', '')
                            if status == 0:
                                features['f3'] += 1
                            else:
                                features['f6'] += 1
                            
                            if self.is_security_sensitive(key):
                                if status == 0:
                                    features['f10'] += 1
                                else:
                                    features['f13'] += 1
                            features['distinct_ops'].add(('delete', key))
        
        return self._compute_feature_vector(features)
    
    def _is_similar_to_system_filename(self, value):
        """Check if value is similar to Windows system filename"""
        if not isinstance(value, str):
            return False
        
        system_files = ['kernel32', 'ntdll', 'user32', 'advapi32', 'wininet']
        value_lower = value.lower()
        return any(sys_file in value_lower for sys_file in system_files)
    
    def _compute_feature_vector(self, features):
        """Compute final 16-dimensional feature vector"""
        n_ops = (features['f1'] + features['f2'] + features['f3'] + 
                features['f4'] + features['f5'] + features['f6'])
        
        f15 = len(features['distinct_ops']) / max(n_ops, 1)
        f16 = features['similar_filenames']
        
        feature_vector = np.array([
            features['f1'],
            features['f2'],
            features['f3'],
            features['f4'],
            features['f5'],
            features['f6'],
            features['f7'],
            features['f8'],
            features['f9'],
            features['f10'],
            features['f11'],
            features['f12'],
            features['f13'],
            features['f14'],
            f15,
            f16
        ], dtype=np.float32)
        
        return feature_vector
    
    def load_from_directory(self, directory_path, label=0):
        """Load and parse all JSON reports from a directory
        
        Args:
            directory_path: Path to directory containing JSON reports
            label: 0 for benign, 1 for malware
        
        Returns:
            Tuple of (feature_vectors, labels)
        """
        directory = Path(directory_path)
        X, y = [], []
        
        json_files = list(directory.glob('*.json')) + list(directory.glob('**/report.json'))
        
        print(f"Found {len(json_files)} JSON files in {directory_path}")
        
        for json_file in json_files:
            try:
                with open(json_file, 'r') as f:
                    report = json.load(f)
                
                feature_vector = self.extract_features_from_report(report)
                
                # Skip if all features are zero
                if np.sum(feature_vector) > 0:
                    X.append(feature_vector)
                    y.append(label)
                    print(f"✓ Processed: {json_file.name}")
            
            except json.JSONDecodeError:
                print(f"✗ Failed to parse JSON: {json_file.name}")
            except Exception as e:
                print(f"✗ Error processing {json_file.name}: {str(e)}")
        
        return np.array(X), np.array(y)


class OneClassClassifier:
    """Wrapper for one-class classifiers"""
    def __init__(self, clf_type='gaussian', nu=0.05):
        self.clf_type = clf_type
        self.nu = nu
        self.scaler = StandardScaler()
        
        if clf_type == 'gaussian':
            self.clf = GaussianMixture(n_components=1)
        elif clf_type == 'knn':
            self.clf = LocalOutlierFactor(n_neighbors=20, novelty=True)
        elif clf_type == 'svm':
            self.clf = OneClassSVM(nu=nu, kernel='rbf', gamma='auto')
        else:
            self.clf = IsolationForest(contamination=nu, random_state=42)
    
    def fit(self, X):
        X_scaled = self.scaler.fit_transform(X)
        self.clf.fit(X_scaled)
        return self
    
    def predict(self, X):
        X_scaled = self.scaler.transform(X)
        return self.clf.score_samples(X_scaled)
    
    def score(self, X, y=None):
        X_scaled = self.scaler.transform(X)
        return np.mean(self.clf.score_samples(X_scaled))


class FireflyAlgorithm:
    """Firefly Algorithm for optimization"""
    def __init__(self, n_fireflies=20, max_iterations=50, gamma=1.0, alpha_0=0.9, alpha_min=0.4):
        self.n_fireflies = n_fireflies
        self.max_iterations = max_iterations
        self.gamma = gamma
        self.alpha_0 = alpha_0
        self.alpha_min = alpha_min
    
    def update_alpha(self, t):
        return (self.alpha_0 - self.alpha_min) * (self.max_iterations - t) / self.max_iterations + self.alpha_min
    
    def hamming_distance(self, z1, z2):
        return np.sum(z1 != z2)


class MementicFireflyEnsemblePruning:
    """MFECP: Memetic Firefly-based Ensemble Classifier Pruning"""
    def __init__(self, ensemble, validation_data, max_iterations=50, n_fireflies=20, 
                 lambda1=1/3, lambda2=1/3, lambda3=1/3, sigma=0.75):
        self.ensemble = ensemble
        self.validation_data = validation_data
        self.max_iterations = max_iterations
        self.n_fireflies = n_fireflies
        self.lambda1 = lambda1
        self.lambda2 = lambda2
        self.lambda3 = lambda3
        self.sigma = sigma
        self.fa = FireflyAlgorithm(n_fireflies, max_iterations)
    
    def compute_light_intensity(self, ensemble_subset, X_val):
        """Compute light intensity based on accuracy, features, and diversity"""
        if len(ensemble_subset) == 0:
            return 0
        
        theta1 = np.exp(-abs(0.03 - 0.03))
        theta2 = 7 / 16
        
        predictions = np.array([clf.predict(X_val) for clf in ensemble_subset])
        n_agree = np.sum(np.mean(predictions > 0, axis=0).astype(bool))
        n_total = X_val.shape[0]
        diversity = min(n_agree, n_total - n_agree) / max(n_total - len(ensemble_subset)//2, 1)
        theta3 = min(1.0, max(0.0, diversity))
        
        intensity = self.lambda1 * theta1 + self.lambda2 * theta2 + self.lambda3 * theta3
        return intensity
    
    def prune(self):
        """Execute MFECP algorithm"""
        m = len(self.ensemble)
        X_val, _ = self.validation_data
        
        fireflies_pos = np.random.rand(self.n_fireflies, m)
        fireflies_z = (fireflies_pos > 0.5).astype(int)
        
        intensities = []
        for z in fireflies_z:
            subset = [self.ensemble[i] for i in range(m) if z[i] == 1]
            if len(subset) == 0:
                subset = [self.ensemble[0]]
            intensity = self.compute_light_intensity(subset, X_val)
            intensities.append(intensity)
        intensities = np.array(intensities)
        
        for t in range(self.max_iterations):
            alpha_t = self.fa.update_alpha(t)
            
            for i in range(self.n_fireflies):
                for j in range(self.n_fireflies):
                    if i != j and intensities[j] > intensities[i]:
                        d_ij = self.fa.hamming_distance(fireflies_z[i], fireflies_z[j])
                        beta_ij = np.exp(-self.fa.gamma * d_ij)
                        
                        fireflies_pos[i] = fireflies_z[i] + beta_ij * (fireflies_z[j] - fireflies_z[i]) + \
                                          alpha_t * np.random.uniform(-1, 1, m)
                        
                        r = np.random.rand(m)
                        fireflies_z[i] = (r < np.tanh(np.abs(fireflies_pos[i]))).astype(int)
                        
                        subset = [self.ensemble[k] for k in range(m) if fireflies_z[i][k] == 1]
                        if len(subset) == 0:
                            subset = [self.ensemble[0]]
                        intensities[i] = self.compute_light_intensity(subset, X_val)
                
                if np.random.rand() < self.sigma:
                    z_new = fireflies_z[i].copy()
                    idx = np.random.randint(0, m)
                    z_new[idx] = 1 - z_new[idx]
                    
                    subset = [self.ensemble[k] for k in range(m) if z_new[k] == 1]
                    if len(subset) == 0:
                        subset = [self.ensemble[0]]
                    intensity_new = self.compute_light_intensity(subset, X_val)
                    
                    if intensity_new > intensities[i]:
                        fireflies_z[i] = z_new
                        intensities[i] = intensity_new
        
        best_idx = np.argmax(intensities)
        best_z = fireflies_z[best_idx]
        pruned_ensemble = [self.ensemble[i] for i in range(m) if best_z[i] == 1]
        
        return pruned_ensemble if len(pruned_ensemble) > 0 else [self.ensemble[0]]


class FibonacciSuperincreasingOWA:
    """FSOWA: Fibonacci-based Superincreasing OWA"""
    def __init__(self, r):
        self.r = r
        self.weights = self._compute_weights(r)
    
    def _compute_weights(self, r):
        """Compute FSOWA weights"""
        w = np.ones(r)
        w[0] = 1
        if r > 1:
            w[1] = 3
        for k in range(2, r):
            w[k] = 3 * w[k-1] - w[k-2]
        
        denominator = 2 * w[-1] - w[-2] - 1 if r > 1 else 1
        weights = w / denominator
        return weights
    
    def aggregate(self, scores):
        """Aggregate classifier outputs"""
        sorted_scores = np.sort(scores)
        return np.dot(self.weights, sorted_scores)


class RAMD:
    """Registry-based Anomaly Malware Detection"""
    def __init__(self, n_classifiers=40, n_features=16):
        self.n_classifiers = n_classifiers
        self.n_features = n_features
        self.ensemble = None
        self.pruned_ensemble = None
        self.fsowa = None
        self.scaler = StandardScaler()
    
    def create_initial_ensemble(self, X_train):
        """Create initial ensemble with random subspace method"""
        ensemble = []
        classifier_types = ['gaussian', 'knn', 'svm', 'isolation_forest']
        
        for i in range(self.n_classifiers):
            n_selected = max(1, int(0.6 * self.n_features))
            feature_idx = np.random.choice(self.n_features, n_selected, replace=False)
            
            clf_type = classifier_types[i % len(classifier_types)]
            clf = OneClassClassifier(clf_type=clf_type, nu=0.03)
            clf.fit(X_train[:, feature_idx])
            
            ensemble.append((clf, feature_idx))
        
        return ensemble
    
    def fit(self, X_train, X_val):
        """Train RAMD model"""
        X_train = self.scaler.fit_transform(X_train)
        X_val = self.scaler.transform(X_val)
        
        print("Creating initial ensemble...")
        self.ensemble = self.create_initial_ensemble(X_train)
        
        print("Pruning ensemble with MFECP...")
        clf_only = [clf for clf, _ in self.ensemble]
        mfecp = MementicFireflyEnsemblePruning(
            clf_only, (X_val, None), max_iterations=30, n_fireflies=15
        )
        pruned_clf = mfecp.prune()
        
        self.pruned_ensemble = []
        for clf in pruned_clf:
            for original_clf, feature_idx in self.ensemble:
                if clf is original_clf:
                    self.pruned_ensemble.append((original_clf, feature_idx))
                    break
        
        self.fsowa = FibonacciSuperincreasingOWA(len(self.pruned_ensemble))
        
        print(f"✓ Pruned ensemble size: {len(self.pruned_ensemble)}/{self.n_classifiers}")
        return self
    
    def predict(self, X_test):
        """Predict malware"""
        X_test = self.scaler.transform(X_test)
        
        scores = []
        for clf, feature_idx in self.pruned_ensemble:
            X_subset = X_test[:, feature_idx]
            score = clf.predict(X_subset)
            scores.append(score)
        
        scores = np.array(scores)
        aggregated = np.array([self.fsowa.aggregate(scores[:, i]) for i in range(X_test.shape[0])])
        
        return (aggregated > 0).astype(int)
    
    def evaluate(self, X_test, y_test):
        """Evaluate performance"""
        y_pred = self.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred, zero_division=0)
        precision = precision_score(y_test, y_pred, zero_division=0)
        
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        far = fp / (fp + tn) if (fp + tn) > 0 else 0
        dr = recall
        
        print(f"\n{'='*40}")
        print(f"{'RAMD Performance Metrics':^40}")
        print(f"{'='*40}")
        print(f"Detection Rate (DR):   {dr*100:6.2f}%")
        print(f"False Alarm Rate (FAR): {far*100:6.2f}%")
        print(f"Accuracy:              {accuracy*100:6.2f}%")
        print(f"Precision:             {precision*100:6.2f}%")
        print(f"Ensemble Size:         {len(self.pruned_ensemble)}/{self.n_classifiers}")
        print(f"{'='*40}")
        
        return {'DR': dr, 'FAR': far, 'Accuracy': accuracy, 'Precision': precision}


# Example usage
if __name__ == "__main__":
    np.random.seed(42)
    
    # Initialize parser
    parser = CuckooReportParser()
    
    # Load benign samples
    print("\n[*] Loading benign samples...")
    X_benign, y_benign = parser.load_from_directory('./cuckoo_reports/benign', label=0)
    
    # Load malware samples
    print("\n[*] Loading malware samples...")
    X_malware, y_malware = parser.load_from_directory('./cuckoo_reports/malware', label=1)
    
    # Combine datasets
    X = np.vstack([X_benign, X_malware]) if len(X_benign) > 0 and len(X_malware) > 0 else None
    y = np.hstack([y_benign, y_malware]) if len(X_benign) > 0 and len(X_malware) > 0 else None
    
    if X is None or len(X) < 10:
        print("\n✗ Not enough samples loaded. Please provide JSON reports in:")
        print("  - ./cuckoo_reports/benign/")
        print("  - ./cuckoo_reports/malware/")
        exit(1)
    
    print(f"\n[*] Total samples loaded: {len(X)}")
    print(f"    Benign: {np.sum(y == 0)}, Malware: {np.sum(y == 1)}")
    
    # Split data
    split_idx = int(0.8 * len(X))
    X_train, X_test = X[:split_idx], X[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]
    
    val_split = int(0.75 * len(X_train))
    X_train_train = X_train[:val_split]
    X_train_val = X_train[val_split:]
    
    # Create and train RAMD
    print("\n[*] Training RAMD model...")
    ramd = RAMD(n_classifiers=40, n_features=16)
    ramd.fit(X_train_train, X_train_val)
    
    # Evaluate
    print("\n[*] Evaluating on test set...")
    ramd.evaluate(X_test, y_test)