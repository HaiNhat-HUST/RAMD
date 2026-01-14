# RAMD: Registry-based Anomaly Malware Detection
An implementation of malware detection using one-class ensemble classifiers based on Windows Registry activities.

## Project Overview
This project provides a complete pipeline from feature extraction of Cuckoo Sandbox reports to training and deploying an anomaly detection model. 
It includes a pre-trained model for demo and a web interface for real-time malware analysis.

>Raw data (json reports) is not included because it huge. Preprocessed data is included in data/preprocessed folder for quickly test and demo. So need to add new data to data folder if you want to train your own model

## Repository Structure

```text
./RAMD
├── data/                        # Preprocessed data for quick testing
├── src/
│   ├── models/                  # Storing trained model files (.pkl, .h5, etc.)
│   ├── ramd_implementation/     # Core preprocessing and RAMD algorithm
│   └── web/                     # Flask/FastAPI web application source code
├── preprocessing.py             # Script for data feature extraction
├── train.py                     # Model training entry point
├── test.py                      # Model evaluation entry point
└── app.py                       # Web demo entry point
```



## Setup & Installation
1. Clone the repository:
```Bash
git clone [https://github.com/your-username/RAMD.git](https://github.com/your-username/RAMD.git)
cd RAMD
```
2. Environment Setup:
```Bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```
3. Cuckoo Sandbox: Ensure you have a running Cuckoo Sandbox instance. Configure the API to be accessible at 0.0.0.0.

## workflow
1. Data Preparation
Organize your raw Cuckoo JSON reports as follows:
```text
./data
├── ben_train/ | ben_test/  # Benign samples
└── mal_train/ | mal_test/  # Malware samples
```
2. Preprocessing
```Bash
$ python .\preprocessing.py --help 
usage: preprocessing.py [-h] [--benign-report-folder BENIGN_REPORT_FOLDER] [--malware-report-folder MALWARE_REPORT_FOLDER] [--output-file OUTPUT_FILE]

RAMD Testing Module

options:
  -h, --help            show this help message and exit
  --benign-report-folder BENIGN_REPORT_FOLDER
                        Path to benign report folder for preprocessing
  --malware-report-folder MALWARE_REPORT_FOLDER
                        Path to malware report folder for preprocessing
  --output-file OUTPUT_FILE
                        Output file path for the processed dataset. Ex: data/processed/processed_dataset.csv
```
1. Training & Evaluation
```Bash
$ python train.py --help 
usage: train.py [-h] [--data DATA] [--model-name MODEL_NAME]

RAMD Training Module

options:
  -h, --help            show this help message and exit
  --data DATA           Path to CSV file data for training
  --model-name MODEL_NAME
                        Custom name for saved model (without extension)
```

```Bash
$ python test.py --help 
usage: test.py [-h] [--input INPUT] [--model MODEL]

RAMD Testing Module

options:
  -h, --help            show this help message and exit
  --input INPUT         Path to CSV file for testing
  --model MODEL         Path to the trained model file
```
1. Web Demo
   - Start your Cuckoo server.
   - Run the application: python app.py
   - Upload an .exe file via the web UI.
   - The system will:
      - Submit the file to Cuckoo.
      - Fetch the dynamic analysis report.
      - Extract features and classify the behavior.
