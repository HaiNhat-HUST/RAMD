# RAMD
registry-based anomaly malware detection using one-class ensemble classifiers




## repositiory description
1. raw test data is not included because it huge, preprocessed data is included in data/preprocessed folder for quickly test and demo. So need to add new data to data folder if you want to train your own folder
2. 





## web application demo
1. need to start cuckoo server (follow the documents)
2. run `python3 app.py`

# about this project

this project already have pre-trained model for test and demo

## workflow
1. Fetch jason report from cuckoo
2. Perform feature extraction as mentioned in paper about RAMD to preparing data before training model
3. Training model with preprocessed data `train.py`
4. Test the model with preprocessed data `test.py`
5. Demo by running `app.py`, upload executable file to the application
   1. Application will sent this file to cuckoo sandbox
   2. Cuckoo sandbox run this file, perform analyze and create report
   3. Application fetch the json report and perform preprocessing data to convert data into suitable format before test
   4. Application feed the model with pre-processed file to perform classification

# setup
1. Setup virtual environment and install requirements packages
2. Training
   1. Preparing cuckoo report (of benign and malware sample) for training and testing, put them in the folder structure as below
      ./DATA
      ├───ben_test
      ├───ben_train
      ├───mal_test
      ├───mal_train
      └───processed
   2. Preprocessing data into suiteble format for training and testing
   3. Run `train.py` for training model
3. Testing
   1. Ensure the testing data is processed
   2. Run `test.py` and feed them testing data for evaluate model
4. Demo
   1. Setup cuckoo following the instruction in docs, NAT network configuration and expose cuckoo app to 0.0.0.0
   2. Run `app.py` for demo

