# real-time-entropy
real-time entropy detector written in python for anomaly detection of web-server's and load-balancer's logs
The repository includes 2 main files :
  1. entropy-detector.py
  2. real-time-entropy.py

## How to run
first of all install all dependencies using the following command in python 3.12 :
```
python -m venv venv
source venv/bin/activate
pip install -r req.txt
```
after installation run the following command see all helps:
```
python entropy-detector.py --help
```

to run static entropy detector run :
```
python entropy_detector.py -top 5 -ext txt -ignore-ext pyc test.txt
```
Above command shows you top 5 highest detected entropy, ignore the files with 'pyc' postfix and also takes .txt files.

### Pay attention : 
if you do not pass the specific file , it runs on all files contain in the located directory.

To run dynamic entropy detector run :
```
python real-time-entropy.py -config config.json
```
The command above sends a notification on your telegram which specified at config.json

I am open for any issues.
Hope you enjoy.
