## Auth service

Running manually:
```
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
gunicorn -b 127.0.0.1:5000 main:app --log-level debug
```


With docker:
```
docker build -t hackinsdn/mnsec-proxy-auth .
```
