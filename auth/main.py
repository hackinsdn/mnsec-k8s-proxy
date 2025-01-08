from flask import Flask

from auth_api import api as auth_api
from k8s_api import api as k8s_api

app = Flask(__name__)
app.register_blueprint(auth_api, url_prefix='/auth')
app.register_blueprint(k8s_api, url_prefix='/k8s_api')
app.authnz_pods = {}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
