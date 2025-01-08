import traceback
from datetime import datetime, timedelta

from flask import Blueprint, request, g
from flask import current_app
from flask import abort
from flask import make_response
import jwt
import requests
import time
import os
from functools import wraps

api = Blueprint('auth_api', __name__)

EXEMPT_METHODS = {"OPTIONS"}
K8S_APIURL = os.environ.get("K8S_APIURL", "https://kubernetes.default.svc/api")
K8S_CERT = os.environ.get("K8S_CERT", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")

def get_pod_from_authz_header(authz_h):
    try:
        data = jwt.decode(authz_h.split()[1], options={"verify_signature": False})
        return data['kubernetes.io']['pod']
    except:
        return None

def check_authorization():
    try:
        authz_h = request.headers["Authorization"]
        assert authz_h.startswith("Bearer ")
    except:
        print(f"Failed to get authorization headers from request: {request.headers}")
        return False
    pod = get_pod_from_authz_header(authz_h)
    if not pod:
        print(f"Unrecognized client ID from authz header: {authz_h}")
        return False
    seen_pod = current_app.authnz_pods.get(pod["uid"])
    if seen_pod and time.time() - seen_pod["last_update"] < 300:
        g.k8s_owner = pod["uid"]
        return True
    try:
        res = requests.get(K8S_APIURL, headers={"Authorization": authz_h}, verify=K8S_CERT, timeout=5)
        assert res.status_code == 200
    except Exception as exc:
        print(f"Failed to authenticate with kubernetes: {exc}")
        return False
    g.k8s_owner = pod["uid"]
    current_app.authnz_pods[pod['uid']] = {"last_update": time.time(), "authz_h": authz_h, "name": pod["name"]}
    return True

def login_required(func):
    """Based on Flask-Login lib, ensure a Bearer Token Auth on K8s"""
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if request.method in EXEMPT_METHODS:
            pass
        elif not check_authorization():
            abort(401)

        # flask 1.x compatibility
        # current_app.ensure_sync is only available in Flask >= 2.0
        if callable(getattr(current_app, "ensure_sync", None)):
            return current_app.ensure_sync(func)(*args, **kwargs)
        return func(*args, **kwargs)

    return decorated_view


@api.get('/')
@login_required
def login():
    resp = make_response({}, 200)
    resp.headers['X-K8S-OWNER'] = g.k8s_owner
    return resp
