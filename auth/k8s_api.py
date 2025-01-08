import traceback
from datetime import datetime, timedelta

from flask import Blueprint, request, Response
from flask import current_app
from flask import abort
import jwt
import requests
import time
import os
import json
import re
from functools import wraps

API_URL = "k8s_api"
API_HOST = "http://127.0.0.1:8002"
K8S_NAMESPACE = ""

api = Blueprint(API_URL, __name__)

if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/namespace"):
    K8S_NAMESPACE = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read()
K8S_NAMESPACE = os.environ.get("K8S_NAMESPACE", K8S_NAMESPACE)

def clean_headers(orig_headers):
    """Clean request headers by excluding all "hop-by-hop headers" defined by
    RFC 2616 (https://www.rfc-editor.org/rfc/rfc2616#section-13.5.1)"""
    excluded_headers = [
        'content-encoding', 'content-length', 'transfer-encoding', 'connection'
    ]  
    return [
        (k,v) for k,v in orig_headers.items()
        if k.lower() not in excluded_headers
    ]

def check_authz_del_pod(path, owner):
    try:
        res = requests.get(f"{API_HOST}/{path}", timeout=10)
        filter_pod(res.json(), owner)
    except Exception as exc:
        print(f"[ERROR] Exception while getting pod info ({path}): {exc}")
        return False
    return True

def check_pod_creation(data, owner):
    errors = []

    try:
        data = json.loads(data.decode())
    except Exception as exc:
        err = traceback.format_exc().replace("\n", ", ")
        print(f"[ERROR] error parsing pod data for create: {exc} - {err}")
        return ["Failed to parse pod data"]

    try:
        res = requests.get(f"{API_URL}/api/v1/namespaces/{K8S_NAMESPACE}/configmaps/mnsec-proxy-settings", timeout=10)
        assert res.status_code == 200
        settings = json.loads(res.json()["data"])
    except:
        settings = {}

    deny_images = settings.get("_global", {}).get("deny_images", [])
    allow_images = settings.get("_global", {}).get("allow_images", [])

    # check for allow/deny container attributes
    for container in data["spec"]["containers"]:
        if container["image"] in deny_images:
            errors.append(f"Image {container['image']} not allowed")
        if allow_images and container["image"] not in allow_images:
            errors.append(f"Image {container['image']} not allowed")
        if "volumeMounts" in container:
            errors.append("Not allowed to mount volumes")

    # dont allow users to mount volumes to avoid security breaches
    if "volumes" in data["spec"]:
        errors.append("Not allowed to define volumes")

    # pods created by mnsec-proxy require ownerReferences:
    try:
        filter_pod(data, owner)
    except Exception as exc:
        errors.append("Pod metadata does not include ownerReferences (mandatory!)")

    return errors

def filter_pod(data, owner):
    for own_ref in data["metadata"].get("ownerReferences", []):
        if own_ref["uid"] == owner:
            return True
    raise ValueError(f"Unauthorized access to {data['metadata']['name']} by {owner}")

def filter_pod_list(data, owner):
    pods = data["items"]
    data["items"] = []
    for pod in pods:
        authorized = False
        for own_ref in pod["metadata"].get("ownerReferences", []):
            if own_ref["uid"] == owner:
                authorized = True
        if authorized:
            data["items"].append(pod)

def filter_pod_table(data, owner):
    pods = data["rows"]
    data["rows"] = []
    for pod in pods:
        authorized = False
        for own_ref in pod["object"]["metadata"].get("ownerReferences", []):
            if own_ref["uid"] == owner:
                authorized = True
        if authorized:
            data["rows"].append(pod)

def filter_pods(data, owner):
    filter_handler = {
        "PodList": filter_pod_list,
        "Pod": filter_pod,
        "Table": filter_pod_table,
    }
    try:
        filter_handler[data["kind"]](data, owner)
    except Exception as exc:
        err = traceback.format_exc().replace("\n", ", ")
        print(f"[ERROR] error parsing pods: {exc} - {err}")
        data = {
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "reason": "NotFound",
            "details": {},
            "message": f"pods you request were not found",
            "code": 404,
        }
    return json.dumps(data, indent=2).encode()

@api.route('/<path:path>', methods=["GET", "POST", "DELETE"])
def wrapper_request(path):
    msg_failure = {
      "kind": "Status",
      "apiVersion": "v1",
      "metadata": {},
      "status": "Failure",
      "message": "forbidden: Failed to identify user from token",
      "reason": "Forbidden",
      "details": {},
      "code": 400,
    }

    req_type = "unknown"
    if re.match(r"^api/v1/namespaces/[a-zA-Z0-9-]+/pods$", path):
        if request.method == "GET":
            req_type = "list_namespaced_pod"
        elif request.method == "POST":
            req_type = "create_namespaced_pod"
        elif request.method == "DELETE":
            req_type = "delete_namespaced_pod"
    elif re.match(r"^api/v1/namespaces/[a-zA-Z0-9-]+/pods/[a-zA-Z0-9-]+$", path):
        req_type = "read_namespaced_pod"
    elif re.match(r"^openapi/(v2|v3)$", path):
        req_type = "openapi_validator"
    elif re.match(r"^api/v1$", path):
        req_type = "get_api_resources"
    elif re.match(r"^(api|apis)$", path):
        req_type = "get_api_versions"
    elif re.match(r"^apis/authorization\.k8s\.io/v1/selfsubjectaccessreviews$", path):
        req_type = "create_self_subject_access_review"

    if req_type == "unknown":
        msg_failure["message"] = "Failed to handle request: unknown method"
        print(f"[WARN] Unknown request method {path=} {request.url=}")
        return msg_failure, 400

    owner = request.headers.get("X-K8s-Owner")
    if not owner:
        msg_failure["message"] = "Failed to identify user from token"
        return msg_failure, 400

    if req_type == "create_namespaced_pod":
        errors = check_pod_creation(request.get_data(), owner)
        if errors:
            msg_failure["message"] = f"Failed to create pod: {errors}"
            print(f"[WARN] Failed to create pod; {errors=} {request.get_data()=}")
            return msg_failure, 400
    elif req_type == "delete_namespaced_pod":
        if not check_authz_del_pod(path, owner):
            msg_failure["message"] = "Unauthorized to delete pod"
            print(f"[WARN] Failed to delete pod {owner=} {path=}")
            return msg_failure, 400

    res = requests.request(
        method          = request.method,
        url             = request.url.replace(request.host_url + API_URL, API_HOST),
        headers         = {k:v for k,v in request.headers if k.lower() != 'host'},  # exclude 'host' header
        data            = request.get_data(),
        cookies         = request.cookies,
        allow_redirects = False,
    )

    content = res.content
    if req_type in ["list_namespaced_pod", "read_namespaced_pod"]:
        content = filter_pods(res.json(), owner)

    response = Response(content, res.status_code, clean_headers(res.raw.headers))
    return response
