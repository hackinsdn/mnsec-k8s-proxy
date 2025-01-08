# mnsec-k8s-proxy

This repo contains a Kubernetes Proxy for Mininet-Sec. It helps deploying Mininet-Sec into Kubernetes for multiple users because it avoid having to share credentials amoung all Mininet-Sec instances. Besides, it applies some sanity checks before listing or creating resources to avoid mis-usage of the cluster.

## Deploy instructions

1. create deployment

```
kubectl create -f manifest.yaml
MNSEC_PROXY=$(kubectl get pods | grep mnsec-proxy | awk '{print $1}')
```

2. configure auth service:
```
kubectl cp auth $MNSEC_PROXY:/app --container auth-service
kubectl exec -it $MNSEC_PROXY --container auth-service -- bash

cd /app/
python3 -m pip install -r requirements.txt
apt-get update && apt-get install --no-install-recommends -y tmux
tmux new-sess -d -n app gunicorn -b 0.0.0.0:5000 main:app --log-level debug
```

3. configure kubectl

```
kubectl exec -it $MNSEC_PROXY --container kubectl-service -- bash

apt-get update && apt-get install -y --no-install-recommends curl ca-certificates tmux
curl -L "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl
chmod +x /usr/local/bin/kubectl
mkdir /root/.kube
cat >/root/.kube/config <EOF
-->> ADD here the config
EOF
tmux new-sess -d -n kubectl kubectl proxy --port=8001 --reject-paths='^/api/.*/pods/.*/attach'
```

4. configure nginx

```
if [ ! -f server-chain.crt ]; then
	bash setup-certs.sh
fi
```

TODO: export ca.crt to configmaps

```
kubectl exec -it $MNSEC_PROXY --container nginx -- bash -c "apt-get update && apt-get install -y --no-install-recommends nginx libnginx-mod-http-lua && service nginx start"
kubectl cp server-chain.crt $MNSEC_PROXY:/etc/nginx/server-chain.crt --container nginx
kubectl cp server.key $MNSEC_PROXY:/etc/nginx/server.key --container nginx
kubectl cp get_req_body.lua $MNSEC_PROXY:/etc/nginx/get_req_body.lua --container nginx
kubectl cp dhparams.pem $MNSEC_PROXY:/etc/nginx/dhparam.pem --container nginx
kubectl cp nginx.conf $MNSEC_PROXY:/etc/nginx/nginx.conf --container nginx

kubectl exec -it $MNSEC_PROXY --container nginx -- bash -c "service nginx start"
```
