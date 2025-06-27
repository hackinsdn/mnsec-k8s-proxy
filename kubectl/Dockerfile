FROM debian:12

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && curl -L "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl \
 && chmod +x /usr/local/bin/kubectl

EXPOSE 8001

CMD ["kubectl", "proxy", "--port=8001", "--reject-paths='^/api/.*/pods/.*/attach'"]
