FROM debian:12

RUN apt-get update \
 && apt-get install -y --no-install-recommends nginx libnginx-mod-http-lua \
 && rm -rf /var/lib/apt/lists/*

COPY files/ /

EXPOSE 80

CMD [ "nginx", "-g", "daemon off;"]

