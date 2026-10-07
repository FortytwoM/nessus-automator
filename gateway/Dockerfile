FROM nginx:alpine-slim@sha256:3b171d7224b669faa3cc2137fea0a65301791df1ec1f271ebd2a2b7461f7fade

RUN apk upgrade --no-cache \
    && apk add --no-cache curl iproute2 openssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN sed -i 's/\r$//' /docker-entrypoint.sh \
    && chmod +x /docker-entrypoint.sh

EXPOSE 8834

ENTRYPOINT ["/docker-entrypoint.sh"]
