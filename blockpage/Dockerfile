FROM nginx:alpine
RUN apk add --no-cache openssl
COPY default.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
COPY 40-portal.sh /docker-entrypoint.d/40-portal.sh
RUN chmod +x /docker-entrypoint.d/40-portal.sh
