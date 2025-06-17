
# ---------------------------------------------------------------
#
# ---------------------------------------------------------------

FROM nginx:stable-alpine

# For Grafana
ENV API_HOST=gnat_dashboard
ENV API_PORT=3001

## For Galileo proxy -- change defaults below
ENV GALILEO_HOST=gnat_dashboard
ENV GALILEO_PORT=3000
ENV GALILEO_SSL=/C=US/ST=Virginia/L=Crozet/O=Fidelis Farm/OU=Galileo Toolkit/CN=localhost/

## Generate certificate
RUN apk add --update openssl && \
    rm -rf /var/cache/apk/*
RUN openssl req -x509 -out /etc/nginx/ssl.crt -keyout /etc/nginx/ssl.key -newkey rsa:4096 -nodes -sha256 -subj ${GALILEO_SSL}
    
## Copy configuration
COPY ./etc/default.conf /etc/nginx/templates/default.conf.template
COPY ./etc/conf.d /etc/nginx/conf.d

CMD ["nginx", "-g", "daemon off;"]
