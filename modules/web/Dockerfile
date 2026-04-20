FROM httpd:2.4-alpine

RUN apk update && apk upgrade && \
    apk add --no-cache apache2-utils

RUN deluser www-data && \
    adduser -D -H -u 1000 -s /sbin/nologin www-data

COPY --chown=www-data:www-data ./modules/web/server/ /usr/local/apache2/htdocs/

COPY modules/web/conf/web.conf /usr/local/apache2/conf/httpd.conf

RUN mkdir -p /usr/local/apache2/logs && \
    chown -R www-data:www-data /usr/local/apache2 && \
    chmod -R 755 /usr/local/apache2/htdocs && \
    chmod -R 755 /usr/local/apache2/logs

RUN sed -i 's/^User.*/User www-data/' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's/^Group.*/Group www-data/' /usr/local/apache2/conf/httpd.conf

RUN sed -i \
    -e 's/^ServerTokens OS/ServerTokens Prod/' \
    -e 's/^ServerSignature On/ServerSignature Off/' \
    /usr/local/apache2/conf/httpd.conf

RUN echo "ServerName localhost" >> /usr/local/apache2/conf/httpd.conf

EXPOSE 80

USER www-data

CMD ["httpd-foreground"]
