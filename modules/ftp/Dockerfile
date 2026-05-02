FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends vsftpd && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -M -d /home/vsftpd/ftpuser -s /bin/false ftpuser && \
    echo "ftpuser:ftppass" | chpasswd && \
    echo "/bin/false" >> /etc/shells

# Explicit PAM config — avoids @include common-auth chain issues in slim images
RUN printf 'auth required pam_unix.so\naccount required pam_unix.so\nsession required pam_unix.so\n' \
    > /etc/pam.d/vsftpd

RUN mkdir -p /var/run/vsftpd/empty

COPY modules/ftp/conf/vsftpd.conf /etc/vsftpd.conf

RUN printf '#!/bin/bash\ntouch /var/log/vsftpd.log\nchmod 644 /var/log/vsftpd.log\nexec /usr/sbin/vsftpd /etc/vsftpd.conf\n' \
    > /usr/local/bin/start-ftp.sh && chmod +x /usr/local/bin/start-ftp.sh

EXPOSE 21

CMD ["/usr/local/bin/start-ftp.sh"]
