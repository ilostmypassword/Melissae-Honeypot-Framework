FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y openssh-server rsyslog bash && \
    mkdir -p /var/run/sshd

RUN useradd -m -s /bin/bash user && \
    echo 'user:admin' | chpasswd && \
    mkdir -p /home/user/.ssh && \
    chown -R user:user /home/user/.ssh

RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config && \
    echo "Port 22" >> /etc/ssh/sshd_config

RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf

RUN mkdir -p /host-logs/ssh && \
    chmod -R 777 /host-logs/ssh && \
    echo 'auth,authpriv.* /host-logs/ssh/sshd.log' >> /etc/rsyslog.d/50-default.conf

RUN echo 'export PROMPT_COMMAND="history -a >( \
    ip=\$(last -i | grep \$(whoami) | head -n 1 | awk \047{print \$3}\047); \
    echo \$(date +\"%Y-%m-%d %H:%M:%S\") \| \${ip:-\"Unknown IP\"} \| \$(history 1) >> /host-logs/ssh/commands.log)"' \
    >> /home/user/.bashrc && \
    chown user:user /home/user/.bashrc

RUN printf '#!/bin/bash\nrm -f /run/rsyslogd.pid\ntouch /host-logs/ssh/sshd.log /host-logs/ssh/commands.log\nchmod 666 /host-logs/ssh/sshd.log /host-logs/ssh/commands.log\nrsyslogd\nsleep 1\nexec /usr/sbin/sshd -D\n' > /usr/local/bin/start-services.sh && \
    chmod +x /usr/local/bin/start-services.sh

EXPOSE 22

CMD ["/usr/local/bin/start-services.sh"]