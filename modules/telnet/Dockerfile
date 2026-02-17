FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y \
        inetutils-telnetd \
        inetutils-inetd \
        rsyslog \
        tcpd \
        procps \
        iproute2 \
        bsdutils && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get purge -y curl wget netcat-openbsd netcat-traditional socat nmap 2>/dev/null || true && \
    rm -f /usr/bin/curl /usr/bin/wget /usr/bin/nc /usr/bin/ncat /usr/bin/socat 2>/dev/null || true

RUN apt-get purge -y gcc g++ make python3 perl ruby 2>/dev/null || true

RUN rm -f /usr/bin/apt /usr/bin/apt-get /usr/bin/dpkg 2>/dev/null || true

RUN rm -f /usr/bin/zsh /usr/bin/fish /usr/bin/csh 2>/dev/null || true

RUN sed -i '/imklog/s/^/#/' /etc/rsyslog.conf

RUN mkdir -p /host-logs/telnet && \
    chmod -R 777 /host-logs/telnet && \
    echo 'auth,authpriv.* /host-logs/telnet/auth.log' >> /etc/rsyslog.d/50-default.conf

RUN sed -i '/pam_loginuid\|pam_securetty/s/^/#/' /etc/pam.d/login

RUN touch /var/log/wtmp /var/log/lastlog && \
    chmod 664 /var/log/wtmp /var/log/lastlog

RUN { \
      echo 'export REMOTE_IP=$(w -h 2>/dev/null | grep "^$(whoami)" | head -1 | awk '"'"'{print $3}'"'"')'; \
      echo '[ -z "$REMOTE_IP" ] && export REMOTE_IP=$(ss -tn 2>/dev/null | grep ":23" | head -1 | awk '"'"'{print $5}'"'"' | cut -d: -f1)'; \
      echo '[ -z "$REMOTE_IP" ] && export REMOTE_IP="unknown"'; \
      echo '_log_cmd() {'; \
      echo '    local cmd=$(history 1 | sed '"'"'s/^[ ]*[0-9]*[ ]*//'"'"')'; \
      echo '    [ -n "$cmd" ] && echo "$(date +"%Y-%m-%d %H:%M:%S") | $REMOTE_IP | $(whoami) | $cmd" >> /host-logs/telnet/commands.log'; \
      echo '}'; \
      echo 'PROMPT_COMMAND='"'"'_log_cmd'"'"''; \
    } > /etc/profile.d/honeypot-logging.sh && chmod +x /etc/profile.d/honeypot-logging.sh

RUN echo 'telnet stream tcp nowait root /usr/sbin/tcpd /usr/sbin/telnetd' >> /etc/inetd.conf

RUN useradd -m -s /bin/bash admin && \
    echo 'admin:telnet' | chpasswd

COPY startup.sh /
RUN chmod +x /startup.sh

EXPOSE 23

ENTRYPOINT ["/startup.sh"]
