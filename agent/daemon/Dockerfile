FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && curl -fsSL https://download.docker.com/linux/static/stable/$(uname -m)/docker-27.5.1.tgz \
       | tar xz --strip-components=1 -C /usr/local/bin docker/docker \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN adduser --disabled-password --gecos "" agentuser

COPY log_parser.py agent_daemon.py /app/

RUN mkdir -p /var/lib/melissae /etc/melissae/certs /logs \
    && chown -R agentuser:agentuser /var/lib/melissae /app

EXPOSE 8444

ENTRYPOINT ["python", "agent_daemon.py", "--config"]
CMD ["/etc/melissae/config.yml"]
