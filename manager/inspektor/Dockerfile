FROM python:3.11-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV UV_COMPILE_BYTECODE=1
ENV UV_PROJECT_ENVIRONMENT=/app/.venv

COPY pyproject.toml ./
COPY uv.lock* ./
RUN uv sync --no-dev --no-install-project

COPY inspektor.py tools.py config.yml ./
COPY prompts/ ./prompts/
COPY skills/ ./skills/

RUN adduser --disabled-password --gecos "" inspektor \
    && chown -R inspektor:inspektor /app
USER inspektor

EXPOSE 8088

ENTRYPOINT ["uv", "run", "--no-sync", "python", "inspektor.py"]
