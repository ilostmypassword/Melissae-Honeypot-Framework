FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir flask flask-cors pymongo gunicorn

RUN adduser --disabled-password --gecos "" apiuser

COPY api.py /app/api.py

RUN chown -R apiuser:apiuser /app
USER apiuser

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "api:app"]
