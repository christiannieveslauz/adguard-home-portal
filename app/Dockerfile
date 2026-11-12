FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -r -u 10001 app && chown -R app /app
USER app
EXPOSE 8090
HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8090/healthz')"
CMD ["gunicorn", "-b", "0.0.0.0:8090", "-w", "1", "--threads", "4", "app:app"]
