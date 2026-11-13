FROM python:3.12-slim
WORKDIR /app
COPY secretlens.py /app/secretlens.py
RUN useradd --create-home --uid 10001 appuser
USER appuser
ENTRYPOINT ["python", "/app/secretlens.py"]
