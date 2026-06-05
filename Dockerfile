# Pure standard library — no dependencies.
FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /srv
COPY . .
ENTRYPOINT ["python", "-m", "dlp.cli"]
CMD ["--help"]
