FROM python:3.11-slim

# Install system inspection tools (ExifTool, ffprobe) and ca-certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    libimage-exiftool-perl \
    ffmpeg \
    curl \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-root user for security
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/storage_data && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
