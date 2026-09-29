FROM python:3.12-slim

WORKDIR /app

# Install system build dependencies and libpcap for passive capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements (core dashboard + ThreatCore ML dependencies)
COPY requirements.txt requirements-ml.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt -r requirements-ml.txt

# Copy application files
COPY . .

# Expose default port
EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=8000
ENV DIODE_DASHBOARD_MODE=live

# Use production entrypoint
CMD ["python", "-m", "dashboard", "--host", "0.0.0.0", "--port", "8000"]
