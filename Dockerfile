# ============================
# Stage 1: Builder
# ============================
FROM python:3.11-slim AS builder

# Disable Python bytecode and buffering for cleaner containers
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install build tools (if cryptography needs them)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency file and install dependencies
COPY requirements.txt .

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


# ============================
# Stage 2: Runtime
# ============================
FROM python:3.11-slim

# Set timezone to UTC
ENV TZ=UTC
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies: cron + timezone data
RUN apt-get update && apt-get install -y --no-install-recommends \
        cron \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

# Configure timezone to UTC
RUN ln -snf /usr/share/zoneinfo/Etc/UTC /etc/localtime && \
    echo "Etc/UTC" > /etc/timezone

# Copy installed Python packages from builder stage
COPY --from=builder /usr/local /usr/local

# Copy application code and config into container
COPY main.py crypto_utils.py ./
COPY student_private.pem student_public.pem instructor_public.pem ./

# These will be created in Step 10, but we wire them now
# scripts/   -> cron logging script
# cron/      -> cron configuration file
COPY scripts/ ./scripts/
COPY cron/ /cron/

# Create volume mount points
RUN mkdir -p /data /cron && \
    chmod 755 /data /cron

# Install cron job
# We assume cron/2fa-cron contains a line like:
# * * * * * cd /app && /usr/local/bin/python3 scripts/log_2fa_cron.py >> /cron/last_code.txt 2>&1
RUN chmod 0644 /cron/2fa-cron && \
    crontab /cron/2fa-cron

# Expose API port
EXPOSE 8080

# Start cron and API server
# - cron runs in background
# - uvicorn runs in foreground on port 8080
CMD ["sh", "-c", "cron && uvicorn main:app --host 0.0.0.0 --port 8080"]
