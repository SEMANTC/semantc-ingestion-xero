# use the official python image as the base
FROM python:3.11-slim

# set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app"

# set work directory
WORKDIR /app

# install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# copy and install python dependencies
COPY xero_python/requirements.txt ./requirements.txt

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# copy application code
COPY xero_python/ ./xero_python/

# create a non-root user
RUN adduser --disabled-password appuser && \
    chown -R appuser:appuser /app

# switch to non-root user
USER appuser

# set environment variables (to be overridden at runtime)
ENV USER_ID=""
ENV PROJECT_ID=""
ENV TOKEN_ENCRYPTION_KEY=""
ENV CLOUD_RUN_REGION="us-central1"

# set work directory to where main.py is located
WORKDIR /app/xero_python

# run the application
CMD ["python", "-u", "main.py"]
