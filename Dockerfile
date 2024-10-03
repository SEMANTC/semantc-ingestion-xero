# Use the official Python image as the base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app"

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY xero_python/requirements.txt ./requirements.txt

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY xero_python/ ./xero_python/

# Create a non-root user
RUN adduser --disabled-password appuser && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Set environment variables (to be overridden at runtime)
ENV CLIENT_ID=""
ENV PROJECT_ID=""
ENV GOOGLE_APPLICATION_CREDENTIALS="/app/service_account.json"

# Mount service account JSON (done at runtime)

# Set work directory to where main.py is located
WORKDIR /app/xero_python

# Run the application
CMD ["python", "-u", "main.py"]