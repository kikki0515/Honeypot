FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs data migrations

# Set environment
ENV FLASK_CONFIG=docker
ENV FLASK_APP=run.py
ENV PYTHONUNBUFFERED=1

# Expose ports
EXPOSE 5000 2222 8080 2121

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:5000/auth/login || exit 1

# Init database and run
CMD ["sh", "-c", "flask init-db && python run.py"]
