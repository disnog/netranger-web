FROM python:3.12-slim

WORKDIR /app

# Install git for pip git dependencies
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY pyproject.toml README.md ./
COPY nrweb/ ./nrweb/
RUN pip install --no-cache-dir .

# Run with gunicorn
EXPOSE 5000
CMD ["gunicorn", "nrweb:app", "--bind", "0.0.0.0:5000", "--workers", "4"]
