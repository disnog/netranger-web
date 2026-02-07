FROM python:3.12-slim

WORKDIR /app

# Install git for pip git dependencies
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir .

# Copy application
COPY nrweb/ ./nrweb/

# Run
EXPOSE 8000
CMD ["uvicorn", "nrweb.main:app", "--host", "0.0.0.0", "--port", "8000"]
