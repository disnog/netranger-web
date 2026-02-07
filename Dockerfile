FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir .

# Copy application
COPY nrweb/ ./nrweb/

# Run
EXPOSE 8000
CMD ["uvicorn", "nrweb.main:app", "--host", "0.0.0.0", "--port", "8000"]
