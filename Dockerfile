FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        gnupg \
        apt-transport-https \
        ca-certificates \
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] \
       https://packages.cloud.google.com/apt cloud-sdk main" \
       > /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg \
       | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
    && apt-get update && apt-get install -y --no-install-recommends \
        google-cloud-cli \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install CPU-only PyTorch before requirements.txt to avoid pulling the 2 GB CUDA wheel
RUN pip install --no-cache-dir \
    torch==2.3.0 --index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Copy only inference artifacts from the CryptoBERT model directory.
# The 5 checkpoint subdirectories (~3.8 GB) are training artifacts and are excluded.
COPY data/models/cryptobert-streamjacking/config.json \
     data/models/cryptobert-streamjacking/model.safetensors \
     data/models/cryptobert-streamjacking/tokenizer.json \
     data/models/cryptobert-streamjacking/tokenizer_config.json \
     data/models/cryptobert-streamjacking/training_args.bin \
     data/models/cryptobert-streamjacking/calibration.json \
     data/models/cryptobert-streamjacking/training_results.json \
     ./data/models/cryptobert-streamjacking/

RUN mkdir -p data/results data/analysis

COPY scripts/run_job.sh ./scripts/run_job.sh
RUN chmod +x ./scripts/run_job.sh

ENV PYTHONPATH=/app/src

ENTRYPOINT ["/app/scripts/run_job.sh"]
