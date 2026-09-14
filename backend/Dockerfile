# syntax=docker/dockerfile:1
# Backend: FastAPI risk engine + NIST RAG store, built into the image.
# Works on amd64 and arm64 (Oracle Ampere) — no arch-specific pins.
#
# Build context is the REPOSITORY ROOT (see docker-compose.yml) so the image can
# copy both backend/ and the Dataset/ data pack and be fully self-contained.
FROM python:3.11-slim

# Model + KB caches live inside the image so the container starts fast and
# works without network access at runtime.
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/app/.hf \
    SENTENCE_TRANSFORMERS_HOME=/app/.hf \
    DATA_DIR=/app/data \
    DATASET_DIR=/app/Dataset

WORKDIR /app

# Install CPU-only PyTorch first so sentence-transformers does not pull the
# multi-gigabyte CUDA build (this app runs embeddings on CPU). Keeps the image
# small enough for a free-tier VM.
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Install dependencies (better layer caching): pyproject + package.
COPY backend/pyproject.toml ./
COPY backend/app ./app
RUN pip install -e .

# Build script and the data pack (self-contained image).
COPY backend/scripts ./scripts
COPY Dataset ./Dataset

# Build the knowledge base at image-build time: fetch CISA KEV + NIST OSCAL and
# embed ~1,196 controls with bge-small-en-v1.5. Slow, but the runtime container
# then needs no build step and no external fetch.
RUN python scripts/build_kb.py

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
