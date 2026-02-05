# Pipecat Cloud agent image
# NOTE: Pipecat Cloud expects Linux/ARM64 images.
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for audio processing
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    libsndfile1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
# Use BuildKit cache for faster rebuilds (cache is not persisted in the final image)
RUN --mount=type=cache,target=/root/.cache/pip pip install --no-cache-dir -r requirements.txt

COPY bot.py ./bot.py

CMD ["python", "bot.py"]
