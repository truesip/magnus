# Pipecat Cloud agent image
# NOTE: Pipecat Cloud expects Linux/ARM64 images.
#
# IMPORTANT: Pipecat Cloud requires a long-running runner process (app.py) inside the image.
# The last-known-good images in this repo ship /app/app.py and start it by default.
# We layer our bot.py and Python deps on top of that runner image.
FROM truesip/agenttalkusa:ambience-2026-01-19-a7959c8

WORKDIR /app

# Install system dependencies for audio processing (not included in the base runner image)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    libsndfile1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
# Use BuildKit cache for faster rebuilds (cache is not persisted in the final image)
RUN --mount=type=cache,target=/root/.cache/pip pip install --no-cache-dir -r requirements.txt

COPY bot.py ./bot.py

# Do not override CMD; base image starts the Pipecat runner (python app.py)
