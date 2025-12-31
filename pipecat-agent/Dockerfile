# Pipecat Cloud agent image
# NOTE: Pipecat Cloud expects Linux/ARM64 images.
#
# We intentionally base on the last-known-good image in this repo to avoid re-uploading
# a large dependency layer to Docker Hub (which has been failing intermittently).
FROM truesip/agenttalkusa:ambience-2025-12-26

WORKDIR /app

COPY requirements.txt ./requirements.txt
# Use BuildKit cache for faster rebuilds (cache is not persisted in the final image)
RUN --mount=type=cache,target=/root/.cache/pip pip install -r requirements.txt

COPY bot.py ./bot.py
