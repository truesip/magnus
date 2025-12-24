# Pipecat Cloud agent image
# NOTE: Pipecat Cloud expects Linux/ARM64 images.
FROM dailyco/pipecat-base:latest-py3.11

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py ./bot.py
