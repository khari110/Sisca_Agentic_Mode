# Standard Python 3.12 slim image
FROM python:3.12-slim

WORKDIR /app

# Update Linux packages and install Virtual Screen & UI dependencies
RUN apt-get update && apt-get install -y \
    xvfb \
    x11vnc \
    novnc \
    websockify \
    fluxbox \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Python automation & Data Science libraries
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    playwright \
    browser-use \
    langchain-google-genai \
    pandas \
    matplotlib \
    seaborn \
    scikit-learn \
    numpy \
    scipy \
    requests

# Install Chromium and its dependencies
RUN playwright install --with-deps chromium

RUN apt-get update && apt-get install -y procps

# Setup environment variables
ENV PYTHONUNBUFFERED=1 \
    DISPLAY=:99 \
    TZ=Asia/Karachi

# Create isolation directories
RUN mkdir -p /app/uploads /app/static/outputs && \
    chmod -R 777 /app/uploads /app/static/outputs

# Copy the boot script into the container and make it executable
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Run the boot script
CMD ["/app/start.sh"]