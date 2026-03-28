# ─────────────────────────────────────────────────────
#  cyberm4fia-scanner — Docker Image
#  AI-Driven Penetration Testing Platform
# ─────────────────────────────────────────────────────

FROM python:3.12-slim AS base

# System dependencies for Playwright + crypto + parsers
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl git nmap dnsutils whois \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 libatspi2.0-0 libgtk-3-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (Chromium only — saves ~500MB)
RUN playwright install chromium

# Copy scanner source
COPY . .

# Default Ollama URL — connects to host machine
# Override with: docker run -e OLLAMA_URL=http://your-ollama:11434
ENV OLLAMA_URL=http://host.docker.internal:11434
ENV PYTHONUNBUFFERED=1

# Expose API port
EXPOSE 8000

# Default: show help
ENTRYPOINT ["python3", "scanner.py"]
CMD ["--help"]
