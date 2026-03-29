FROM python:3.11-slim

LABEL maintainer="Kinetic Project"
LABEL description="Kinetic Strike Engine — offensive MCP gateway"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install system dependencies and security tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei.
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(wget -qO- https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d '"' -f4 | sed 's/v//')_linux_amd64.zip -O /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

# Install ffuf.
RUN wget -q https://github.com/ffuf/ffuf/releases/latest/download/ffuf_$(wget -qO- https://api.github.com/repos/ffuf/ffuf/releases/latest | grep tag_name | cut -d '"' -f4 | sed 's/v//')_linux_amd64.tar.gz -O /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf \
    && rm /tmp/ffuf.tar.gz \
    && chmod +x /usr/local/bin/ffuf

# Create log directory.
RUN mkdir -p /tmp/kinetic/logs

WORKDIR /app

# Install Python dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code.
COPY app/ ./app/
COPY mcp/ ./mcp/
COPY tools/ ./tools/

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
