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
    git \
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

# Install Subfinder.
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_$(wget -qO- https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep tag_name | cut -d '"' -f4 | sed 's/v//')_linux_amd64.zip -O /tmp/subfinder.zip \
    && unzip /tmp/subfinder.zip -d /usr/local/bin/ \
    && rm /tmp/subfinder.zip \
    && chmod +x /usr/local/bin/subfinder

# Install Amass.
RUN wget -q https://github.com/owasp-amass/amass/releases/latest/download/amass_Linux_amd64.zip -O /tmp/amass.zip \
    && unzip /tmp/amass.zip -d /tmp/amass \
    && mv /tmp/amass/amass_Linux_amd64/amass /usr/local/bin/amass \
    && rm -rf /tmp/amass /tmp/amass.zip \
    && chmod +x /usr/local/bin/amass

# Install Gitleaks.
RUN wget -q https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_$(wget -qO- https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d '"' -f4 | sed 's/v//')_linux_amd64.tar.gz -O /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin/ gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && chmod +x /usr/local/bin/gitleaks

# Install Semgrep (Python-based).
RUN pip install --no-cache-dir semgrep

# Install Arjun (Python-based).
RUN pip install --no-cache-dir arjun

# Create working directories.
RUN mkdir -p /tmp/kinetic/logs /tmp/kinetic/workspace

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
