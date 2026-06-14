FROM python:3.11-slim

# Prevent python from buffering stdout/stderr outputs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 1. Install prerequisites first (including ca-certificates for secure HTTPS repo connections)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libyara-dev \
    sqlite3 \
    upx-ucl \
    p7zip-full \
    wget \
    git \
    ca-certificates \
    apt-transport-https \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# 2. Add Microsoft repository, force-trust it to bypass 2026 SHA-1 deprecation, and install .NET
RUN wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && echo "deb [trusted=yes] https://packages.microsoft.com/debian/12/prod bookworm main" > /etc/apt/sources.list.d/microsoft-prod.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends dotnet-runtime-8.0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 3. Handle clean pip caching & layer isolation
COPY requirements.txt .
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r requirements.txt

# 4. Provision upcoming bundling tools
RUN wget https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py -O /opt/pyinstxtractor.py

COPY . .

CMD ["python", "pipeline.py"]