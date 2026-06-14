# 1. Base Image
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 2. Install all system dependencies required for unpacking
RUN apt-get update && apt-get install -y --no-install-recommends \
    upx-ucl \
    p7zip-full \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# 3. Install .NET runtime natively for de4dot
RUN wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \x
    && apt-get update && apt-get install -y dotnet-runtime-8.0 \
    && rm -rf /var/lib/apt/lists/*

# 4. Set standard application working directory
WORKDIR /app

# 5. Copy the unified requirements file and install python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 6. Fetch external tools into globally accessible directories
RUN wget https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py -O /opt/pyinstxtractor.py

RUN wget https://github.com/de4dot/de4dot/releases/download/v3.1.41592/de4dot-v3.1.41592.zip \
    && 7z x de4dot-v3.1.41592.zip -o/opt/de4dot \
    && rm de4dot-v3.1.41592.zip

# 7. Copy the entire main repository into the container
COPY . .

# 8. DEFAULT COMMAND: Run your main repository orchestrator
CMD ["python", "main_pipeline.py"]