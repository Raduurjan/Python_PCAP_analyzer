FROM python:3.11-slim

# System dependencies for scapy (libpcap) and tshark (optional)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Output directory for reports (mount a volume here in production)
RUN mkdir -p /app/reports

ENTRYPOINT ["python", "analyze.py"]
CMD ["--help"]
