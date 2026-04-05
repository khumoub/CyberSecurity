FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap nikto sslscan curl wget git whois dnsutils net-tools \
    masscan netdiscover arp-scan \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /tmp/leruo-scans

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
