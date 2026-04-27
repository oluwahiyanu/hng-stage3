FROM python:3.11-slim

WORKDIR /app

# Install iptables (needed for blocking)
RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create audit log directory
RUN mkdir -p /var/log/detector

CMD ["python", "main.py"]
