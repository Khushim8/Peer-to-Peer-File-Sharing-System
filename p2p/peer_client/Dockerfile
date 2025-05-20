FROM python:3.9-slim

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy peer_client code
COPY . .

# Copy blockchain_logger into the container
COPY ../blockchain_logger ./blockchain_logger

CMD ["python", "client.py"]
CMD ["tail", "-f", "/dev/null"]

