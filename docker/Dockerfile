FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "src/main.py", "run", "--count", "200", "--output", "logs/events.jsonl", "--alerts-output", "logs/alerts.log"]
