FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir httpx asyncio

COPY trigger.py .

CMD ["python", "trigger.py"]
