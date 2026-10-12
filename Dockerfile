FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PORT=8080 DB_PATH=/data/bank.db
RUN mkdir -p /data
EXPOSE 8080
# One worker keeps SQLite simple; switch to PostgreSQL to scale out.
CMD ["sh", "-c", "gunicorn -w 1 --threads 4 -b 0.0.0.0:${PORT} app:app"]
