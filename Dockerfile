FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY init_db.py .
COPY static/ ./static/

# Create data directory
RUN mkdir -p /app/data

# Environment variables
ENV DATABASE_PATH=/app/data/kronos.db
ENV FLAG=AdwaCTF{kr0n0s_4lg_n0ne_bypass_m4st3r}
ENV PORT=5000

# Copy entrypoint
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]
