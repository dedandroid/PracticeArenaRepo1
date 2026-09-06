FROM python:3.11-slim

WORKDIR /app

# Build context is the repo root (see docker-compose.yml) so this image can
# also copy in ../scoring - the difficulty-weighted milestone ladder the
# dashboard renders alongside the flat, flag-driven milestones. scoring/'s
# only dependency (PyYAML) is already in arena's own requirements.txt.
COPY arena/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY arena/ .
COPY scoring ./scoring

EXPOSE 8000

CMD ["python", "app.py"]
