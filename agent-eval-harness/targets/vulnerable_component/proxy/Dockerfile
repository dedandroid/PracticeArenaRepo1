# Pure standard library (see app.py's docstring for why no Flask/WSGI) -
# no requirements.txt needed.
FROM python:3.11-slim

WORKDIR /app
COPY app.py .

EXPOSE 5000

CMD ["python", "app.py"]
