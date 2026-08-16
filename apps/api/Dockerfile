FROM python:3.11-slim
RUN useradd --create-home appuser
WORKDIR /app
COPY apps/api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY apps/api/app ./apps/api/app
COPY ml/models/production ./ml/models/production
RUN mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
CMD ["uvicorn","apps.api.app.main:app","--host","0.0.0.0","--port","8000"]
