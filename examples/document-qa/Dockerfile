FROM python:3.12-alpine
RUN adduser -D -u 10001 cinderlock && mkdir -p /data && chown 10001:10001 /data
WORKDIR /app
COPY app.py /app/app.py
COPY models /app/models
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 FIXTURE_DATABASE=/data/app.sqlite
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["python", "/app/app.py"]
CMD ["serve"]
