FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY releasesage/ releasesage/
COPY config/ config/
USER 10001
ENTRYPOINT ["python", "-m", "releasesage"]
CMD ["run"]
