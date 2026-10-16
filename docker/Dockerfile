# Pinned to a digest: the tag moves with every rebuild upstream. To update, take the new digest of
# python:3.11-slim (docker buildx imagetools inspect python:3.11-slim) and regenerate requirements.txt.
FROM python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY docker/requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY app ./app

EXPOSE 5052
VOLUME /data

CMD ["python", "-m", "app.server"]
