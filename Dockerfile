FROM python:3.12-slim-trixie

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY docker ./docker
COPY analysis ./analysis
COPY gateway ./gateway
COPY hospital ./hospital
COPY pharma ./pharma
COPY scripts ./scripts
COPY tests ./tests
COPY tls_client.py ./

ENV OPENSSL_CONF=/app/docker/pq-openssl.cnf

RUN python -c "import ssl; assert ssl.OPENSSL_VERSION_INFO >= (3, 5, 0), ssl.OPENSSL_VERSION"
