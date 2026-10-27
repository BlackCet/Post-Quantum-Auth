FROM python:3.12-slim-trixie

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl libssl-dev cmake build-essential git \
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
COPY crypto_backend.py packet_auth.py keygen.py ./

ENV OPENSSL_CONF=/app/docker/pq-openssl.cnf
ENV OQS_INSTALL_PATH=/usr/local
ENV PYOQS_VERSION=0.16.0

RUN python -c "import ssl; assert ssl.OPENSSL_VERSION_INFO >= (3, 5, 0), ssl.OPENSSL_VERSION" \
    && git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build /tmp/liboqs/build --parallel 4 \
    && cmake --build /tmp/liboqs/build --target install \
    && ldconfig \
    && rm -rf /tmp/liboqs \
    && python -c "import oqs; assert 'ML-KEM-768' in oqs.get_enabled_kem_mechanisms(); assert 'ML-DSA-65' in oqs.get_enabled_sig_mechanisms()"
