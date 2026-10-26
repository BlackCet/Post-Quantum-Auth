#!/bin/sh
set -eu

umask 077
mkdir -p /tls-certs/pq
mkdir -p /tls-certs/classical

generate_profile() {
    destination="$1"
    key_algorithm="$2"
    ca_subject="$3"
    files="ca.key ca.crt gateway.key gateway.crt hospital.key hospital.crt pharma.key pharma.crt"
    found=0
    for file in $files; do
        if [ -e "$destination/$file" ]; then
            found=$((found + 1))
        fi
    done

    if [ "$found" -eq 8 ]; then
        echo "Keeping existing credentials in $destination"
    elif [ "$found" -ne 0 ]; then
        echo "Refusing to overwrite incomplete credential set in $destination" >&2
        exit 1
    else
        workdir="$(mktemp -d)"
        trap 'rm -rf "$workdir"' EXIT HUP INT TERM
        cd "$workdir"

        generate_key() {
            if [ "$key_algorithm" = "EC" ]; then
                openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"
            else
                openssl genpkey -algorithm "$key_algorithm" -out "$1"
            fi
        }

        generate_key ca.key
        openssl req -new -x509 -key ca.key -out ca.crt \
            -subj "$ca_subject" -days 365 \
            -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
            -addext "keyUsage=critical,keyCertSign,cRLSign"

        generate_key gateway.key
        openssl req -new -key gateway.key -out gateway.csr -subj "/CN=gateway" \
            -addext "subjectAltName=DNS:gateway,DNS:tls-proxy,DNS:localhost,IP:127.0.0.1" \
            -addext "basicConstraints=critical,CA:FALSE" \
            -addext "keyUsage=critical,digitalSignature" \
            -addext "extendedKeyUsage=serverAuth"
        openssl x509 -req -in gateway.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
            -out gateway.crt -days 365 -copy_extensions copy

        for client in hospital pharma; do
            generate_key "$client.key"
            openssl req -new -key "$client.key" -out "$client.csr" -subj "/CN=$client" \
                -addext "basicConstraints=critical,CA:FALSE" \
                -addext "keyUsage=critical,digitalSignature" \
                -addext "extendedKeyUsage=clientAuth"
            openssl x509 -req -in "$client.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
                -out "$client.crt" -days 365 -copy_extensions copy
        done

        mkdir -p "$destination"
        cp $files "$destination/"
        chmod 600 "$destination"/*.key
        chmod 644 "$destination"/*.crt
        cd /
        rm -rf "$workdir"
        trap - EXIT HUP INT TERM
    fi
    if [ ! -e "$destination/ticket.key" ]; then
        openssl rand -out "$destination/ticket.key" 80
        chmod 600 "$destination/ticket.key"
    fi
}

generate_profile /tls-certs/pq ML-DSA-65 "/CN=Pharma PQ TLS Lab CA"
generate_profile /tls-certs/classical EC "/CN=Pharma Classical TLS Lab CA"

generate_backend_profile() {
    destination="$1"
    key_algorithm="$2"
    ca_subject="$3"
    files="ca.key ca.crt proxy.key proxy.crt gateway-1.key gateway-1.crt gateway-2.key gateway-2.crt gateway-3.key gateway-3.crt"
    found=0
    for file in $files; do
        if [ -e "$destination/$file" ]; then
            found=$((found + 1))
        fi
    done

    if [ "$found" -eq 10 ]; then
        echo "Keeping existing backend credentials in $destination"
        return
    elif [ "$found" -ne 0 ]; then
        echo "Refusing to overwrite incomplete backend credential set in $destination" >&2
        exit 1
    fi

    workdir="$(mktemp -d)"
    trap 'rm -rf "$workdir"' EXIT HUP INT TERM
    cd "$workdir"

    generate_key() {
        if [ "$key_algorithm" = "EC" ]; then
            openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"
        else
            openssl genpkey -algorithm "$key_algorithm" -out "$1"
        fi
    }

    generate_key ca.key
    openssl req -new -x509 -key ca.key -out ca.crt \
        -subj "$ca_subject" -days 365 \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"

    generate_key proxy.key
    openssl req -new -key proxy.key -out proxy.csr -subj "/CN=proxy-client" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature" \
        -addext "extendedKeyUsage=clientAuth"
    openssl x509 -req -in proxy.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out proxy.crt -days 365 -copy_extensions copy

    for gateway in gateway-1 gateway-2 gateway-3; do
        generate_key "$gateway.key"
        openssl req -new -key "$gateway.key" -out "$gateway.csr" -subj "/CN=$gateway" \
            -addext "subjectAltName=DNS:gateway.internal,IP:127.0.0.1" \
            -addext "basicConstraints=critical,CA:FALSE" \
            -addext "keyUsage=critical,digitalSignature" \
            -addext "extendedKeyUsage=serverAuth"
        openssl x509 -req -in "$gateway.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
            -out "$gateway.crt" -days 365 -copy_extensions copy
    done

    mkdir -p "$destination"
    cp $files "$destination/"
    chmod 600 "$destination"/*.key
    chmod 644 "$destination"/*.crt
    cd /
    rm -rf "$workdir"
    trap - EXIT HUP INT TERM
}

generate_backend_profile /tls-certs/pq/backend ML-DSA-65 "/CN=Pharma PQ Backend CA"
generate_backend_profile /tls-certs/classical/backend EC "/CN=Pharma Classical Backend CA"

echo "TLS test credentials are ready in /tls-certs/pq (ML-DSA-65) and /tls-certs/classical (P-256)."
echo "Keep these demo credentials private; they are not production PKI."
