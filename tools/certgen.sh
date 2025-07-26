#!/bin/bash
set -euo pipefail

DEFAULT_HOST="localhost"
DEFAULT_OUTPUT_DIR="./certs"
DEFAULT_DAYS=14

print_header() {
    echo "=================================================="
    echo "$1"
    echo "=================================================="
}

print_section() {
    echo ""
    echo "[$1]"
    echo "--------------------------------------------------"
}

print_item() {
    printf "  %-20s: %s\n" "$1" "$2"
}

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

WebTransport ECDSA Certificate Generator

OPTIONS:
    -h, --host HOSTNAME     Certificate hostname (default: $DEFAULT_HOST)
    -o, --output DIR        Output directory (default: $DEFAULT_OUTPUT_DIR)
    -d, --days DAYS         Validity period in days, max 14 (default: $DEFAULT_DAYS)
    --help                  Show this help message

EXAMPLES:
    $0                                          
    $0 -h example.com -o /tmp/certs            
    $0 --host 192.168.1.100 --days 7          

EOF
}

validate_days() {
    local days=$1
    if [[ ! "$days" =~ ^[0-9]+$ ]] || [ "$days" -lt 1 ] || [ "$days" -gt 14 ]; then
        echo "Error: Days must be a number between 1 and 14" >&2
        exit 1
    fi
}

generate_certificate() {
    local host=$1
    local output_dir=$2
    local days=$3
    
    local crt="$output_dir/$host.crt"
    local key="$output_dir/$host.key"
    local fingerprint_hex="$output_dir/fingerprint.hex"
    local fingerprint_b64="$output_dir/fingerprint.base64"
    local thumbprint_file="$output_dir/thumbprint.hex"
    
    mkdir -p "$output_dir"
    
    print_section "Generating ECDSA Private Key"
    openssl ecparam -genkey -name secp256r1 -noout -out "$key"
    print_item "Key file" "$key"
    
    print_section "Creating Certificate Configuration"
    cat > "$output_dir/cert.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Test State  
L = Test City
O = Test Organization
OU = WebTransport Test
CN = $host

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = critical, serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $host
EOF

    if [[ "$host" == "localhost" ]]; then
        cat >> "$output_dir/cert.conf" << EOF
DNS.2 = *.localhost  
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
    elif [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "IP.1 = $host" >> "$output_dir/cert.conf"
    else
        echo "DNS.2 = *.$host" >> "$output_dir/cert.conf"
    fi
    
    print_section "Generating Certificate"
    openssl req -new -key "$key" -out "$output_dir/server.csr" -config "$output_dir/cert.conf"
    
    openssl x509 -req \
        -in "$output_dir/server.csr" \
        -signkey "$key" \
        -out "$crt" \
        -days "$days" \
        -extensions v3_req \
        -extfile "$output_dir/cert.conf" \
        -sha256
    
    print_item "Certificate" "$crt"
    
    print_section "Generating Fingerprints"
    openssl x509 -in "$crt" -outform der | openssl dgst -sha256 -binary | xxd -p -c 256 > "$fingerprint_hex"
    openssl x509 -in "$crt" -outform der | openssl dgst -sha256 -binary | base64 > "$fingerprint_b64"
    openssl x509 -in "$crt" -outform der | openssl dgst -sha1 -binary | xxd -p -c 256 > "$thumbprint_file"
    
    print_item "SHA256 (hex)" "$fingerprint_hex"
    print_item "SHA256 (base64)" "$fingerprint_b64"
    print_item "SHA1 Thumbprint" "$thumbprint_file"
    
    rm "$output_dir/server.csr" "$output_dir/cert.conf"
    
    chmod 600 "$key"
    chmod 644 "$crt"
}

verify_certificate() {
    local crt=$1
    local days=$2
    
    print_section "Certificate Verification"
    
    if [ ! -f "$crt" ]; then
        echo "Error: Certificate file not found: $crt"
        return 1
    fi
    
    local cert_text=$(openssl x509 -in "$crt" -noout -text 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "Error: Failed to read certificate for verification"
        return 1
    fi
    
    local version=$(echo "$cert_text" | grep "Version:" | grep -o "[0-9]" | head -1)
    if [ "$version" = "3" ]; then
        print_item "X.509 Version" "v3 (OK)"
    else
        print_item "X.509 Version" "v$version (WARNING: Should be v3)"
    fi
    
    local key_alg=$(echo "$cert_text" | grep "Public Key Algorithm")
    if echo "$key_alg" | grep -q "id-ecPublicKey\|EC"; then
        print_item "Key Algorithm" "ECDSA (OK)"
    else
        print_item "Key Algorithm" "Not ECDSA (ERROR)"
    fi
    
    if echo "$cert_text" | grep -q "prime256v1\|secp256r1"; then
        print_item "Curve" "secp256r1/P-256 (OK)"
    else
        print_item "Curve" "Not secp256r1 (WARNING)"
    fi
    
    local not_before=$(openssl x509 -in "$crt" -noout -startdate 2>/dev/null | cut -d= -f2)
    local not_after=$(openssl x509 -in "$crt" -noout -enddate 2>/dev/null | cut -d= -f2)
    
    if [ -n "$not_before" ] && [ -n "$not_after" ]; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            local not_before_epoch=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$not_before" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$not_before" +%s 2>/dev/null)
            local not_after_epoch=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$not_after" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null)
        else
            local not_before_epoch=$(date -d "$not_before" +%s 2>/dev/null)
            local not_after_epoch=$(date -d "$not_after" +%s 2>/dev/null)
        fi
        
        if [ -n "$not_before_epoch" ] && [ -n "$not_after_epoch" ]; then
            local validity_seconds=$((not_after_epoch - not_before_epoch))
            local validity_days=$((validity_seconds / 86400))
            
            if [ $validity_days -le 14 ]; then
                print_item "Validity Period" "$validity_days days (OK)"
            else
                print_item "Validity Period" "$validity_days days (ERROR: >14 days)"
            fi
        else
            print_item "Validity Period" "Unable to parse dates"
        fi
        
        print_item "Valid From" "$not_before"
        print_item "Valid Until" "$not_after"
    else
        print_item "Validity Period" "Unable to read validity dates"
    fi
}

display_certificate_info() {
    local crt=$1
    
    print_section "Certificate Information"
    
    if [ ! -f "$crt" ]; then
        echo "Error: Certificate file not found: $crt"
        return 1
    fi
    
    local cert_text=$(openssl x509 -in "$crt" -noout -text 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "Error: Failed to read certificate"
        return 1
    fi
    
    local subject=$(openssl x509 -in "$crt" -noout -subject 2>/dev/null | sed 's/subject=//')
    local issuer=$(openssl x509 -in "$crt" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    local serial=$(openssl x509 -in "$crt" -noout -serial 2>/dev/null | sed 's/serial=//')
    
    print_item "Subject" "$subject"
    print_item "Issuer" "$issuer"
    print_item "Serial Number" "$serial"
    
    local key_size=$(echo "$cert_text" | grep -A1 "Public Key Algorithm" | grep "Public-Key:" | grep -o "[0-9]\+" | head -1)
    if [ -n "$key_size" ]; then
        print_item "Public Key" "ECC ($key_size Bits)"
    else
        print_item "Public Key" "ECC (256 Bits)"
    fi
    
    if echo "$cert_text" | grep -q "prime256v1"; then
        print_item "Public Key Params" "ECDH_P256"
    fi
    
    local sans=$(echo "$cert_text" | grep -A1 "Subject Alternative Name:" | tail -1 | sed 's/^[[:space:]]*//')
    if [ -n "$sans" ]; then
        print_item "Subject Alt Names" "$sans"
    fi
    
    local ski=$(echo "$cert_text" | grep -A1 "Subject Key Identifier:" | tail -1 | sed 's/^[[:space:]]*//' | tr -d ':')
    if [ -n "$ski" ]; then
        print_item "Subject Key ID" "${ski:0:32}..."
    fi
    
    local key_usage=$(echo "$cert_text" | grep -A1 "Key Usage:" | tail -1 | sed 's/^[[:space:]]*//')
    if [ -n "$key_usage" ]; then
        print_item "Key Usage" "$key_usage"
    fi
    
    local ext_key_usage=$(echo "$cert_text" | grep -A1 "Extended Key Usage:" | tail -1 | sed 's/^[[:space:]]*//')
    if [ -n "$ext_key_usage" ]; then
        print_item "Enhanced Key Usage" "$ext_key_usage"
    fi
}

display_fingerprints() {
    local fingerprint_hex=$1
    local fingerprint_b64=$2
    local thumbprint_file=$3
    
    print_section "Certificate Fingerprints"
    
    if [ ! -f "$thumbprint_file" ]; then
        echo "Error: Thumbprint file not found: $thumbprint_file"
        return 1
    fi
    
    if [ ! -f "$fingerprint_hex" ]; then
        echo "Error: SHA-256 hex file not found: $fingerprint_hex"
        return 1
    fi
    
    if [ ! -f "$fingerprint_b64" ]; then
        echo "Error: SHA-256 base64 file not found: $fingerprint_b64"
        return 1
    fi
    
    echo "SHA-1 Thumbprint (standard):"
    if [ -s "$thumbprint_file" ]; then
        cat "$thumbprint_file" | sed 's/\(..\)/\1:/g' | sed 's/:$//' | tr '[:lower:]' '[:upper:]'
    else
        echo "Error: Empty thumbprint file"
    fi
    echo ""
    
    echo "SHA-256 Fingerprint (hex):"
    if [ -s "$fingerprint_hex" ]; then
        cat "$fingerprint_hex"
    else
        echo "Error: Empty fingerprint file"
    fi
    echo ""
    
    echo "SHA-256 Fingerprint (base64):"
    if [ -s "$fingerprint_b64" ]; then
        cat "$fingerprint_b64"
    else
        echo "Error: Empty fingerprint file"
    fi
    echo ""
}

display_usage_examples() {
    local host=$1
    local crt=$2
    local key=$3
    
    print_section "Usage Examples"
    
    echo "1. Start WebTransport server:"
    echo "   ./wt_echo_server --cert $crt --key $key --port 4433"
    echo ""
    
    echo "2. WebTransport client with certificate hash:"
    echo "   const transport = new WebTransport('https://$host:4433/', {"
    echo "     serverCertificateHashes: [{"
    echo "       algorithm: 'sha-256',"
    echo "       value: new Uint8Array([/* hex bytes from fingerprint.hex */])"
    echo "     }]"
    echo "   });"
    echo ""
    
    echo "NOTES:"
    echo "  - Certificate uses ECDSA with secp256r1 as required by WebTransport"
    echo "  - RSA keys are forbidden by WebTransport specification"
    echo "  - Self-signed certificates will show browser warnings"
    echo "  - For development/testing only"
}

HOST="$DEFAULT_HOST"
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
DAYS="$DEFAULT_DAYS"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host)
            HOST="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -d|--days)
            DAYS="$2"
            validate_days "$DAYS"
            shift 2
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option $1" >&2
            echo "Use --help for usage information" >&2
            exit 1
            ;;
    esac
done

print_header "WebTransport Certificate Generator"

echo "Configuration:"
print_item "Host" "$HOST"
print_item "Output Directory" "$OUTPUT_DIR"
print_item "Validity Days" "$DAYS"

generate_certificate "$HOST" "$OUTPUT_DIR" "$DAYS"

crt="$OUTPUT_DIR/$HOST.crt"
key="$OUTPUT_DIR/$HOST.key"
fingerprint_hex="$OUTPUT_DIR/fingerprint.hex"
fingerprint_b64="$OUTPUT_DIR/fingerprint.base64"
thumbprint_file="$OUTPUT_DIR/thumbprint.hex"

display_certificate_info "$crt"
verify_certificate "$crt" "$DAYS"
display_fingerprints "$fingerprint_hex" "$fingerprint_b64" "$thumbprint_file"
display_usage_examples "$HOST" "$crt" "$key"

print_header "Certificate Generation Complete"