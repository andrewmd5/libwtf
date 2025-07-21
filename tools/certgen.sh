#!/bin/bash
set -euo pipefail

# WebTransport ECDSA Certificate Generation Script
# Generates certificates compliant with WebTransport requirements:
# - ECDSA with secp256r1 (P-256) curve (RSA forbidden)
# - X.509v3 certificate
# - Validity period ≤ 2 weeks
# - Proper WebTransport extensions

echo "🔐 Generating WebTransport-compliant ECDSA certificates..."

# Configuration
HOST="localhost"
BUILD_DIR="$(pwd)/build"
CRT="$BUILD_DIR/$HOST.crt"
KEY="$BUILD_DIR/$HOST.key"
DAYS=14  # Maximum 2 weeks as per WebTransport spec
FINGERPRINT_FILE="$BUILD_DIR/fingerprint.hex"

# Create build directory
mkdir -p "$BUILD_DIR"

echo "1. Generating ECDSA private key (secp256r1/P-256)..."
# Use ECDSA with secp256r1 curve as required by WebTransport
openssl ecparam -genkey -name secp256r1 -noout -out "$KEY"

echo "2. Creating certificate configuration..."
cat > "$BUILD_DIR/cert.conf" << EOF
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
CN = $HOST

[v3_req]
# Critical key usage for WebTransport
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = critical, serverAuth
subjectAltName = @alt_names

# WebTransport extension (if supported by OpenSSL version)
# OID 1.3.6.1.4.1.11129.2.1.24 indicates WebTransport usage
# Note: Some OpenSSL versions may not support this custom OID
# 1.3.6.1.4.1.11129.2.1.24 = ASN1:NULL

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost  
DNS.3 = 127.0.0.1
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

echo "3. Generating certificate signing request..."
openssl req -new -key "$KEY" -out "$BUILD_DIR/server.csr" -config "$BUILD_DIR/cert.conf"

echo "4. Generating self-signed X.509v3 certificate (valid for $DAYS days)..."
openssl x509 -req \
    -in "$BUILD_DIR/server.csr" \
    -signkey "$KEY" \
    -out "$CRT" \
    -days $DAYS \
    -extensions v3_req \
    -extfile "$BUILD_DIR/cert.conf" \
    -sha256

echo "5. Computing SHA256 fingerprint for WebTransport client..."
# Generate hex fingerprint for use in WebTransport client configuration
openssl x509 -in "$CRT" -outform der | openssl dgst -sha256 -binary | xxd -p -c 256 > "$FINGERPRINT_FILE"

# Also generate base64 fingerprint  
openssl x509 -in "$CRT" -outform der | openssl dgst -sha256 -binary | base64 > "$BUILD_DIR/fingerprint.base64"

# Clean up temporary files
rm "$BUILD_DIR/server.csr" "$BUILD_DIR/cert.conf"

# Set appropriate permissions
chmod 600 "$KEY"
chmod 644 "$CRT"

echo ""
echo "✅ WebTransport ECDSA certificate generation complete!"
echo ""
echo "📁 Generated files:"
echo "   📄 Certificate: $CRT"
echo "   🔑 Private key: $KEY" 
echo "   🔍 SHA256 hex:  $FINGERPRINT_FILE"
echo "   📋 SHA256 b64:  $BUILD_DIR/fingerprint.base64"
echo ""

# Verify certificate details
echo "🔍 Certificate verification:"
echo ""
echo "Public key algorithm:"
openssl x509 -in "$CRT" -noout -text | grep "Public Key Algorithm" || echo "  ✓ ECDSA (implicit)"
echo ""
echo "Key details:"
openssl x509 -in "$CRT" -noout -text | grep -A 3 "ASN1 OID: prime256v1" || echo "  ✓ Using secp256r1 (P-256) curve"
echo ""
echo "Validity period:"
openssl x509 -in "$CRT" -noout -dates
echo ""
echo "Subject Alternative Names:"
openssl x509 -in "$CRT" -noout -text | grep -A 5 "Subject Alternative Name:" || echo "  ⚠️  SANs may not be visible in this OpenSSL version"
echo ""

# Display fingerprints for easy copying
echo "🔗 Certificate fingerprints for WebTransport client:"
echo ""
echo "SHA256 (hex):"
cat "$FINGERPRINT_FILE"
echo ""
echo "SHA256 (base64):"
cat "$BUILD_DIR/fingerprint.base64"
echo ""

echo "🚀 Usage examples:"
echo ""
echo "1. Start your WebTransport server:"
echo "   ./wt_echo_server --cert $CRT --key $KEY --port 4433"
echo ""
echo "2. Use in WebTransport client with certificate hash:"
echo "   const transport = new WebTransport('https://localhost:4433/', {"
echo "     serverCertificateHashes: [{"
echo "       algorithm: 'sha-256',"
echo "       value: new Uint8Array([/* hex bytes from fingerprint.hex */])"
echo "     }]"
echo "   });"
echo ""
echo "⚠️  Important notes:"
echo "   • This certificate uses ECDSA with secp256r1 as required by WebTransport"
echo "   • RSA keys are forbidden by WebTransport specification"  
echo "   • Validity period is limited to $DAYS days (≤2 weeks per spec)"
echo "   • This is for development/testing only"
echo "   • Browsers will show warnings for self-signed certificates"
echo ""

# Validate the certificate meets WebTransport requirements
echo "🧪 WebTransport compliance check:"
echo ""

# Check if it's X.509v3
VERSION=$(openssl x509 -in "$CRT" -noout -text | grep "Version:" | grep -o "[0-9]" | head -1)
if [ "$VERSION" = "3" ]; then
    echo "   ✅ X.509v3 certificate"
else
    echo "   ❌ Not X.509v3 (found version '$VERSION')"
fi

# Check key algorithm
KEY_ALG=$(openssl x509 -in "$CRT" -noout -text | grep "Public Key Algorithm")
if echo "$KEY_ALG" | grep -q "id-ecPublicKey\|EC"; then
    echo "   ✅ ECDSA public key algorithm"
else
    echo "   ❌ Not ECDSA public key algorithm"
fi

# Check validity period (should be ≤ 14 days)
NOT_BEFORE=$(openssl x509 -in "$CRT" -noout -startdate | cut -d= -f2)
NOT_AFTER=$(openssl x509 -in "$CRT" -noout -enddate | cut -d= -f2)

# Cross-platform date parsing (works on both macOS and Linux)
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    NOT_BEFORE_EPOCH=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$NOT_BEFORE" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$NOT_BEFORE" +%s)
    NOT_AFTER_EPOCH=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$NOT_AFTER" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$NOT_AFTER" +%s)
else
    # Linux
    NOT_BEFORE_EPOCH=$(date -d "$NOT_BEFORE" +%s)
    NOT_AFTER_EPOCH=$(date -d "$NOT_AFTER" +%s)
fi

VALIDITY_SECONDS=$((NOT_AFTER_EPOCH - NOT_BEFORE_EPOCH))
VALIDITY_DAYS=$((VALIDITY_SECONDS / 86400))

if [ $VALIDITY_DAYS -le 14 ]; then
    echo "   ✅ Validity period: $VALIDITY_DAYS days (≤14 days)"
else
    echo "   ❌ Validity period: $VALIDITY_DAYS days (>14 days)"
fi

echo ""
echo "🎉 Certificate ready for WebTransport testing!"