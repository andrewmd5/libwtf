# WebTransport Certificates

Getting WebTransport working requires ECDSA certificates. This tool generates temporary development certificates that work with Chrome, Firefox, and Safari.

## Basic Usage

Generate certificates for localhost:

```bash
./certgen.sh
```

This creates several files in `./certs/`:
- `localhost.crt` and `localhost.key` - Certificate and private key
- `localhost.pfx` - Windows-compatible bundle
- `fingerprint.hex` - SHA-256 hash for WebTransport clients
- `thumbprint.hex` - SHA-1 hash for Windows certificate store

## Platform Differences

### macOS and Linux

Load certificates from files:

```c
wtf_certificate_config_t cert_config = {
    .cert_type = WTF_CERT_TYPE_FILE,
    .cert_data.file = {
        .cert_path = "./certs/localhost.crt",
        .key_path = "./certs/localhost.key"
    }
};
```

Safari requires installing the `.crt` file in Keychain Access. Just double-click the file and mark it as trusted.

### Windows

Windows doesn't support file-based certificates. Import the PFX file into your certificate store first:

1. Run `certlm.msc`
2. Go to Personal → Certificates → Import
3. Select your `.pfx` file

Then use the thumbprint:

```c
wtf_certificate_config_t cert_config = {
    .cert_type = WTF_CERT_TYPE_HASH,
    .cert_data.hash = {
        .thumbprint = "A1B2C3..." // From thumbprint.hex
    }
};
```

## WebTransport Client Setup

### Using Certificate Hashes (Chrome/Firefox)

Copy the hex values from `fingerprint.hex` and convert to bytes:

```javascript
const transport = new WebTransport('https://localhost:4433/', {
    serverCertificateHashes: [{
        algorithm: 'sha-256',
        value: new Uint8Array([0xa1, 0xb2, 0xc3, /* ... */])
    }]
});
```

The included `certain.sh` script can test connections immediately.

### Standard PKI (Production)

For production with proper certificates, omit the hash array:

```javascript
const transport = new WebTransport('https://example.com:443/');
```

## Tool Options

Generate for specific hostname:
```bash
./certgen.sh --host example.com
```

Generate for IP address:
```bash
./certgen.sh --host 192.168.1.100
```

Set password on PFX file:
```bash
./certgen.sh --pfx-password mypassword
```

Custom output directory:
```bash
./certgen.sh --output /tmp/certs
```

## Production Considerations

### Hash Pinning Strategy

For Chromium-based browsers, you can skip traditional PKI by providing certificate hashes. The browser trusts any certificate matching the provided hashes.

Pros: No certificate authority needed, works immediately
Cons: Chromium-only, requires distributing hashes to clients

### Traditional PKI

Standard approach using certificates from a trusted CA. Works with all browsers but requires domain validation and certificate management.

### Wildcard Certificates

Generate certificates for multiple subdomains:
```bash
./certgen.sh --host "*.api.example.com"
```

## Limitations

Development certificates have restrictions:
- Maximum 14 days validity (WebTransport spec requirement)
- Must use ECDSA with secp256r1 curve (RSA forbidden)
- Certificate rotation requires client updates when using hash pinning

## Certificate Types

The library supports multiple certificate configurations:

- `WTF_CERT_TYPE_FILE` - PEM files (macOS/Linux)
- `WTF_CERT_TYPE_HASH` - Imported certificate by thumbprint (Windows)
- `WTF_CERT_TYPE_PKCS12` - PFX/PKCS#12 files with optional password
- `WTF_CERT_TYPE_HASH_STORE` - Certificate from specific Windows store

## Testing

1. Generate certificate: `./certgen.sh`
2. Start server: `./wtf_echo_server --cert ./certs/localhost.crt --key ./certs/localhost.key`
3. Test connection: `./certain.sh localhost:4433`