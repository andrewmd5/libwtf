#if defined(__APPLE__) && defined(WTF_QUIC_BACKEND_NETWORK)
    #define __STDC_WANT_LIB_EXT1__ 1
    #include <unistd.h>

    #include "cert.h"
    #include "network_internal.h"

static CFDataRef network_credentials_read_file(const char* path)
{
    if (!path) {
        return NULL;
    }
    FILE* f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END)) {
        fclose(f);
        return NULL;
    }
    long size = ftell(f);
    rewind(f);
    if (size <= 0) {
        fclose(f);
        return NULL;
    }
    uint8_t* bytes = malloc((size_t)size);
    CFDataRef data = NULL;
    if (bytes && fread(bytes, 1, (size_t)size, f) == (size_t)size) {
        data = CFDataCreate(kCFAllocatorDefault, bytes, size);
    }
    free(bytes);
    fclose(f);
    return data;
}

static SecCertificateRef network_credentials_load_certificate(const char* path)
{
    uint8_t* der = NULL;
    size_t length = 0;
    if (!path || wtf_cert_load_der_from_file(path, &der, &length) != WTF_SUCCESS) {
        return NULL;
    }
    CFDataRef data = CFDataCreate(NULL, der, length);
    free(der);
    if (!data) {
        return NULL;
    }
    SecCertificateRef certificate = SecCertificateCreateWithData(NULL, data);
    CFRelease(data);
    return certificate;
}

static SecIdentityRef network_credentials_import_pkcs12(const QUIC_CERTIFICATE_PKCS12* pkcs12)
{
    if (!pkcs12 || !pkcs12->Asn1Blob || !pkcs12->Asn1BlobLength) {
        return NULL;
    }
    const char* passphrase = pkcs12->PrivateKeyPassword;
    if (!passphrase) {
        passphrase = "";
    }
    CFDataRef data = CFDataCreate(NULL, pkcs12->Asn1Blob, pkcs12->Asn1BlobLength);
    CFStringRef password = CFStringCreateWithCString(NULL, passphrase, kCFStringEncodingUTF8);
    if (!data || !password) {
        if (data) {
            CFRelease(data);
        }
        if (password) {
            CFRelease(password);
        }
        return NULL;
    }
    const void* keys[] = {kSecImportExportPassphrase, kSecImportToMemoryOnly};
    const void* values[] = {password, kCFBooleanTrue};
    CFDictionaryRef options = CFDictionaryCreate(
        NULL, keys, values, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFArrayRef items = NULL;
    SecIdentityRef identity = NULL;
    if (options && SecPKCS12Import(data, options, &items) == errSecSuccess && items
        && CFArrayGetCount(items)) {
        identity = (SecIdentityRef)CFDictionaryGetValue(
            CFArrayGetValueAtIndex(items, 0), kSecImportItemIdentity);
        if (identity) {
            CFRetain(identity);
        }
    }
    if (items) {
        CFRelease(items);
    }
    if (options) {
        CFRelease(options);
    }
    CFRelease(password);
    CFRelease(data);
    return identity;
}

    #if TARGET_OS_OSX
static OSStatus network_credentials_create_keychain(network_configuration* configuration)
{
    char directory[] = "/private/tmp/libwtf-identity-XXXXXX";
    if (!mkdtemp(directory)) {
        return errSecIO;
    }
    configuration->keychain_directory = strdup(directory);
    if (!configuration->keychain_directory) {
        rmdir(directory);
        return errSecAllocate;
    }
    char path[sizeof(directory) + 32];
    snprintf(path, sizeof(path), "%s/identity.keychain", directory);
    uint8_t password[32];
    arc4random_buf(password, sizeof(password));
    OSStatus status = SecKeychainCreate(
        path, sizeof(password), password, false, NULL, &configuration->keychain);
    memset_s(password, sizeof(password), 0, sizeof(password));
    return status;
}

static OSStatus network_credentials_import_key(
    network_configuration* configuration, const char* path, const char* passphrase)
{
    CFDataRef data = network_credentials_read_file(path);
    if (!data) {
        return errSecIO;
    }
    if (!passphrase) {
        passphrase = "";
    }
    CFStringRef password = CFStringCreateWithCString(NULL, passphrase, kCFStringEncodingUTF8);
    if (!password) {
        CFRelease(data);
        return errSecAllocate;
    }
    SecExternalFormat format = kSecFormatUnknown;
    SecExternalItemType type = kSecItemTypePrivateKey;
    SecItemImportExportKeyParameters parameters = {0};
    parameters.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    parameters.flags = kSecKeyImportOnlyOne | kSecKeyNoAccessControl;
    parameters.passphrase = password;
    CFArrayRef items = NULL;
    OSStatus status = SecItemImport(
        data, NULL, &format, &type, 0, &parameters, configuration->keychain, &items);
    if (items) {
        CFRelease(items);
    }
    CFRelease(password);
    CFRelease(data);
    return status;
}

static SecIdentityRef network_credentials_import_pem(network_configuration* configuration,
    const char* certificate_path,
    const char* key_path,
    const char* passphrase)
{
    if (!certificate_path || !key_path) {
        return NULL;
    }
    /* Keep imported private keys outside the user's keychains. */
    if (network_credentials_create_keychain(configuration) != errSecSuccess
        || network_credentials_import_key(configuration, key_path, passphrase) != errSecSuccess) {
        return NULL;
    }
    SecCertificateRef certificate = network_credentials_load_certificate(certificate_path);
    if (!certificate) {
        return NULL;
    }
    SecIdentityRef identity = NULL;
    SecIdentityCreateWithCertificate(configuration->keychain, certificate, &identity);
    CFRelease(certificate);
    return identity;
}
    #endif

static QUIC_STATUS network_credentials_load_identity(
    network_configuration* configuration, const QUIC_CREDENTIAL_CONFIG* credentials)
{
    SecIdentityRef identity = NULL;
    switch (credentials->Type) {
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT:
            identity = (SecIdentityRef)credentials->CertificateContext;
            if (identity) {
                CFRetain(identity);
            }
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12:
            identity = network_credentials_import_pkcs12(credentials->CertificatePkcs12);
            break;
    #if TARGET_OS_OSX
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE: {
            const QUIC_CERTIFICATE_FILE* file = credentials->CertificateFile;
            if (!file) {
                return QUIC_STATUS_INVALID_PARAMETER;
            }
            identity = network_credentials_import_pem(
                configuration, file->CertificateFile, file->PrivateKeyFile, NULL);
            break;
        }
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED: {
            const QUIC_CERTIFICATE_FILE_PROTECTED* file = credentials->CertificateFileProtected;
            if (!file) {
                return QUIC_STATUS_INVALID_PARAMETER;
            }
            identity = network_credentials_import_pem(configuration, file->CertificateFile,
                file->PrivateKeyFile, file->PrivateKeyPassword);
            break;
        }
    #endif
        default:
            return QUIC_STATUS_NOT_SUPPORTED;
    }
    if (!identity) {
        return QUIC_STATUS_TLS_ERROR;
    }
    configuration->identity = sec_identity_create(identity);
    CFRelease(identity);
    if (!configuration->identity) {
        return QUIC_STATUS_TLS_ERROR;
    }
    return QUIC_STATUS_SUCCESS;
}

nw_parameters_t network_parameters_create(
    network_connection* connection, network_configuration* config, const char* host, uint16_t port)
{
    return nw_parameters_create_quic(^(nw_protocol_options_t options) {
        nw_quic_add_tls_application_protocol(options, config->alpn);
        if (host) {
            network_session_configure(options, config, host, port);
        }
        if (config->settings.ReliableResetEnabled && wtf_network_supports_reliable_reset()) {
            nw_quic_set_reset_stream_at_enabled(options, true);
        }
        nw_quic_set_initial_max_streams_bidirectional(
            options, config->settings.PeerBidiStreamCount);
        nw_quic_set_initial_max_streams_unidirectional(
            options, config->settings.PeerUnidiStreamCount);
        nw_quic_set_initial_max_data(options, config->settings.ConnFlowControlWindow);
        uint32_t local_window = config->settings.StreamRecvWindowDefault;
        uint32_t remote_window = local_window;
        uint32_t unidirectional_window = local_window;
        if (config->settings.IsSet.StreamRecvWindowBidiLocalDefault) {
            local_window = config->settings.StreamRecvWindowBidiLocalDefault;
        }
        if (config->settings.IsSet.StreamRecvWindowBidiRemoteDefault) {
            remote_window = config->settings.StreamRecvWindowBidiRemoteDefault;
        }
        if (config->settings.IsSet.StreamRecvWindowUnidiDefault) {
            unidirectional_window = config->settings.StreamRecvWindowUnidiDefault;
        }
        nw_quic_set_initial_max_stream_data_bidirectional_local(options, local_window);
        nw_quic_set_initial_max_stream_data_bidirectional_remote(options, remote_window);
        nw_quic_set_initial_max_stream_data_unidirectional(options, unidirectional_window);
        if (config->settings.IsSet.IdleTimeoutMs) {
            nw_quic_set_idle_timeout(options, (uint32_t)config->settings.IdleTimeoutMs);
        }
        if (config->settings.DatagramReceiveEnabled) {
            nw_quic_set_max_datagram_frame_size(options, 65535);
        }
        sec_protocol_options_t tls = nw_quic_copy_sec_protocol_options(options);
        if (config->settings.IsSet.ServerResumptionLevel) {
            sec_protocol_options_set_tls_resumption_enabled(
                tls, config->settings.ServerResumptionLevel != QUIC_SERVER_NO_RESUME);
            sec_protocol_options_set_tls_tickets_enabled(
                tls, config->settings.ServerResumptionLevel != QUIC_SERVER_NO_RESUME);
            if (sec_protocol_options_set_tls_early_data_enabled) {
                sec_protocol_options_set_tls_early_data_enabled(
                    tls, config->settings.ServerResumptionLevel == QUIC_SERVER_RESUME_AND_ZERORTT);
            }
        }
        if (config->identity) {
            sec_protocol_options_set_local_identity(tls, config->identity);
        }
        if (!(config->credential_flags & QUIC_CREDENTIAL_FLAG_CLIENT)) {
            sec_protocol_options_set_peer_authentication_required(tls, false);
        } else {
            sec_protocol_options_set_verify_block(tls,
                ^(sec_protocol_metadata_t metadata, sec_trust_t sec_trust,
                    sec_protocol_verify_complete_t complete) {
                    (void)metadata;
                    SecTrustRef trust = sec_trust_copy_ref(sec_trust);
                    bool valid = (config->credential_flags
                                     & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)
                        != 0;
                    if (config->anchor) {
                        const void* certificates[] = {config->anchor};
                        CFArrayRef anchors = CFArrayCreate(
                            NULL, certificates, 1, &kCFTypeArrayCallBacks);
                        SecTrustSetAnchorCertificates(trust, anchors);
                        SecTrustSetAnchorCertificatesOnly(trust, true);
                        CFRelease(anchors);
                    }
                    if (!valid) {
                        valid = SecTrustEvaluateWithError(trust, NULL);
                    }
                    if (valid
                        && (config->credential_flags
                            & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED)) {
                        CFArrayRef chain = SecTrustCopyCertificateChain(trust);
                        SecCertificateRef certificate = NULL;
                        if (chain && CFArrayGetCount(chain)) {
                            certificate = (SecCertificateRef)CFArrayGetValueAtIndex(chain, 0);
                        }
                        CFDataRef data = NULL;
                        QUIC_BUFFER buffer = {0};
                        if (certificate) {
                            data = SecCertificateCopyData(certificate);
                        }
                        if (data) {
                            buffer.Length = (uint32_t)CFDataGetLength(data);
                            buffer.Buffer = (uint8_t*)CFDataGetBytePtr(data);
                        }
                        QUIC_CONNECTION_EVENT event = {
                            .Type = QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED};
                        event.PEER_CERTIFICATE_RECEIVED.Certificate = &buffer;
                        valid = QUIC_SUCCEEDED(network_emit_connection(connection, &event));
                        if (data) {
                            CFRelease(data);
                        }
                        if (chain) {
                            CFRelease(chain);
                        }
                    }
                    CFRelease(trust);
                    complete(valid);
                },
                connection->handle.queue);
        }
        nw_release(tls);
    });
}

static QUIC_STATUS network_configuration_validate_settings(const QUIC_SETTINGS* settings)
{
    const QUIC_SETTINGS supported = {
        .IsSet = {
            .HandshakeIdleTimeoutMs = true,
            .IdleTimeoutMs = true,
            .StreamRecvWindowDefault = true,
            .ConnFlowControlWindow = true,
            .PeerBidiStreamCount = true,
            .PeerUnidiStreamCount = true,
            .SendBufferingEnabled = true,
            .PacingEnabled = true,
            .DatagramReceiveEnabled = true,
            .ServerResumptionLevel = true,
            .StreamRecvWindowBidiLocalDefault = true,
            .StreamRecvWindowBidiRemoteDefault = true,
            .StreamRecvWindowUnidiDefault = true,
            .ReliableResetEnabled = true,
        },
    };
    if (settings->IsSetFlags & ~supported.IsSetFlags) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
    if (settings->IsSet.PacingEnabled && !settings->PacingEnabled) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
    if (settings->IsSet.IdleTimeoutMs && settings->IdleTimeoutMs > UINT32_MAX) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (settings->IsSet.ServerResumptionLevel
        && settings->ServerResumptionLevel > QUIC_SERVER_RESUME_AND_ZERORTT) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS network_configuration_open(HQUIC reg,
    const QUIC_BUFFER* alpns,
    uint32_t count,
    const QUIC_SETTINGS* settings,
    uint32_t settings_size,
    void* context,
    HQUIC* out)
{
    if (!reg || !out || !count || !alpns || !alpns[0].Buffer || !alpns[0].Length
        || alpns[0].Length > 255 || (settings && settings_size > sizeof(QUIC_SETTINGS))) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    network_configuration* h = (network_configuration*)network_handle_create(
        NETWORK_CONFIGURATION, sizeof(*h), reg);
    if (!h) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    h->alpn = strndup((char*)alpns[0].Buffer, alpns[0].Length);
    if (!h->alpn) {
        network_handle_release((HQUIC)h);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    h->handle.context = context;
    if (settings) {
        memcpy(&h->settings, settings, settings_size);
    }
    QUIC_STATUS status = network_configuration_validate_settings(&h->settings);
    if (QUIC_FAILED(status)) {
        network_handle_release((HQUIC)h);
        return status;
    }
    if (!h->settings.IsSet.PeerBidiStreamCount) {
        h->settings.PeerBidiStreamCount = 16;
    }
    if (!h->settings.IsSet.PeerUnidiStreamCount) {
        h->settings.PeerUnidiStreamCount = 16;
    }
    if (!h->settings.IsSet.StreamRecvWindowDefault) {
        h->settings.StreamRecvWindowDefault = 1024 * 1024;
    }
    if (!h->settings.IsSet.ConnFlowControlWindow) {
        h->settings.ConnFlowControlWindow = 16 * 1024 * 1024;
    }
    *out = (HQUIC)h;
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS network_configuration_load(HQUIC handle, const QUIC_CREDENTIAL_CONFIG* credentials)
{
    network_configuration* h = (network_configuration*)handle;
    if (!h || !credentials) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    const QUIC_CREDENTIAL_FLAGS supported_flags = QUIC_CREDENTIAL_FLAG_CLIENT
        | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION
        | QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED
        | QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES
        | QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
    if ((credentials->Flags & ~supported_flags) || credentials->Principal) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
    h->credential_flags = credentials->Flags;
    if (credentials->CaCertificateFile) {
        h->anchor = network_credentials_load_certificate(credentials->CaCertificateFile);
        if (!h->anchor) {
            return QUIC_STATUS_TLS_ERROR;
        }
    }
    if (h->credential_flags & QUIC_CREDENTIAL_FLAG_CLIENT) {
        return QUIC_STATUS_SUCCESS;
    }
    return network_credentials_load_identity(h, credentials);
}

void wtf_network_configuration_set_certificate_pin(HQUIC configuration, const uint8_t pin[32])
{
    memcpy(((network_configuration*)configuration)->certificate_pin, pin, 32);
}

void network_configuration_dispose(network_configuration* configuration)
{
    if (configuration->identity) {
        nw_release(configuration->identity);
    }
    if (configuration->anchor) {
        CFRelease(configuration->anchor);
    }
    #if TARGET_OS_OSX
    if (configuration->keychain) {
        SecKeychainDelete(configuration->keychain);
        CFRelease(configuration->keychain);
    }
    if (configuration->keychain_directory) {
        rmdir(configuration->keychain_directory);
        free(configuration->keychain_directory);
    }
    #endif
    free(configuration->alpn);
}
#endif
