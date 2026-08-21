#include "cert.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
    #include <windows.h>
    #include <bcrypt.h>
    #include <wincrypt.h>
#elif defined(__APPLE__)
    #include <CommonCrypto/CommonDigest.h>
    #include <CoreFoundation/CoreFoundation.h>
    #include <Security/Security.h>
#else
    #include <openssl/err.h>
    #include <openssl/pem.h>
    #include <openssl/sha.h>
    #include <openssl/x509.h>
#endif

static wtf_result_t wtf_cert_copy_der(const uint8_t* source, size_t length, uint8_t** der,
                                      size_t* der_len)
{
    if (!source || length == 0 || !der || !der_len) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    uint8_t* copy = malloc(length);
    if (!copy) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    memcpy(copy, source, length);
    *der = copy;
    *der_len = length;
    return WTF_SUCCESS;
}

#if defined(_WIN32)
wtf_result_t wtf_cert_load_der_from_file(const char* path, uint8_t** der, size_t* der_len)
{
    if (!path || !der || !der_len) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    *der = NULL;
    *der_len = 0;

    DWORD encoding = 0;
    DWORD content_type = 0;
    DWORD format_type = 0;
    HCERTSTORE cert_store = NULL;
    HCRYPTMSG crypt_msg = NULL;
    const void* cert_context_raw = NULL;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path, CERT_QUERY_CONTENT_FLAG_CERT,
                           CERT_QUERY_FORMAT_FLAG_ALL, 0, &encoding, &content_type,
                           &format_type, &cert_store, &crypt_msg, &cert_context_raw)) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    PCCERT_CONTEXT cert_context = (PCCERT_CONTEXT)cert_context_raw;
    wtf_result_t result = WTF_ERROR_INVALID_PARAMETER;
    if (cert_context && cert_context->pbCertEncoded && cert_context->cbCertEncoded > 0) {
        result = wtf_cert_copy_der(cert_context->pbCertEncoded, cert_context->cbCertEncoded, der,
                                   der_len);
    }

    if (cert_context) {
        CertFreeCertificateContext(cert_context);
    }
    if (crypt_msg) {
        CryptMsgClose(crypt_msg);
    }
    if (cert_store) {
        CertCloseStore(cert_store, 0);
    }
    return result;
}

bool wtf_cert_sha256(const uint8_t* data, size_t length, uint8_t digest[WTF_CERT_SHA256_SIZE])
{
    if (!data || length == 0 || !digest) {
        return false;
    }

    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    bool success = false;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        goto cleanup;
    }
    if (!BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0))) {
        goto cleanup;
    }

    size_t offset = 0;
    while (offset < length) {
        size_t remaining = length - offset;
        ULONG chunk = remaining > ULONG_MAX ? ULONG_MAX : (ULONG)remaining;
        if (!BCRYPT_SUCCESS(BCryptHashData(hash, (PUCHAR)data + offset, chunk, 0))) {
            goto cleanup;
        }
        offset += chunk;
    }

    success = BCRYPT_SUCCESS(BCryptFinishHash(hash, digest, WTF_CERT_SHA256_SIZE, 0));

cleanup:
    if (hash) {
        BCryptDestroyHash(hash);
    }
    if (algorithm) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    return success;
}
#elif defined(__APPLE__)
static wtf_result_t wtf_cert_read_file(const char* path, uint8_t** data, size_t* length)
{
    if (!path || !data || !length) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    *data = NULL;
    *length = 0;

    FILE* file = fopen(path, "rb");
    if (!file) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return WTF_ERROR_INVALID_PARAMETER;
    }
    long file_size = ftell(file);
    if (file_size <= 0) {
        fclose(file);
        return WTF_ERROR_INVALID_PARAMETER;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return WTF_ERROR_INVALID_PARAMETER;
    }

    uint8_t* buffer = malloc((size_t)file_size);
    if (!buffer) {
        fclose(file);
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    size_t bytes_read = fread(buffer, 1, (size_t)file_size, file);
    fclose(file);
    if (bytes_read != (size_t)file_size) {
        free(buffer);
        return WTF_ERROR_INVALID_PARAMETER;
    }

    *data = buffer;
    *length = bytes_read;
    return WTF_SUCCESS;
}

wtf_result_t wtf_cert_load_der_from_file(const char* path, uint8_t** der, size_t* der_len)
{
    if (!path || !der || !der_len) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    *der = NULL;
    *der_len = 0;

    uint8_t* file_data = NULL;
    size_t file_len = 0;
    wtf_result_t result = wtf_cert_read_file(path, &file_data, &file_len);
    if (result != WTF_SUCCESS) {
        return result;
    }

    CFDataRef data_ref = CFDataCreate(kCFAllocatorDefault, file_data, (CFIndex)file_len);
    free(file_data);
    if (!data_ref) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    SecExternalFormat format = kSecFormatUnknown;
    SecExternalItemType item_type = kSecItemTypeUnknown;
    CFArrayRef imported_items = NULL;
    OSStatus status = SecItemImport(data_ref, NULL, &format, &item_type, 0, NULL, NULL,
                                    &imported_items);
    CFRelease(data_ref);
    if (status != errSecSuccess || !imported_items) {
        if (imported_items) {
            CFRelease(imported_items);
        }
        return WTF_ERROR_INVALID_PARAMETER;
    }

    result = WTF_ERROR_INVALID_PARAMETER;
    CFIndex count = CFArrayGetCount(imported_items);
    for (CFIndex i = 0; i < count; i++) {
        CFTypeRef item = CFArrayGetValueAtIndex(imported_items, i);
        if (!item || CFGetTypeID(item) != SecCertificateGetTypeID()) {
            continue;
        }

        CFDataRef cert_data = SecCertificateCopyData((SecCertificateRef)item);
        if (!cert_data) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            break;
        }
        result = wtf_cert_copy_der(CFDataGetBytePtr(cert_data), (size_t)CFDataGetLength(cert_data),
                                   der, der_len);
        CFRelease(cert_data);
        break;
    }

    CFRelease(imported_items);
    return result;
}

bool wtf_cert_sha256(const uint8_t* data, size_t length, uint8_t digest[WTF_CERT_SHA256_SIZE])
{
    if (!data || length == 0 || !digest) {
        return false;
    }

    CC_SHA256_CTX context;
    if (!CC_SHA256_Init(&context)) {
        return false;
    }

    size_t offset = 0;
    while (offset < length) {
        size_t remaining = length - offset;
        CC_LONG chunk = remaining > UINT32_MAX ? UINT32_MAX : (CC_LONG)remaining;
        if (!CC_SHA256_Update(&context, data + offset, chunk)) {
            return false;
        }
        offset += chunk;
    }

    return CC_SHA256_Final(digest, &context) != 0;
}
#else
static X509* wtf_cert_openssl_read_x509(const char* path)
{
    BIO* bio = BIO_new_file(path, "rb");
    if (!bio) {
        return NULL;
    }

    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (cert) {
        return cert;
    }

    ERR_clear_error();
    bio = BIO_new_file(path, "rb");
    if (!bio) {
        return NULL;
    }
    cert = d2i_X509_bio(bio, NULL);
    BIO_free(bio);
    return cert;
}

wtf_result_t wtf_cert_load_der_from_file(const char* path, uint8_t** der, size_t* der_len)
{
    if (!path || !der || !der_len) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    *der = NULL;
    *der_len = 0;

    X509* cert = wtf_cert_openssl_read_x509(path);
    if (!cert) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    int encoded_len = i2d_X509(cert, NULL);
    if (encoded_len <= 0) {
        X509_free(cert);
        return WTF_ERROR_INVALID_PARAMETER;
    }

    uint8_t* encoded = malloc((size_t)encoded_len);
    if (!encoded) {
        X509_free(cert);
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    unsigned char* cursor = encoded;
    int written = i2d_X509(cert, &cursor);
    X509_free(cert);
    if (written != encoded_len) {
        free(encoded);
        return WTF_ERROR_INVALID_PARAMETER;
    }

    *der = encoded;
    *der_len = (size_t)encoded_len;
    return WTF_SUCCESS;
}

bool wtf_cert_sha256(const uint8_t* data, size_t length, uint8_t digest[WTF_CERT_SHA256_SIZE])
{
    if (!data || length == 0 || !digest) {
        return false;
    }
    return SHA256(data, length, digest) != NULL;
}
#endif
