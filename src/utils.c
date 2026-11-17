#include "utils.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "wtf_version.h"

#ifdef _WIN32
    #include <bcrypt.h>
    #include <windows.h>
    #pragma comment(lib, "bcrypt.lib")
    #include <io.h>
#elif defined(__linux__) || defined(__ANDROID__)
    #include <fcntl.h>
    #include <sys/random.h>
    #include <unistd.h>
#elif defined(__APPLE__)
    #include <Security/SecRandom.h>
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    #include <sys/random.h>
#else
    #include <fcntl.h>
    #include <unistd.h>
#endif


const char* wtf_result_to_string(wtf_result_t result)
{
    switch (result) {
        case WTF_SUCCESS:
            return "Success";
        case WTF_ERROR_INVALID_PARAMETER:
            return "Invalid parameter";
        case WTF_ERROR_OUT_OF_MEMORY:
            return "Out of memory";
        case WTF_ERROR_INTERNAL:
            return "Internal error";
        case WTF_ERROR_CONNECTION_ABORTED:
            return "Connection aborted";
        case WTF_ERROR_STREAM_ABORTED:
            return "Stream aborted";
        case WTF_ERROR_INVALID_STATE:
            return "Invalid state";
        case WTF_ERROR_BUFFER_TOO_SMALL:
            return "Buffer too small";
        case WTF_ERROR_NOT_FOUND:
            return "Not found";
        case WTF_ERROR_REJECTED:
            return "Rejected";
        case WTF_ERROR_TIMEOUT:
            return "Timeout";
        case WTF_ERROR_TLS_HANDSHAKE_FAILED:
            return "TLS handshake failed";
        case WTF_ERROR_PROTOCOL_VIOLATION:
            return "Protocol violation";
        case WTF_ERROR_FLOW_CONTROL:
            return "Flow control error";
        case WTF_ERROR_NOT_SUPPORTED:
            return "Not supported by the QUIC backend";
        default:
            return "Unknown error";
    }
}

wtf_result_t wtf_quic_status_to_result(QUIC_STATUS status)
{
    if (status == QUIC_STATUS_CONNECTION_REFUSED || status == QUIC_STATUS_ABORTED) {
        return WTF_ERROR_CONNECTION_ABORTED;
    }
    if (status == QUIC_STATUS_TLS_ERROR) {
        return WTF_ERROR_TLS_HANDSHAKE_FAILED;
    }

    switch (status) {
        case QUIC_STATUS_NOT_SUPPORTED:
            return WTF_ERROR_NOT_SUPPORTED;
        case QUIC_STATUS_SUCCESS:
            return WTF_SUCCESS;
        case QUIC_STATUS_INVALID_PARAMETER:
            return WTF_ERROR_INVALID_PARAMETER;
        case QUIC_STATUS_OUT_OF_MEMORY:
            return WTF_ERROR_OUT_OF_MEMORY;
        case QUIC_STATUS_CONNECTION_TIMEOUT:
            return WTF_ERROR_CONNECTION_ABORTED;
        case QUIC_STATUS_PROTOCOL_ERROR:
            return WTF_ERROR_PROTOCOL_VIOLATION;
        default:
            return WTF_ERROR_INTERNAL;
    }
}

uint64_t wtf_map_webtransport_error_to_h3(uint32_t wt_error)
{
    uint64_t base = WTF_WEBTRANSPORT_APPLICATION_ERROR_BASE;
    uint64_t mapped = base + wt_error + (wt_error / 0x1e);

    if (mapped > WTF_WEBTRANSPORT_APPLICATION_ERROR_MAX) {
        mapped = WTF_WEBTRANSPORT_APPLICATION_ERROR_MAX;
    }

    return mapped;
}

uint32_t wtf_map_h3_error_to_webtransport(uint64_t h3_error)
{
    if (h3_error < WTF_WEBTRANSPORT_APPLICATION_ERROR_BASE
        || h3_error > WTF_WEBTRANSPORT_APPLICATION_ERROR_MAX) {
        return 0;
    }

    if ((h3_error - 0x21) % 0x1f == 0) {
        return 0;
    }

    uint64_t shifted = h3_error - WTF_WEBTRANSPORT_APPLICATION_ERROR_BASE;
    return (uint32_t)(shifted - (shifted / 0x1f));
}

char* wtf_strdup(const char* s)
{
    if (s == NULL) {
#ifdef EINVAL
        errno = EINVAL;
#endif
        return NULL;
    }

#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200809L
    return strdup(s);
#elif defined(_WIN32)
    return _strdup(s);
#endif

    size_t siz = strlen(s) + 1;
    char* y = malloc(siz);
    if (y != NULL) {
        memcpy(y, s, siz);
    } else {
#ifdef ENOMEM
        errno = ENOMEM;
#endif
    }
    return y;
}

size_t wtf_strncpy(char* dest, const char* src, size_t dest_size)
{
    if (!dest || dest_size == 0) {
#ifdef EINVAL
        errno = EINVAL;
#endif
        return 0;
    }
    if (!src) {
        dest[0] = '\0';
        return 0;
    }
#ifdef _WIN32
    errno_t err = strcpy_s(dest, dest_size, src);
    if (err != 0) {
        dest[0] = '\0';
        return 0;
    }
    return strlen(dest);
#else
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
    return strlen(dest);
#endif
}

bool wtf_path_valid(const char* path)
{
    if (path == NULL) {
        return false;
    }

#ifdef _WIN32
    errno_t err = _access_s(path, 0);
    return err == 0;
#else
    return access(path, F_OK) == 0;
#endif
}

bool wtf_parse_thumbprint(const char* hex_thumbprint, uint8_t sha_hash[20])
{
    if (!hex_thumbprint || !sha_hash) {
        return false;
    }

    size_t hex_len = strlen(hex_thumbprint);

    size_t clean_len = 0;
    char clean_hex[41];

    for (size_t i = 0; i < hex_len && clean_len < 40; i++) {
        char c = hex_thumbprint[i];
        if (c == ':' || c == '-' || c == ' ') {
            continue;
        }
        if (!isxdigit(c)) {
            return false;
        }
        clean_hex[clean_len++] = tolower(c);
    }

    if (clean_len != 40) {
        return false;
    }

    clean_hex[40] = '\0';

    for (int i = 0; i < 20; i++) {
        char byte_str[3] = {clean_hex[i * 2], clean_hex[i * 2 + 1], '\0'};
        char* endptr;
        unsigned long byte_val = strtoul(byte_str, &endptr, 16);

        if (*endptr != '\0' || byte_val > 255) {
            return false;
        }

        sha_hash[i] = (uint8_t)byte_val;
    }

    return true;
}

bool wtf_random_uint64(uint64_t* result)
{
    if (!result) {
        return false;
    }

    *result = 0;

#ifdef _WIN32
    // Windows: Use BCryptGenRandom
    NTSTATUS status = BCryptGenRandom(NULL, (PUCHAR)result, sizeof(*result),
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    return BCRYPT_SUCCESS(status);

#elif defined(__linux__) || defined(__ANDROID__)
    // Linux/Android: Use getrandom()
    ssize_t bytes_read = getrandom(result, sizeof(*result), 0);
    return bytes_read == sizeof(*result);

#elif defined(__APPLE__)
    // macOS: Use SecRandomCopyBytes
    OSStatus status = SecRandomCopyBytes(kSecRandomDefault, sizeof(*result), (uint8_t*)result);
    return status == errSecSuccess;

#elif defined(__OpenBSD__)
    // OpenBSD: Use getentropy()
    return getentropy(result, sizeof(*result)) == 0;

#elif defined(__FreeBSD__) || defined(__NetBSD__)
    // FreeBSD/NetBSD: Use arc4random_buf()
    arc4random_buf(result, sizeof(*result));
    return true;

#else
    // Other Unix systems: Use /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        return false;
    }

    ssize_t bytes_read = read(fd, result, sizeof(*result));
    close(fd);

    return bytes_read == sizeof(*result);
#endif
}

char* wtf_strndup(const char* s, size_t n)
{
    if (s == NULL) {
#ifdef EINVAL
        errno = EINVAL;
#endif
        return NULL;
    }

#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200809L
    return strndup(s, n);
#endif

    size_t len = 0;
    while (len < n && s[len] != '\0') {
        len++;
    }

    char* y = malloc(len + 1);
    if (y != NULL) {
        memcpy(y, s, len);
        y[len] = '\0';
    } else {
#ifdef ENOMEM
        errno = ENOMEM;
#endif
    }
    return y;
}

const wtf_version_info_t* wtf_get_version()
{
    static const wtf_version_info_t version_info = {
        .major = WTF_VERSION_MAJOR,
        .minor = WTF_VERSION_MINOR,
        .patch = WTF_VERSION_PATCH,
        .version = WTF_VERSION};
    return &version_info;
}

const char* wtf_webtransport_error_to_string(uint32_t error_code)
{
    switch (error_code) {
        case 0x00:
            return "No error";
        case 0x01:
            return "General protocol error";
        case 0x02:
            return "Internal error";
        case 0x03:
            return "Connection error";
        case 0x04:
            return "Flow control error";
        case 0x05:
            return "Stream limit error";
        case 0x06:
            return "Stream state error";
        case 0x07:
            return "Final size error";
        case 0x08:
            return "Frame encoding error";
        case 0x09:
            return "Transport parameter error";
        case 0x0A:
            return "Connection ID limit error";
        case 0x0B:
            return "Protocol violation";
        case 0x0C:
            return "Invalid token";
        case 0x0D:
            return "Application error";
        case 0x0E:
            return "Crypto buffer exceeded";
        case 0x0F:
            return "Key update error";
        case 0x10:
            return "Aead limit reached";
        case 0x11:
            return "No viable path";
        default:
            return "Unknown error";
    }
}

wtf_result_t wtf_get_error_details(uint32_t error_code, wtf_error_details_t* details)
{
    if (!details) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    details->error_code = error_code;
    details->description = wtf_webtransport_error_to_string(error_code);
    details->is_application_error = (error_code >= 0x100);
    details->is_transport_error = (error_code < 0x100);
    details->is_protocol_error = (error_code >= 0x100 && error_code <= 0x1FF);

    return WTF_SUCCESS;
}

const char* wtf_http3_error_to_string(uint64_t http3_error)
{
    switch (http3_error) {
        case WTF_H3_NO_ERROR:
            return "HTTP3_NO_ERROR";
        case WTF_H3_GENERAL_PROTOCOL_ERROR:
            return "HTTP3_GENERAL_PROTOCOL_ERROR";
        case WTF_H3_INTERNAL_ERROR:
            return "HTTP3_INTERNAL_ERROR";
        case WTF_H3_STREAM_CREATION_ERROR:
            return "HTTP3_STREAM_CREATION_ERROR";
        case WTF_H3_CLOSED_CRITICAL_STREAM:
            return "HTTP3_CLOSED_CRITICAL_STREAM";
        case WTF_H3_FRAME_UNEXPECTED:
            return "HTTP3_FRAME_UNEXPECTED";
        case WTF_H3_FRAME_ERROR:
            return "HTTP3_FRAME_ERROR";
        case WTF_H3_EXCESSIVE_LOAD:
            return "HTTP3_EXCESSIVE_LOAD";
        case WTF_H3_ID_ERROR:
            return "HTTP3_ID_ERROR";
        case WTF_H3_SETTINGS_ERROR:
            return "HTTP3_SETTINGS_ERROR";
        case WTF_H3_MISSING_SETTINGS:
            return "HTTP3_MISSING_SETTINGS";
        case WTF_H3_REQUEST_REJECTED:
            return "HTTP3_REQUEST_REJECTED";
        case WTF_H3_REQUEST_CANCELLED:
            return "HTTP3_REQUEST_CANCELLED";
        case WTF_H3_REQUEST_INCOMPLETE:
            return "HTTP3_REQUEST_INCOMPLETE";
        case WTF_H3_MESSAGE_ERROR:
            return "HTTP3_MESSAGE_ERROR";
        case WTF_H3_CONNECT_ERROR:
            return "HTTP3_CONNECT_ERROR";
        case WTF_H3_VERSION_FALLBACK:
            return "HTTP3_VERSION_FALLBACK";
        case WTF_QPACK_DECOMPRESSION_FAILED:
            return "QPACK_DECOMPRESSION_FAILED";
        case WTF_QPACK_ENCODER_STREAM_ERROR:
            return "QPACK_ENCODER_STREAM_ERROR";
        case WTF_QPACK_DECODER_STREAM_ERROR:
            return "QPACK_DECODER_STREAM_ERROR";
        case WTF_H3_DATAGRAM_ERROR:
            return "H3_DATAGRAM_ERROR";
        default:
            return "Unknown HTTP/3 error";
    }
}

bool wtf_is_valid_application_error(uint32_t error_code)
{
    uint64_t mapped = WTF_WEBTRANSPORT_APPLICATION_ERROR_BASE + (uint64_t)error_code
        + ((uint64_t)error_code / 0x1eU);
    return mapped <= WTF_WEBTRANSPORT_APPLICATION_ERROR_MAX;
}

wtf_result_t wtf_internal_send_context_create(size_t length, wtf_internal_send_context** send_ctx,
                                              uint8_t** data)
{
    if (!send_ctx || !data || length > UINT32_MAX) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    *send_ctx = NULL;
    *data = NULL;

    wtf_internal_send_context* ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    ctx->buffers = ctx->inline_buffers;
    ctx->buffers_inline = true;
    ctx->count = 1;
    ctx->internal_send = true;

    uint8_t* payload = NULL;
    if (length <= WTF_INLINE_SEND_STORAGE) {
        payload = ctx->inline_data;
        ctx->owns_buffer_data = false;
    } else {
        payload = malloc(length);
        if (!payload) {
            free(ctx);
            return WTF_ERROR_OUT_OF_MEMORY;
        }
        ctx->owns_buffer_data = true;
    }

    ctx->buffers[0].data = payload;
    ctx->buffers[0].length = (uint32_t)length;

    *send_ctx = ctx;
    *data = payload;
    return WTF_SUCCESS;
}

wtf_result_t wtf_internal_send_context_create_copy(const void* data, size_t length,
                                                   wtf_internal_send_context** send_ctx)
{
    if ((!data && length > 0) || !send_ctx) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    uint8_t* payload = NULL;
    wtf_result_t result = wtf_internal_send_context_create(length, send_ctx, &payload);
    if (result != WTF_SUCCESS) {
        return result;
    }

    if (length > 0) {
        memcpy(payload, data, length);
    }
    return WTF_SUCCESS;
}

wtf_result_t wtf_internal_send_context_take_buffer(uint8_t* data, size_t length,
                                                   wtf_internal_send_context** send_ctx)
{
    if ((!data && length > 0) || !send_ctx || length > UINT32_MAX) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    *send_ctx = NULL;

    wtf_internal_send_context* ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        free(data);
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    ctx->buffers = ctx->inline_buffers;
    ctx->buffers_inline = true;
    ctx->count = 1;
    ctx->internal_send = true;
    ctx->buffers[0].length = (uint32_t)length;

    if (length <= WTF_INLINE_SEND_STORAGE) {
        if (length > 0) {
            memcpy(ctx->inline_data, data, length);
        }
        free(data);
        ctx->buffers[0].data = ctx->inline_data;
        ctx->owns_buffer_data = false;
    } else {
        ctx->buffers[0].data = data;
        ctx->owns_buffer_data = true;
    }

    *send_ctx = ctx;
    return WTF_SUCCESS;
}

void wtf_internal_send_context_destroy(wtf_internal_send_context* send_ctx)
{
    if (!send_ctx) {
        return;
    }

    if (send_ctx->buffers) {
        uint32_t app_offset = send_ctx->app_buffer_offset;
        if (app_offset > send_ctx->count) {
            app_offset = send_ctx->count;
        }

        if (send_ctx->owns_buffer_data) {
            for (uint32_t i = app_offset; i < send_ctx->count; i++) {
                const uint8_t* payload = send_ctx->buffers[i].data;
                if (payload && payload != send_ctx->inline_data) {
                    free((void*)payload);
                }
            }
        }

        if (!send_ctx->buffers_inline) {
            free(send_ctx->buffers);
        }
    }

    free(send_ctx);
}
