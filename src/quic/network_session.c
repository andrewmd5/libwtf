#if defined(__APPLE__) && defined(WTF_QUIC_BACKEND_NETWORK)
    #include "network_internal.h"

    #define NETWORK_SESSION_LIMIT 32u
    #define NETWORK_SESSION_DATA_LIMIT (256u * 1024u)

typedef struct {
    dispatch_data_t transport_parameters;
    dispatch_data_t tls_session;
} network_session_entry;

static void network_session_entry_dispose(network_session_entry* entry)
{
    if (entry->transport_parameters) {
        dispatch_release(entry->transport_parameters);
    }
    if (entry->tls_session) {
        dispatch_release(entry->tls_session);
    }
    free(entry);
}

    #define NAME network_session_map
    #define KEY_TY CFArrayRef
    #define VAL_TY network_session_entry*
    #define HASH_FN CFHash
    #define CMPR_FN CFEqual
    #define KEY_DTOR_FN CFRelease
    #define VAL_DTOR_FN network_session_entry_dispose
    #include "verstable.h"

static void network_session_map_dispose(void* context)
{
    network_session_map* cache = context;
    network_session_map_cleanup(cache);
    free(cache);
}

dispatch_queue_t network_session_queue_create(void)
{
    network_session_map* cache = calloc(1, sizeof(*cache));
    if (!cache) {
        return NULL;
    }
    network_session_map_init(cache);
    dispatch_queue_t queue = dispatch_queue_create(
        "libwtf.network.sessions", DISPATCH_QUEUE_SERIAL);
    dispatch_set_context(queue, cache);
    dispatch_set_finalizer_f(queue, network_session_map_dispose);
    return queue;
}

static CFArrayRef network_session_key_create(
    network_configuration* configuration, const char* host, uint16_t port)
{
    CFStringRef hostname = CFStringCreateWithCString(NULL, host, kCFStringEncodingUTF8);
    CFStringRef alpn = CFStringCreateWithCString(NULL, configuration->alpn, kCFStringEncodingUTF8);
    CFNumberRef service = CFNumberCreate(NULL, kCFNumberSInt32Type, &(int32_t) {port});
    CFDataRef flags = CFDataCreate(NULL, (const uint8_t*)&configuration->credential_flags,
        sizeof(configuration->credential_flags));
    CFDataRef pin = CFDataCreate(
        NULL, configuration->certificate_pin, sizeof(configuration->certificate_pin));
    CFDataRef anchor = NULL;
    if (configuration->anchor) {
        anchor = SecCertificateCopyData(configuration->anchor);
    } else {
        anchor = CFDataCreate(NULL, NULL, 0);
    }
    CFArrayRef key = NULL;
    if (hostname && alpn && service && flags && pin && anchor) {
        const void* values[] = {hostname, service, alpn, flags, pin, anchor};
        key = CFArrayCreate(
            NULL, values, sizeof(values) / sizeof(values[0]), &kCFTypeArrayCallBacks);
    }
    CFTypeRef values[] = {hostname, service, alpn, flags, pin, anchor};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        if (values[i]) {
            CFRelease(values[i]);
        }
    }
    return key;
}

void network_session_configure(nw_protocol_options_t options,
    network_configuration* configuration,
    const char* host,
    uint16_t port)
{
    if (!wtf_network_supports_early_data()
        || configuration->settings.ServerResumptionLevel == QUIC_SERVER_NO_RESUME) {
        return;
    }
    CFArrayRef key = network_session_key_create(configuration, host, port);
    if (!key) {
        return;
    }
    nw_protocol_options_t connection_options = nw_quic_stream_copy_shared_connection_options(
        options);
    if (!connection_options) {
        CFRelease(key);
        return;
    }
    network_registration* registration = (network_registration*)configuration->handle.parent;
    dispatch_queue_t queue = registration->session_queue;
    dispatch_sync(queue, ^{
        network_session_map* cache = dispatch_get_context(queue);
        network_session_map_itr found = network_session_map_get(cache, key);
        network_session_entry* entry = NULL;
        if (!network_session_map_is_end(found)) {
            entry = found.data->val;
        } else if (network_session_map_size(cache) < NETWORK_SESSION_LIMIT) {
            entry = calloc(1, sizeof(*entry));
            if (entry) {
                CFRetain(key);
                found = network_session_map_insert(cache, key, entry);
                if (network_session_map_is_end(found)) {
                    CFRelease(key);
                    free(entry);
                    entry = NULL;
                }
            }
        }
        if (!entry) {
            return;
        }
        WTF_LOG_TRACE(network_logging_context((HQUIC)configuration), "network.session",
            "Cached session available: %u", entry->tls_session != NULL);
        if (entry->transport_parameters && entry->tls_session) {
            nw_quic_connection_set_session_state(
                connection_options, entry->transport_parameters, entry->tls_session);
        }
        nw_quic_connection_set_session_state_update_block(connection_options,
            ^(dispatch_data_t transport_parameters, dispatch_data_t tls_session) {
                if (!transport_parameters || !tls_session
                    || dispatch_data_get_size(transport_parameters) > NETWORK_SESSION_DATA_LIMIT
                    || dispatch_data_get_size(tls_session) > NETWORK_SESSION_DATA_LIMIT) {
                    return;
                }
                dispatch_retain(transport_parameters);
                dispatch_retain(tls_session);
                if (entry->transport_parameters) {
                    dispatch_release(entry->transport_parameters);
                }
                if (entry->tls_session) {
                    dispatch_release(entry->tls_session);
                }
                entry->transport_parameters = transport_parameters;
                entry->tls_session = tls_session;
            },
            queue);
    });
    nw_release(connection_options);
    CFRelease(key);
}
#endif
