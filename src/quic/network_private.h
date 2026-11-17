#ifndef WTF_NETWORK_PRIVATE_H
#define WTF_NETWORK_PRIVATE_H

#if defined(__APPLE__) && defined(WTF_QUIC_BACKEND_NETWORK)
    #include <Network/Network.h>
    #include <Security/Security.h>

extern void nw_quic_set_reset_stream_at_enabled(nw_protocol_options_t options, bool enabled)
    __attribute__((weak_import));
extern bool nw_quic_get_reset_stream_at_supported(nw_protocol_metadata_t metadata)
    __attribute__((weak_import));
extern void nw_quic_set_stream_reset_stream_at_reliable_size(
    nw_protocol_metadata_t metadata, uint64_t reliable_size) __attribute__((weak_import));
extern uint64_t nw_quic_get_stream_reset_stream_at_reliable_size(nw_protocol_metadata_t metadata)
    __attribute__((weak_import));
extern void sec_protocol_options_set_tls_early_data_enabled(
    sec_protocol_options_t options, bool enabled) __attribute__((weak_import));
extern bool sec_protocol_metadata_get_session_resumed(sec_protocol_metadata_t metadata)
    __attribute__((weak_import));
extern void nw_quic_connection_set_session_state(nw_protocol_options_t options,
    dispatch_data_t transport_parameters,
    dispatch_data_t tls_session) __attribute__((weak_import));
extern void nw_quic_connection_set_session_state_update_block(nw_protocol_options_t options,
    void (^update)(dispatch_data_t transport_parameters, dispatch_data_t tls_session),
    dispatch_queue_t queue) __attribute__((weak_import));
extern nw_protocol_options_t nw_quic_stream_copy_shared_connection_options(
    nw_protocol_options_t options) __attribute__((weak_import));
#endif

#endif
