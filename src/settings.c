#include "settings.h"

#include "log.h"
#include "qpack.h"
#include "utils.h"
#include "varint.h"

void wtf_settings_init(wtf_settings* settings)
{
    if (!settings)
        return;

    memset(settings, 0, sizeof(*settings));
    settings->max_field_section_size = 65536;
    settings->qpack_max_table_capacity = WTF_QPACK_DYNAMIC_TABLE_SIZE;
    settings->qpack_blocked_streams = WTF_QPACK_MAX_BLOCKED_STREAMS;
    settings->webtransport_max_sessions = WTF_DEFAULT_MAX_SESSIONS;
    settings->h3_datagram_enabled = false;
    settings->h3_datagram_rfc_enabled = false;
    settings->h3_datagram_draft04_enabled = false;
    settings->enable_connect_protocol = false;
    settings->enable_webtransport = false;
    settings->enable_webtransport_draft02 = false;
    settings->enable_webtransport_draft07 = false;
    settings->enable_webtransport_draft15 = false;
    settings->settings_sent = false;
    settings->settings_received = false;
}

static bool wtf_settings_decode_bool(wtf_connection* conn WTF_MAYBE_UNUSED,
                                     uint64_t setting_id WTF_MAYBE_UNUSED,
                                     uint64_t setting_value, bool* value)
{
    if (!value) {
        return false;
    }

    if (setting_value > 1) {
        WTF_LOG_ERROR(conn->context, "http3",
                      "Invalid boolean setting value: ID=%llu (0x%llx), value=%llu",
                      (unsigned long long)setting_id, (unsigned long long)setting_id,
                      (unsigned long long)setting_value);
        return false;
    }

    *value = setting_value == 1;
    return true;
}

bool wtf_settings_send(wtf_connection* conn)
{
    if (!conn || !conn->control_stream || !conn->control_stream->quic_stream) {
        return false;
    }

    uint8_t data[512];
    size_t settings_length;

    if (!wtf_settings_encode_frame(conn, data, sizeof(data), &settings_length)) {
        WTF_LOG_ERROR(conn->context, "settings", "Failed to write settings frame");
        return false;
    }

    wtf_internal_send_context* send_ctx = NULL;
    if (wtf_internal_send_context_create_copy(data, settings_length, &send_ctx) != WTF_SUCCESS) {
        WTF_LOG_ERROR(conn->context, "settings", "Failed to allocate settings send context");
        return false;
    }

    QUIC_STATUS status = conn->context->quic_api->StreamSend(
        conn->control_stream->quic_stream, (QUIC_BUFFER*)send_ctx->buffers, 1, QUIC_SEND_FLAG_NONE,
        send_ctx);

    if (QUIC_SUCCEEDED(status)) {
        conn->local_settings.settings_sent = true;
        WTF_LOG_INFO(conn->context, "settings", "%s settings sent",
                     conn->role == WTF_ENDPOINT_SERVER ? "Server" : "Client");
        return true;
    } else {
        WTF_LOG_ERROR(conn->context, "settings", "Failed to send settings frame: 0x%x",
                      status);
        wtf_internal_send_context_destroy(send_ctx);
        return false;
    }
}

bool wtf_settings_decode_frame(wtf_connection* conn, const uint8_t* data, size_t data_len)
{
    if (!conn || !data)
        return false;

    size_t offset = 0;

    WTF_LOG_DEBUG(conn->context, "http3", "Parsing settings frame: %zu bytes", data_len);

    while (offset < data_len) {
        uint64_t setting_id, setting_value;

        if (!wtf_varint_decode(data_len, data, &offset, &setting_id)) {
            WTF_LOG_ERROR(conn->context, "http3",
                          "Failed to decode setting ID at offset %zu", offset);
            return false;
        }

        if (!wtf_varint_decode(data_len, data, &offset, &setting_value)) {
            WTF_LOG_ERROR(conn->context, "http3",
                          "Failed to decode setting value for ID %llu at offset %zu",
                          (unsigned long long)setting_id, offset);
            return false;
        }

        WTF_LOG_DEBUG(conn->context, "http3", "Setting ID: %llu (0x%llx), Value: %llu",
                      (unsigned long long)setting_id, (unsigned long long)setting_id,
                      (unsigned long long)setting_value);

        switch (setting_id) {
            case WTF_SETTING_ENABLE_CONNECT_PROTOCOL: {
                bool enabled = false;
                if (!wtf_settings_decode_bool(conn, setting_id, setting_value, &enabled)) {
                    return false;
                }
                conn->peer_settings.enable_connect_protocol = enabled;
                WTF_LOG_DEBUG(conn->context, "http3", "CONNECT protocol enabled: %s",
                              conn->peer_settings.enable_connect_protocol ? "yes" : "no");
                break;
            }

            case WTF_SETTING_WT_ENABLED_DRAFT15:
                conn->peer_settings.enable_webtransport_draft15 = (setting_value > 0);
                conn->peer_settings.enable_webtransport
                    = conn->peer_settings.enable_webtransport_draft02
                    || conn->peer_settings.enable_webtransport_draft07
                    || conn->peer_settings.enable_webtransport_draft15;
                WTF_LOG_TRACE(conn->context, "http3",
                              "WebTransport draft-15 enabled: %s",
                              conn->peer_settings.enable_webtransport_draft15 ? "yes" : "no");
                break;

            case WTF_SETTING_WT_MAX_SESSIONS:
                conn->peer_settings.enable_webtransport_draft15 = (setting_value != 0);
                conn->peer_settings.enable_webtransport
                    = conn->peer_settings.enable_webtransport_draft02
                    || conn->peer_settings.enable_webtransport_draft07
                    || conn->peer_settings.enable_webtransport_draft15;
                conn->peer_settings.webtransport_max_sessions
                    = setting_value > UINT32_MAX ? UINT32_MAX : (uint32_t)setting_value;
                WTF_LOG_TRACE(conn->context, "http3",
                              "Peer WebTransport max sessions: %u",
                              conn->peer_settings.webtransport_max_sessions);
                break;

            case WTF_SETTING_ENABLE_WEBTRANSPORT_DRAFT02: {
                bool enabled = false;
                if (!wtf_settings_decode_bool(conn, setting_id, setting_value, &enabled)) {
                    return false;
                }
                conn->peer_settings.enable_webtransport_draft02 = enabled;
                conn->peer_settings.enable_webtransport
                    = conn->peer_settings.enable_webtransport_draft02
                    || conn->peer_settings.enable_webtransport_draft07
                    || conn->peer_settings.enable_webtransport_draft15;
                WTF_LOG_TRACE(conn->context, "http3",
                              "WebTransport legacy draft enabled: %s",
                              conn->peer_settings.enable_webtransport_draft02 ? "yes" : "no");
                break;
            }

            case WTF_SETTING_H3_DATAGRAM: {
                bool enabled = false;
                if (!wtf_settings_decode_bool(conn, setting_id, setting_value, &enabled)) {
                    return false;
                }
                conn->peer_settings.h3_datagram_rfc_enabled = enabled;
                conn->peer_settings.h3_datagram_enabled
                    = conn->peer_settings.h3_datagram_rfc_enabled
                    || conn->peer_settings.h3_datagram_draft04_enabled;
                WTF_LOG_TRACE(conn->context, "http3", "H3 datagrams enabled: %s",
                              conn->peer_settings.h3_datagram_rfc_enabled ? "yes" : "no");
                break;
            }

            case WTF_SETTING_H3_DRAFT04_DATAGRAM: {
                bool enabled = false;
                if (!wtf_settings_decode_bool(conn, setting_id, setting_value, &enabled)) {
                    return false;
                }
                conn->peer_settings.h3_datagram_draft04_enabled = enabled;
                conn->peer_settings.h3_datagram_enabled
                    = conn->peer_settings.h3_datagram_rfc_enabled
                    || conn->peer_settings.h3_datagram_draft04_enabled;
                WTF_LOG_TRACE(conn->context, "http3", "H3 draft04 datagrams enabled: %s",
                              enabled ? "yes" : "no");
                break;
            }

            case WTF_SETTING_QPACK_MAX_TABLE_CAPACITY:
                conn->peer_settings.qpack_max_table_capacity = (uint32_t)setting_value;
                conn->qpack.peer_max_table_capacity = (uint32_t)setting_value;
                WTF_LOG_TRACE(conn->context, "http3", "Peer QPACK max table capacity: %u",
                              (uint32_t)setting_value);
                break;

            case WTF_SETTING_MAX_FIELD_SECTION_SIZE:
                conn->peer_settings.max_field_section_size = (uint32_t)setting_value;
                WTF_LOG_TRACE(conn->context, "http3", "Max field section size: %u",
                              (uint32_t)setting_value);
                break;

            case WTF_SETTING_QPACK_BLOCKED_STREAMS:
                conn->peer_settings.qpack_blocked_streams = (uint32_t)setting_value;
                conn->qpack.peer_blocked_streams = setting_value;
                WTF_LOG_TRACE(conn->context, "http3", "Peer QPACK blocked streams: %u",
                              (uint32_t)setting_value);
                break;

            case WTF_SETTING_WEBTRANSPORT_MAX_SESSIONS_DRAFT07:
                conn->peer_settings.enable_webtransport_draft07 = (setting_value != 0);
                conn->peer_settings.enable_webtransport
                    = conn->peer_settings.enable_webtransport_draft02
                    || conn->peer_settings.enable_webtransport_draft07
                    || conn->peer_settings.enable_webtransport_draft15;
                conn->peer_settings.webtransport_max_sessions
                    = setting_value > UINT32_MAX ? UINT32_MAX : (uint32_t)setting_value;
                WTF_LOG_TRACE(conn->context, "http3",
                              "Peer draft-07 WebTransport max sessions: %u",
                              conn->peer_settings.webtransport_max_sessions);
                break;

            case WTF_SETTING_WT_INITIAL_MAX_STREAMS_UNI:
                conn->peer_settings.wt_initial_max_streams_uni = setting_value;
                WTF_LOG_TRACE(conn->context, "http3",
                              "Peer WT initial max uni streams: %llu",
                              (unsigned long long)setting_value);
                break;

            case WTF_SETTING_WT_INITIAL_MAX_STREAMS_BIDI:
                conn->peer_settings.wt_initial_max_streams_bidi = setting_value;
                WTF_LOG_TRACE(conn->context, "http3",
                              "Peer WT initial max bidi streams: %llu",
                              (unsigned long long)setting_value);
                break;

            case WTF_SETTING_WT_INITIAL_MAX_DATA:
                conn->peer_settings.wt_initial_max_data = setting_value;
                WTF_LOG_TRACE(conn->context, "http3", "Peer WT initial max data: %llu",
                              (unsigned long long)setting_value);
                break;

            default:
                WTF_LOG_DEBUG(conn->context, "http3",
                              "Ignoring unknown setting %llu (0x%llx) = %llu",
                              (unsigned long long)setting_id, (unsigned long long)setting_id,
                              (unsigned long long)setting_value);
                break;
        }
    }
    return true;
}

bool wtf_settings_encode_frame(wtf_connection* conn, uint8_t* buffer, size_t buffer_size,
                               size_t* frame_length)
{
#ifdef WTF_QUIC_BACKEND_NETWORK
    if (conn && conn->requested_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_15 && !conn->reliable_reset_negotiated) {
        return false;
    }
#endif
    if (!conn || !buffer || !frame_length)
        return false;

    uint8_t* current_pos = buffer;
    uint8_t* buffer_end = buffer + buffer_size;

    // Encode frame type
    current_pos = wtf_varint_encode(WTF_FRAME_SETTINGS, current_pos);
    if (current_pos >= buffer_end) {
        return false;
    }

    struct wtf_setting_pair {
        uint64_t id;
        uint64_t value;
    } settings_list[16];
    size_t settings_count = 0;

#define WTF_ADD_SETTING(Id, Value) \
    do { \
        settings_list[settings_count++] = (struct wtf_setting_pair){(Id), (Value)}; \
    } while (0)

    bool draft_auto = conn->requested_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_AUTO;
    bool draft15 = draft_auto || conn->requested_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_15;
#ifdef WTF_QUIC_BACKEND_NETWORK
    draft15 = draft15 && conn->reliable_reset_negotiated;
#endif
    bool draft07 = draft_auto || conn->requested_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_07;
    bool draft02 = draft_auto || conn->requested_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_02;

    WTF_ADD_SETTING(WTF_SETTING_QPACK_MAX_TABLE_CAPACITY,
                    conn->local_settings.qpack_max_table_capacity);
    WTF_ADD_SETTING(WTF_SETTING_QPACK_BLOCKED_STREAMS, conn->local_settings.qpack_blocked_streams);
    if (draft15 || draft07) {
        WTF_ADD_SETTING(WTF_SETTING_ENABLE_CONNECT_PROTOCOL, 1);
    }
    if (draft15) {
        WTF_ADD_SETTING(WTF_SETTING_WT_ENABLED_DRAFT15, 1);
        WTF_ADD_SETTING(WTF_SETTING_WT_MAX_SESSIONS,
                        conn->local_settings.webtransport_max_sessions);
    }
    if (draft02) {
        WTF_ADD_SETTING(WTF_SETTING_ENABLE_WEBTRANSPORT_DRAFT02, 1);
    }
    if (draft15 || draft07) {
        WTF_ADD_SETTING(WTF_SETTING_H3_DATAGRAM, 1);
    }
    if (draft02) {
        WTF_ADD_SETTING(WTF_SETTING_H3_DRAFT04_DATAGRAM, 1);
    }
    if (draft07) {
        WTF_ADD_SETTING(WTF_SETTING_WEBTRANSPORT_MAX_SESSIONS_DRAFT07,
                        conn->local_settings.webtransport_max_sessions);
    }
    if (draft15) {
        WTF_ADD_SETTING(WTF_SETTING_WT_INITIAL_MAX_STREAMS_UNI,
                        conn->local_settings.wt_initial_max_streams_uni);
        WTF_ADD_SETTING(WTF_SETTING_WT_INITIAL_MAX_STREAMS_BIDI,
                        conn->local_settings.wt_initial_max_streams_bidi);
        WTF_ADD_SETTING(WTF_SETTING_WT_INITIAL_MAX_DATA,
                        conn->local_settings.wt_initial_max_data);
    }
    WTF_ADD_SETTING(WTF_SETTING_MAX_FIELD_SECTION_SIZE, conn->local_settings.max_field_section_size);

#undef WTF_ADD_SETTING

    size_t settings_size = 0;
    for (size_t i = 0; i < settings_count; i++) {
        settings_size += wtf_varint_size(settings_list[i].id)
            + wtf_varint_size(settings_list[i].value);
    }

    // Encode settings size
    current_pos = wtf_varint_encode(settings_size, current_pos);
    if (current_pos >= buffer_end) {
        return false;
    }

    for (size_t i = 0; i < settings_count; i++) {
        // Encode setting ID
        current_pos = wtf_varint_encode(settings_list[i].id, current_pos);
        if (current_pos >= buffer_end) {
            return false;
        }

        // Encode setting value
        current_pos = wtf_varint_encode(settings_list[i].value, current_pos);
        if (current_pos >= buffer_end) {
            return false;
        }
    }

    *frame_length = current_pos - buffer;
    return true;
}
