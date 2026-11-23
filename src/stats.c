#include "conn.h"
#include "utils.h"

#include <string.h>

typedef struct {
    const char* key;
    size_t offset;
    size_t size;
} wtf_quic_stat;

#define WTF_QUIC_STAT(key, field) \
    {key, offsetof(QUIC_STATISTICS_V2, field), sizeof(((QUIC_STATISTICS_V2*)0)->field)}

static const wtf_quic_stat quic_stats[] = {
    WTF_QUIC_STAT("quic.smoothed_rtt_us", Rtt),
    WTF_QUIC_STAT("quic.min_rtt_us", MinRtt),
#ifdef QUIC_STATISTICS_V2_SIZE_4
    WTF_QUIC_STAT("quic.rtt_variance_us", RttVariance),
#else
    {"quic.rtt_variance_us", 0, 0},
#endif
    WTF_QUIC_STAT("quic.congestion_window_bytes", SendCongestionWindow),
    WTF_QUIC_STAT("quic.path_mtu_bytes", SendPathMtu),
    WTF_QUIC_STAT("quic.congestion_events", SendCongestionCount),
    WTF_QUIC_STAT("quic.packets_sent", SendTotalPackets),
    WTF_QUIC_STAT("quic.packets_lost", SendSuspectedLostPackets),
    WTF_QUIC_STAT("quic.bytes_sent", SendTotalBytes),
    WTF_QUIC_STAT("quic.bytes_received", RecvTotalBytes),
};

#undef WTF_QUIC_STAT

static bool wtf_is_app_stat_key(const char* key)
{
    return key && strncmp(key, "app.", 4) == 0 && key[4] != '\0';
}

static wtf_result_t wtf_get_quic_stat(wtf_connection* conn, const wtf_quic_stat* stat,
                                     uint64_t* value)
{
    QUIC_STATISTICS_V2 stats = {0};
    uint32_t size = sizeof(stats);
    wtf_result_t result = wtf_connection_get_statistics(conn, &stats, &size);
    if (result != WTF_SUCCESS) {
        return result;
    }
    if (stat->size == 0 || size < stat->offset + stat->size) {
        return WTF_ERROR_NOT_SUPPORTED;
    }

    const uint8_t* field = (const uint8_t*)&stats + stat->offset;
    switch (stat->size) {
        case sizeof(uint16_t): {
            uint16_t sample;
            memcpy(&sample, field, sizeof(sample));
            *value = sample;
            break;
        }
        case sizeof(uint32_t): {
            uint32_t sample;
            memcpy(&sample, field, sizeof(sample));
            *value = sample;
            break;
        }
        case sizeof(uint64_t):
            if (stat->offset == offsetof(QUIC_STATISTICS_V2, SendSuspectedLostPackets)) {
                uint64_t suspected = stats.SendSuspectedLostPackets;
                uint64_t spurious = stats.SendSpuriousLostPackets;
                *value = suspected > spurious ? suspected - spurious : 0;
            } else {
                memcpy(value, field, sizeof(*value));
            }
            break;
        default:
            return WTF_ERROR_INTERNAL;
    }
    return WTF_SUCCESS;
}

wtf_result_t wtf_session_get_stat(wtf_session_t* session, const char* key, uint64_t* value)
{
    if (!session || !key || !*key || !value) {
        return WTF_ERROR_INVALID_PARAMETER;
    }
    if (wtf_is_app_stat_key(key)) {
        mtx_lock(&session->streams_mutex);
        stat_map_itr entry = stat_map_get(&session->app_stats, key);
        bool found = !stat_map_is_end(entry);
        if (found) {
            *value = entry.data->val;
        }
        mtx_unlock(&session->streams_mutex);
        return found ? WTF_SUCCESS : WTF_ERROR_NOT_FOUND;
    }

    for (size_t i = 0; i < sizeof(quic_stats) / sizeof(quic_stats[0]); ++i) {
        if (strcmp(key, quic_stats[i].key) == 0) {
            return wtf_get_quic_stat(session->connection, &quic_stats[i], value);
        }
    }
    return WTF_ERROR_NOT_FOUND;
}

wtf_result_t wtf_session_set_stat(wtf_session_t* session, const char* key, uint64_t value)
{
    if (!session || !wtf_is_app_stat_key(key)) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    mtx_lock(&session->streams_mutex);
    stat_map_itr entry = stat_map_get(&session->app_stats, key);
    if (!stat_map_is_end(entry)) {
        entry.data->val = value;
        mtx_unlock(&session->streams_mutex);
        return WTF_SUCCESS;
    }
    char* copy = wtf_strdup(key);
    if (!copy) {
        mtx_unlock(&session->streams_mutex);
        return WTF_ERROR_OUT_OF_MEMORY;
    }
    entry = stat_map_insert(&session->app_stats, copy, value);
    bool inserted = !stat_map_is_end(entry);
    if (!inserted) {
        free(copy);
    }
    mtx_unlock(&session->streams_mutex);
    return inserted ? WTF_SUCCESS : WTF_ERROR_OUT_OF_MEMORY;
}

wtf_result_t wtf_session_remove_stat(wtf_session_t* session, const char* key)
{
    if (!session || !wtf_is_app_stat_key(key)) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    mtx_lock(&session->streams_mutex);
    bool removed = stat_map_erase(&session->app_stats, key);
    mtx_unlock(&session->streams_mutex);
    return removed ? WTF_SUCCESS : WTF_ERROR_NOT_FOUND;
}
