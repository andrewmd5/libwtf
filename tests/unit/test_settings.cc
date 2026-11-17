#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>

extern "C" {
#include "settings.h"
#include "varint.h"
}

namespace {

wtf_connection MakeConnection(wtf_webtransport_draft_t draft = WTF_WEBTRANSPORT_DRAFT_AUTO)
{
    wtf_connection conn = {};
    conn.requested_webtransport_draft = draft;
    conn.reliable_reset_negotiated = true;
    wtf_settings_init(&conn.local_settings);
    conn.local_settings.qpack_max_table_capacity = WTF_QPACK_DYNAMIC_TABLE_SIZE;
    conn.local_settings.qpack_blocked_streams = WTF_QPACK_MAX_BLOCKED_STREAMS;
    conn.local_settings.max_field_section_size = 65536;
    conn.local_settings.webtransport_max_sessions = 16;
    conn.local_settings.wt_initial_max_streams_bidi = 32;
    conn.local_settings.wt_initial_max_streams_uni = 32;
    conn.local_settings.wt_initial_max_data = 1048576;
    return conn;
}

uint8_t* AppendSetting(uint8_t* pos, uint64_t id, uint64_t value)
{
    pos = wtf_varint_encode(id, pos);
    return wtf_varint_encode(value, pos);
}

bool EncodedSettingsHasId(const uint8_t* frame, size_t frame_len, uint64_t expected_id)
{
    size_t offset = 0;
    uint64_t frame_type = 0;
    uint64_t payload_len = 0;

    if (!wtf_varint_decode(frame_len, frame, &offset, &frame_type)
        || !wtf_varint_decode(frame_len, frame, &offset, &payload_len)) {
        return false;
    }

    if (frame_type != WTF_FRAME_SETTINGS || payload_len > frame_len - offset) {
        return false;
    }

    size_t end = offset + static_cast<size_t>(payload_len);
    while (offset < end) {
        uint64_t setting_id = 0;
        uint64_t setting_value = 0;
        if (!wtf_varint_decode(end, frame, &offset, &setting_id)
            || !wtf_varint_decode(end, frame, &offset, &setting_value)) {
            return false;
        }
        if (setting_id == expected_id) {
            return true;
        }
    }

    return false;
}

}  // namespace

TEST(Settings, AutoAdvertisesAllSupportedDrafts)
{
    wtf_connection conn = MakeConnection();
    uint8_t frame[512] = {};
    size_t frame_len = 0;

    ASSERT_TRUE(wtf_settings_encode_frame(&conn, frame, sizeof(frame), &frame_len));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_WT_ENABLED_DRAFT15));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_ENABLE_WEBTRANSPORT_DRAFT02));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_WEBTRANSPORT_MAX_SESSIONS_DRAFT07));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_H3_DATAGRAM));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_H3_DRAFT04_DATAGRAM));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_WT_INITIAL_MAX_STREAMS_BIDI));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_WT_INITIAL_MAX_DATA));
}

TEST(Settings, Draft15OnlyAdvertisesRfcDatagramsAndDraft15Settings)
{
    wtf_connection conn = MakeConnection(WTF_WEBTRANSPORT_DRAFT_15);
    uint8_t frame[512] = {};
    size_t frame_len = 0;

    ASSERT_TRUE(wtf_settings_encode_frame(&conn, frame, sizeof(frame), &frame_len));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_WT_ENABLED_DRAFT15));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_H3_DATAGRAM));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_WT_INITIAL_MAX_STREAMS_BIDI));
    EXPECT_FALSE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_ENABLE_WEBTRANSPORT_DRAFT02));
    EXPECT_FALSE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_WEBTRANSPORT_MAX_SESSIONS_DRAFT07));
    EXPECT_FALSE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_H3_DRAFT04_DATAGRAM));
}

TEST(Settings, Draft07OnlyAdvertisesRfcDatagramsAndMaxSessions)
{
    wtf_connection conn = MakeConnection(WTF_WEBTRANSPORT_DRAFT_07);
    uint8_t frame[512] = {};
    size_t frame_len = 0;

    ASSERT_TRUE(wtf_settings_encode_frame(&conn, frame, sizeof(frame), &frame_len));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_ENABLE_CONNECT_PROTOCOL));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_H3_DATAGRAM));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_WEBTRANSPORT_MAX_SESSIONS_DRAFT07));
    EXPECT_FALSE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_WT_ENABLED_DRAFT15));
    EXPECT_FALSE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_ENABLE_WEBTRANSPORT_DRAFT02));
    EXPECT_FALSE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_WT_INITIAL_MAX_STREAMS_BIDI));
}

TEST(Settings, Draft02OnlyAdvertisesLegacyDatagramsAndLegacyWebTransport)
{
    wtf_connection conn = MakeConnection(WTF_WEBTRANSPORT_DRAFT_02);
    uint8_t frame[512] = {};
    size_t frame_len = 0;

    ASSERT_TRUE(wtf_settings_encode_frame(&conn, frame, sizeof(frame), &frame_len));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_ENABLE_WEBTRANSPORT_DRAFT02));
    EXPECT_TRUE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_H3_DRAFT04_DATAGRAM));
    EXPECT_FALSE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_ENABLE_CONNECT_PROTOCOL));
    EXPECT_FALSE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_H3_DATAGRAM));
    EXPECT_FALSE(EncodedSettingsHasId(frame, frame_len, WTF_SETTING_WT_ENABLED_DRAFT15));
}

TEST(Settings, DecodesDraft15Settings)
{
    wtf_connection conn = MakeConnection();
    wtf_settings_init(&conn.peer_settings);
    uint8_t peer_body[64] = {};
    uint8_t* pos = peer_body;
    pos = AppendSetting(pos, WTF_SETTING_ENABLE_CONNECT_PROTOCOL, 1);
    pos = AppendSetting(pos, WTF_SETTING_H3_DATAGRAM, 1);
    pos = AppendSetting(pos, WTF_SETTING_WT_ENABLED_DRAFT15, 1);
    pos = AppendSetting(pos, WTF_SETTING_WT_INITIAL_MAX_STREAMS_BIDI, 7);

    ASSERT_TRUE(wtf_settings_decode_frame(&conn, peer_body, static_cast<size_t>(pos - peer_body)));
    EXPECT_TRUE(conn.peer_settings.enable_webtransport);
    EXPECT_TRUE(conn.peer_settings.enable_webtransport_draft15);
    EXPECT_TRUE(conn.peer_settings.h3_datagram_rfc_enabled);
    EXPECT_EQ(conn.peer_settings.wt_initial_max_streams_bidi, 7u);
    EXPECT_TRUE(conn.peer_settings.wt_initial_max_streams_bidi_received);
    EXPECT_FALSE(conn.peer_settings.wt_initial_max_streams_uni_received);
}

TEST(Settings, DecodesDraft07Settings)
{
    wtf_connection conn = MakeConnection();
    wtf_settings_init(&conn.peer_settings);
    uint8_t peer_body[64] = {};
    uint8_t* pos = peer_body;
    pos = AppendSetting(pos, WTF_SETTING_ENABLE_CONNECT_PROTOCOL, 1);
    pos = AppendSetting(pos, WTF_SETTING_H3_DATAGRAM, 1);
    pos = AppendSetting(pos, WTF_SETTING_WEBTRANSPORT_MAX_SESSIONS_DRAFT07, 3);

    ASSERT_TRUE(wtf_settings_decode_frame(&conn, peer_body, static_cast<size_t>(pos - peer_body)));
    EXPECT_TRUE(conn.peer_settings.enable_webtransport);
    EXPECT_TRUE(conn.peer_settings.enable_webtransport_draft07);
    EXPECT_TRUE(conn.peer_settings.h3_datagram_rfc_enabled);
    EXPECT_EQ(conn.peer_settings.webtransport_max_sessions, 3u);
}

TEST(Settings, DecodesDraft02Settings)
{
    wtf_connection conn = MakeConnection();
    wtf_settings_init(&conn.peer_settings);
    uint8_t peer_body[64] = {};
    uint8_t* pos = peer_body;
    pos = AppendSetting(pos, WTF_SETTING_ENABLE_CONNECT_PROTOCOL, 1);
    pos = AppendSetting(pos, WTF_SETTING_H3_DRAFT04_DATAGRAM, 1);
    pos = AppendSetting(pos, WTF_SETTING_ENABLE_WEBTRANSPORT_DRAFT02, 1);

    ASSERT_TRUE(wtf_settings_decode_frame(&conn, peer_body, static_cast<size_t>(pos - peer_body)));
    EXPECT_TRUE(conn.peer_settings.enable_webtransport);
    EXPECT_TRUE(conn.peer_settings.enable_webtransport_draft02);
    EXPECT_TRUE(conn.peer_settings.h3_datagram_enabled);
    EXPECT_TRUE(conn.peer_settings.h3_datagram_draft04_enabled);
}

TEST(Settings, RejectsInvalidBooleanSettings)
{
    wtf_connection conn = MakeConnection();
    uint8_t peer_body[64] = {};
    uint8_t* pos = peer_body;
    pos = AppendSetting(pos, WTF_SETTING_H3_DATAGRAM, 2);

    EXPECT_FALSE(wtf_settings_decode_frame(&conn, peer_body, static_cast<size_t>(pos - peer_body)));

    wtf_settings_init(&conn.peer_settings);
    pos = peer_body;
    pos = AppendSetting(pos, WTF_SETTING_ENABLE_WEBTRANSPORT_DRAFT02, 2);
    EXPECT_FALSE(wtf_settings_decode_frame(&conn, peer_body, static_cast<size_t>(pos - peer_body)));
}

TEST(Settings, AllowsNonZeroDraft15EnableValues)
{
    wtf_connection conn = MakeConnection();
    wtf_settings_init(&conn.peer_settings);
    uint8_t peer_body[64] = {};
    uint8_t* pos = peer_body;
    pos = AppendSetting(pos, WTF_SETTING_WT_ENABLED_DRAFT15, 2);

    ASSERT_TRUE(wtf_settings_decode_frame(&conn, peer_body, static_cast<size_t>(pos - peer_body)));
    EXPECT_TRUE(conn.peer_settings.enable_webtransport_draft15);
}
