#include "draft.h"

wtf_webtransport_draft_t wtf_draft_select(wtf_webtransport_draft_t requested,
                                         const wtf_settings* peer_settings, bool reliable_reset)
{
    if (!peer_settings) {
        return WTF_WEBTRANSPORT_DRAFT_NONE;
    }

    bool draft15 = reliable_reset && peer_settings->enable_webtransport_draft15;

    switch (requested) {
        case WTF_WEBTRANSPORT_DRAFT_15:
            return draft15 ? WTF_WEBTRANSPORT_DRAFT_15 : WTF_WEBTRANSPORT_DRAFT_NONE;
        case WTF_WEBTRANSPORT_DRAFT_07:
            return peer_settings->enable_webtransport_draft07 ? WTF_WEBTRANSPORT_DRAFT_07
                                                              : WTF_WEBTRANSPORT_DRAFT_NONE;
        case WTF_WEBTRANSPORT_DRAFT_02:
            return peer_settings->enable_webtransport_draft02 ? WTF_WEBTRANSPORT_DRAFT_02
                                                              : WTF_WEBTRANSPORT_DRAFT_NONE;
        case WTF_WEBTRANSPORT_DRAFT_AUTO:
        default:
            break;
    }

    if (draft15) {
        return WTF_WEBTRANSPORT_DRAFT_15;
    }

    if (peer_settings->enable_webtransport_draft07) {
        return WTF_WEBTRANSPORT_DRAFT_07;
    }

    if (peer_settings->enable_webtransport_draft02) {
        return WTF_WEBTRANSPORT_DRAFT_02;
    }

    return WTF_WEBTRANSPORT_DRAFT_NONE;
}
