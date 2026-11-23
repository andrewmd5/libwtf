#ifndef WTF_DRAFT_H
#define WTF_DRAFT_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

wtf_webtransport_draft_t wtf_draft_select(wtf_webtransport_draft_t requested,
                                         const wtf_settings* peer_settings, bool reliable_reset);

#ifdef __cplusplus
}
#endif

#endif  // WTF_DRAFT_H
