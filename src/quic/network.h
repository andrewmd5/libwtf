#ifndef WTF_QUIC_NETWORK_H
#define WTF_QUIC_NETWORK_H

#if defined(__APPLE__) && defined(WTF_QUIC_BACKEND_NETWORK)
    #include <msquic.h>

bool wtf_network_supports_reliable_reset(void);
bool wtf_network_supports_early_data(void);
void wtf_network_configuration_set_certificate_pin(HQUIC configuration, const uint8_t pin[32]);

/* Network needs the TLS identity before starting the listener. */
QUIC_STATUS wtf_network_listener_set_configuration(HQUIC listener, HQUIC configuration);
#endif

#endif
