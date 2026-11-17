# Network.framework backend

Experimental. Local tests showed substantially worse performance than MsQuic,
especially when creating and closing streams. Prefer MsQuic where possible.

This backend is kept for Apple deployments where shipping MsQuic is not an
option and the system QUIC stack is needed. Apple TV/tvOS is an intended target;
the implementation has only been tested on macOS.

Build with `-DWTF_QUIC_BACKEND=network` on macOS 15 or later.
