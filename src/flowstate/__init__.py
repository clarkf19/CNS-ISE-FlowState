"""FlowState Secure Network Gateway.

Client -> Secure Gateway -> Backend Server. Every request is authenticated,
decrypted, integrity-checked, checked for freshness, session validity and
authorization before it reaches the backend.
"""

__version__ = "1.0.0"
PROTOCOL_VERSION = 1
