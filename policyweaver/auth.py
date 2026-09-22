"""In-memory, audience-scoped token reuse with an early refresh margin."""
import threading
import time


class CachedCredential:
    def __init__(self, credential, *, refresh_margin_seconds=120, clock=time.time):
        self.credential, self.margin, self.clock = credential, refresh_margin_seconds, clock
        self._tokens = {}
        self._lock = threading.Lock()

    def get_token(self, *scopes, **kwargs):
        # Claims challenges and per-call tenant overrides never share cached tokens.
        if kwargs:
            return self.credential.get_token(*scopes, **kwargs)
        with self._lock:
            token = self._tokens.get(tuple(scopes))
            if token is None or token.expires_on <= self.clock() + self.margin:
                token = self.credential.get_token(*scopes)
                if token.expires_on <= self.clock():
                    raise RuntimeError("credential_returned_expired_token")
                self._tokens[tuple(scopes)] = token
            return token

    def close(self):
        with self._lock:
            self._tokens.clear()
        close = getattr(self.credential, "close", None)
        if close:
            close()
