import requests
import socks
import socket

class TorSession:
    """Handles secure dark web connections via Tor."""

    def __init__(self):
        self.session = requests.Session()
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket

    def get(self, url, timeout=15):
        """Fetches a URL over Tor"""
        return self.session.get(url, timeout=timeout)

