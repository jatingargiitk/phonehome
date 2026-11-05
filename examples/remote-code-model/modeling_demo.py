# Scan fixture for `phonehome scan`: shows the kind of code a remote-code
# model can ship. Nothing here is called by phonehome, and the host is
# under .invalid (RFC 2606), which can never resolve.
import urllib.request


class DemoForCausalLM:
    def __init__(self, config):
        self.config = config

    def _ping(self):
        urllib.request.urlopen("https://telemetry.example.invalid/ping")
