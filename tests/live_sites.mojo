# ============================================================================
# live_sites.mojo — manual check against real servers (needs network)
# ============================================================================
# Connects to well-known HTTPS sites with the system CA bundle and checks the
# handshake (including certificate path validation) succeeds, then checks
# that badssl.com's deliberately broken endpoints are rejected.
# Not part of `pixi run test`: run before releases that touch validation.
#
#   mojo run -I . -I <path-to-tcp-package> tests/live_sites.mojo
# ============================================================================

from tcp import TcpSocket
from tls.socket import TlsSocket, load_system_ca_bundle


def main() raises:
    var anchors = load_system_ca_bundle()
    var hosts = List[String]()
    for h in [
        "www.google.com", "github.com", "api.github.com",
        "raw.githubusercontent.com", "www.cloudflare.com", "letsencrypt.org",
        "www.amazon.com", "en.wikipedia.org", "www.microsoft.com",
        "www.apple.com", "example.com", "www.python.org", "pypi.org",
        "www.mozilla.org", "www.bing.com", "conda.modular.com",
        "www.youtube.com", "www.reddit.com", "www.digicert.com", "www.netflix.com",
        "badssl.com",  # TLS 1.2 only, RSA certificate
        "ecc384.badssl.com",  # TLS 1.2, P-384 ECDSA certificate
        "ecc256.badssl.com", "rsa4096.badssl.com",  # (sha384.badssl.com: cert expired 2022)
    ]:
        hosts.append(h)
    var failures = 0
    print("Must validate:")
    for i in range(len(hosts)):
        var host = hosts[i]
        try:
            var tcp = TcpSocket()
            tcp.connect(host, 443)
            var tls = TlsSocket(tcp.fd)
            tls.connect(host, anchors)
            print("  OK  ", host)
            try:
                tls.close()
            except:
                pass
        except e:
            failures += 1
            print("  FAIL", host, "-", String(e))
    print()
    print("Must be rejected:")
    var bad = List[String]()
    for h in [
        "expired.badssl.com", "wrong.host.badssl.com", "self-signed.badssl.com",
        "untrusted-root.badssl.com",
    ]:
        bad.append(h)
    for i in range(len(bad)):
        var host = bad[i]
        try:
            var tcp = TcpSocket()
            tcp.connect(host, 443)
            var tls = TlsSocket(tcp.fd)
            tls.connect(host, anchors)
            failures += 1
            print("  FAIL", host, "- accepted")
        except e:
            print("  OK  ", host, "rejected:", String(e))
    print()
    print(
        "validated", len(hosts), "sites and", len(bad), "bad endpoints:",
        failures, "failure(s)",
    )
    if failures > 0:
        raise Error(String(failures) + " live check(s) failed")
