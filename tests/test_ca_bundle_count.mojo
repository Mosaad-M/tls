from tls.socket import load_system_ca_bundle

def main() raises:
    var anchors = load_system_ca_bundle()
    print("Parsed", len(anchors), "certs from /etc/ssl/certs/ca-certificates.crt")
