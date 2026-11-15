# SSL_CERT_FILE selects the CA bundle, and load_ca_bundle reads any PEM file.
from std.os import setenv, unsetenv
from tls.socket import load_system_ca_bundle, load_ca_bundle


def _first_pem_block(bundle: String) raises -> String:
    var start = bundle.find("-----BEGIN CERTIFICATE-----")
    var end_marker = "-----END CERTIFICATE-----"
    var end = bundle.find(end_marker, start)
    if start < 0 or end < 0:
        raise Error("no certificate in the system bundle")
    return String(bundle[byte=start : end + end_marker.byte_length()]) + "\n"


def main() raises:
    var system = load_system_ca_bundle()
    if len(system) < 10:
        raise Error("system bundle: only " + String(len(system)) + " certs")

    # One certificate from the system bundle, on its own.
    var path = String("/tmp/tls_test_ca_bundle_env.pem")
    var bundle_path = String("/etc/ssl/cert.pem")
    try:
        with open("/etc/ssl/certs/ca-certificates.crt", "r") as f:
            _ = f.read(1)
        bundle_path = "/etc/ssl/certs/ca-certificates.crt"
    except:
        pass
    var text: String
    with open(bundle_path, "r") as f:
        text = f.read()
    with open(path, "w") as f:
        f.write(_first_pem_block(text))

    var one = load_ca_bundle(path)
    if len(one) != 1:
        raise Error("load_ca_bundle: expected 1 cert, got " + String(len(one)))

    _ = setenv("SSL_CERT_FILE", path)
    var from_env = load_system_ca_bundle()
    _ = unsetenv("SSL_CERT_FILE")
    if len(from_env) != 1:
        raise Error("SSL_CERT_FILE ignored: got " + String(len(from_env)) + " certs")

    _ = setenv("SSL_CERT_FILE", "/nonexistent/bundle.pem")
    var raised = False
    try:
        _ = load_system_ca_bundle()
    except:
        raised = True
    _ = unsetenv("SSL_CERT_FILE")
    if not raised:
        raise Error("a missing SSL_CERT_FILE must raise, not fall back")
    print("test_ca_bundle_env: PASS (system bundle", len(system), "certs)")
