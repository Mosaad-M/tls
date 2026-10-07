# ============================================================================
# test_std_compat.mojo — tls must not break programs that use Mojo's std
# ============================================================================
# A Mojo program may declare each C function with only one signature. The
# std library declares open/read/write, __error/__errno_location, getenv and
# clock_gettime itself, so if tls declared any of them with other types,
# every program combining tls with open(), listdir(), getenv(), get_errno()
# or the time functions would fail to compile ("existing function with
# conflicting signature"). tls 1.6.1 and earlier did.
#
# Compiling this file is the test: it reaches the tls code that talks to the
# OS (sockets, CA bundle, randomness, timeouts) together with those std APIs.
# Running it checks the std calls and the parts of tls that need no network.
# ============================================================================

from std.ffi import get_errno
from std.os import getenv, listdir
from std.sys import argv
from std.time import monotonic, perf_counter_ns
from crypto.random import csprng_bytes
from tls.connection import tls_set_timeout
from tls.socket import TlsSocket, load_system_ca_bundle

comptime PATH = "/tmp/mojo_tls_std_compat.txt"


def network_paths() raises:
    """Never run: compiled so that every C declaration on tls's socket paths
    is part of this program."""
    var anchors = load_system_ca_bundle()
    var fd = Int32(-1)
    tls_set_timeout(fd, 5)
    var s = TlsSocket(fd)
    s.connect("example.com", anchors)
    _ = s.send(List[UInt8](length=4, fill=0x41))
    _ = s.recv(16)
    _ = s.recv_all()
    s.close()


def main() raises:
    print("test_std_compat")
    if len(argv()) > 1000:
        network_paths()

    # std file I/O, directory listing, environment, errno and clocks
    with open(PATH, "w") as f:
        f.write("std open() next to tls\n")
    var text: String
    with open(PATH, "r") as f:
        text = f.read()
    if not text.startswith("std open()"):
        raise Error("std open()/read() round trip failed")
    var names = listdir("/tmp")
    _ = getenv("HOME")
    _ = get_errno()
    var t0 = perf_counter_ns()
    _ = monotonic()
    print("  PASS: std open/read/write, listdir (", len(names), "entries), getenv, get_errno, clocks")

    # tls code that needs no network
    if len(csprng_bytes(64)) != 64:
        raise Error("csprng_bytes returned the wrong length")
    var anchors = load_system_ca_bundle()
    if len(anchors) < 50:
        raise Error("system CA bundle has only " + String(len(anchors)) + " certificates")
    print("  PASS: csprng_bytes, load_system_ca_bundle (", len(anchors), "anchors)")
    if perf_counter_ns() < t0:
        raise Error("clock went backwards")
    print("Results: 2 passed, 0 failed")
