# ============================================================================
# sockpair.mojo — socketpair plumbing for tests that stand in for a server
# ============================================================================
# tls reads and writes with recv/send, so tests feed it a connected
# AF_UNIX socketpair rather than a file. The C declarations here use the same
# signatures as the tcp package and tls (recv/send/close/shutdown), and none
# that std declares itself (see tests/test_std_compat.mojo).
# ============================================================================

from std.ffi import external_call
from std.memory import alloc
from std.sys.info import CompilationTarget

comptime _SHUT_WR: Int32 = 1
comptime _SOL_SOCKET: Int32 = 0xFFFF if CompilationTarget.is_macos() else 1
comptime _SO_SNDBUF: Int32 = 0x1001 if CompilationTarget.is_macos() else 7
comptime _SO_RCVBUF: Int32 = 0x1002 if CompilationTarget.is_macos() else 8


struct Pair(Movable):
    """mine: the TlsSocket side. peer: the test's "server" side."""
    var mine: Int32
    var peer: Int32

    def __init__(out self) raises:
        var fds = alloc[Int32](2)
        # AF_UNIX = 1, SOCK_STREAM = 1 on Linux and macOS
        var rc = external_call["socketpair", Int32](Int32(1), Int32(1), Int32(0), fds)
        if rc != 0:
            fds.unsafe_free()
            raise Error("socketpair failed")
        self.mine = fds[unsafe_offset=0]
        self.peer = fds[unsafe_offset=1]
        fds.unsafe_free()

    def grow_buffers(self, n: Int):
        """Ask for n-byte socket buffers so a test can write n bytes before
        reading (macOS defaults to ~8 KB; Linux caps at net.core.wmem_max)."""
        var v = alloc[Int32](1)
        v[unsafe_offset=0] = Int32(n)
        for fd in [self.mine, self.peer]:
            _ = external_call["setsockopt", Int32](fd, _SOL_SOCKET, _SO_SNDBUF, Int(v), Int32(4))
            _ = external_call["setsockopt", Int32](fd, _SOL_SOCKET, _SO_RCVBUF, Int(v), Int32(4))
        v.unsafe_free()

    def end_peer_output(self):
        """The peer stops sending: mine reads end of stream after the data
        already sent, and whatever tls writes still reaches the peer."""
        _ = external_call["shutdown", Int32](self.peer, _SHUT_WR)

    def close(self):
        _ = external_call["close", Int32](self.mine)
        _ = external_call["close", Int32](self.peer)


def send_all(fd: Int32, data: List[UInt8]) raises:
    var n = len(data)
    if n == 0:
        return
    var buf = alloc[UInt8](n)
    for i in range(n):
        buf[unsafe_offset=i] = data[i]
    var total = 0
    while total < n:
        var sent = external_call["send", Int](fd, Int(buf.unsafe_offset(total)), n - total, Int32(0))
        if sent <= 0:
            buf.unsafe_free()
            raise Error("peer send failed")
        total += sent
    buf.unsafe_free()


def recv_some(fd: Int32, max_bytes: Int) raises -> List[UInt8]:
    """Up to max_bytes; empty at end of stream."""
    var buf = alloc[UInt8](max_bytes)
    var got = external_call["recv", Int](fd, Int(buf), max_bytes, Int32(0))
    if got < 0:
        buf.unsafe_free()
        raise Error("peer recv failed")
    var out = List[UInt8](capacity=got)
    for i in range(got):
        out.append(buf[unsafe_offset=i])
    buf.unsafe_free()
    return out^


def recv_exact(fd: Int32, n: Int) raises -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    while len(out) < n:
        var chunk = recv_some(fd, n - len(out))
        if len(chunk) == 0:
            raise Error("peer recv: end of stream")
        for b in chunk:
            out.append(b)
    return out^
