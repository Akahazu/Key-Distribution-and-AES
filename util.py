import socket

_buffers = {}

def tune(sock):
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

def recv_line(sock):
    buf = _buffers.get(sock, b"")
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            _buffers.pop(sock, None)
            return buf.decode('ascii').strip()
        buf += chunk
    line, _buffers[sock] = buf.split(b"\n", 1)
    return line.decode('ascii').strip()

def close_sock(sock):
    _buffers.pop(sock, None)
    try:
        sock.shutdown(socket.SHUT_WR)
        sock.settimeout(1)
        while sock.recv(4096):
            pass
    except OSError:
        pass
    finally:
        sock.close()

def ask_key(prompt):
    while True:
        key = input(prompt)
        if len(key) == 16 and key.isascii():
            return key.encode('ascii')
        print("[!] Key harus tepat 16 karakter ASCII.")

def ask_int(prompt):
    while True:
        try:
            return int(input(prompt).strip())
        except ValueError:
            print("[!] Masukkan angka.")

def ask_id(prompt):
    while True:
        val = input(prompt).strip()
        if val and "|" not in val and val.isascii():
            return val
        print("[!] ID tidak boleh kosong, harus ASCII, dan tanpa karakter '|'.")