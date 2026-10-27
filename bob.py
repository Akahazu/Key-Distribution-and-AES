import socket
import threading
import os
import sys
from aes import encrypt_ecb, decrypt_ecb
from util import recv_line, ask_key, ask_int, tune, close_sock

HOST = "0.0.0.0"
state = {"kb": None, "sock": None, "ks": None}

def close_session(sock=None):
    if sock is None or state["sock"] is sock:
        state["sock"] = None
        state["ks"] = None
    if sock:
        close_sock(sock)

def receive_messages(sock, ks):
    try:
        while True:
            line = recv_line(sock)
            if not line:
                break
            try:
                plaintext = decrypt_ecb(bytes.fromhex(line), ks).decode('utf-8')
                print(f"\n[Alice] Ciphertext (hex): {line}")
                print(f"[Alice] Plaintext       : {plaintext}")
            except Exception as e:
                print(f"\n[!] Gagal dekripsi pesan dari Alice: {e}")
            print("> ", end="", flush=True)
    except Exception:
        pass

def authenticate(conn):
    tiket_hex = recv_line(conn)
    if not tiket_hex:
        raise ValueError("Tidak ada tiket diterima")
    print(f"[Langkah 3] E(Kb, ...) : {tiket_hex}")
    try:
        plain = decrypt_ecb(bytes.fromhex(tiket_hex), state["kb"]).decode('utf-8')
    except Exception:
        raise ValueError("Tiket tidak bisa didekripsi (Master Key Bob berbeda dengan di KDC?)")
    parts = plain.split("|")
    if len(parts) != 2 or len(parts[0]) != 32:
        raise ValueError("Format tiket Bob tidak valid")
    ks = bytes.fromhex(parts[0])
    print(f"[Langkah 3] ID Alice = {parts[1]}, Ks = {ks.hex()}")

    n2 = str(int.from_bytes(os.urandom(4), "big"))
    n2_hex = encrypt_ecb(n2.encode('utf-8'), ks).hex()
    conn.sendall(n2_hex.encode('ascii') + b"\n")
    print(f"[Langkah 4] N2 = {n2}")
    print(f"[Langkah 4] E(Ks, N2) : {n2_hex}")

    f_hex = recv_line(conn)
    if not f_hex:
        raise ValueError("Alice tidak mengirim f(N2)")
    f_plain = decrypt_ecb(bytes.fromhex(f_hex), ks).decode('utf-8')
    print(f"[Langkah 5] E(Ks, f(N2)) : {f_hex}")
    expected = str(int(n2) + 1)
    if f_plain != expected:
        raise ValueError(f"Verifikasi f(N2) gagal (diharapkan {expected}, dapat {f_plain})")
    print(f"[Langkah 5] f(N2) = {f_plain} -> valid")
    return ks

def handle_alice(conn, addr):
    print(f"\n[Bob] Koneksi masuk dari {addr[0]}:{addr[1]}")
    conn.settimeout(10)
    tune(conn)
    try:
        ks = authenticate(conn)
    except Exception as e:
        print(f"[!] Autentikasi gagal: {e}")
        close_sock(conn)
        return
    conn.settimeout(None)
    state["sock"] = conn
    state["ks"] = ks
    print("\n[SUKSES] Autentikasi selesai. Ketik pesan untuk dikirim.\n")
    print("> ", end="", flush=True)
    receive_messages(conn, ks)
    if state["sock"] is conn:
        print("\n[info] Koneksi dengan Alice terputus.")
        print("> ", end="", flush=True)
    close_session(conn)

def accept_loop(server):
    while True:
        try:
            conn, addr = server.accept()
        except OSError:
            return
        handle_alice(conn, addr)

def show_help():
    print("Perintah: /key  /help  exit   (selain itu = pesan)")

def start_bob():
    print("=" * 50)
    print("                 BOB (RESPONDER)               ")
    print("=" * 50)

    port = ask_int("Port Bob: ")
    state["kb"] = ask_key("Master Key Bob (16 karakter): ")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, port))
    server.listen(1)
    threading.Thread(target=accept_loop, args=(server,), daemon=True).start()
    print(f"[Bob] Menunggu Alice di port {port}...")
    show_help()

    while True:
        try:
            msg = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not msg:
            continue
        low = msg.lower()
        if low == "exit":
            break
        elif low == "/key":
            state["kb"] = ask_key("Master Key Bob baru (16 karakter): ")
            print("[Bob] Key diganti. Berlaku untuk koneksi berikutnya.")
        elif low == "/help":
            show_help()
        elif state["sock"] is None:
            print("[!] Belum ada Alice yang terhubung.")
        else:
            try:
                packet = encrypt_ecb(msg.encode('utf-8'), state["ks"])
                state["sock"].sendall(packet.hex().encode('ascii') + b"\n")
                print(f"[Bob] Ciphertext (hex): {packet.hex()}")
            except Exception:
                print("[!] Gagal mengirim pesan.")
                close_session(state["sock"])
    close_session(state["sock"])
    server.close()
    print("[Bob] Selesai.")

if __name__ == "__main__":
    start_bob()
    sys.exit(0)