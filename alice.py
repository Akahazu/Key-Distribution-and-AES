import socket
import threading
import time
import sys
from aes import encrypt_cbc, decrypt_cbc
from util import recv_line, ask_key, ask_int, ask_id, tune, close_sock

session = {"sock": None, "ks": None}

def close_session():
    sock = session["sock"]
    session["sock"] = None
    session["ks"] = None
    if sock:
        close_sock(sock)

def receive_messages(sock, ks):
    try:
        while True:
            line = recv_line(sock)
            if not line:
                break
            try:
                plaintext = decrypt_cbc(bytes.fromhex(line), ks).decode('utf-8')
                print(f"\n[Bob] Ciphertext (hex): {line}")
                print(f"[Bob] Plaintext       : {plaintext}")
            except Exception as e:
                print(f"\n[!] Gagal dekripsi pesan dari Bob: {e}")
            print("> ", end="", flush=True)
    except Exception:
        pass
    if session["sock"] is sock:
        close_session()
        print("\n[info] Koneksi dengan Bob terputus.")
        print("> ", end="", flush=True)

def ask_config():
    cfg = {}
    cfg["kdc_ip"] = input("IP KDC: ").strip()
    cfg["kdc_port"] = ask_int("Port KDC: ")
    cfg["bob_ip"] = input("IP Bob: ").strip()
    cfg["bob_port"] = ask_int("Port Bob: ")
    cfg["id_a"] = ask_id("ID Alice: ")
    cfg["id_b"] = ask_id("ID Bob: ")
    return cfg

def get_session_key(cfg, ka):
    n1 = str(int(time.time()))
    print(f"\n[Langkah 1] Kirim ke KDC {cfg['kdc_ip']}:{cfg['kdc_port']} : {cfg['id_a']} || {cfg['id_b']} || {n1}")
    kdc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    kdc_sock.settimeout(10)
    tune(kdc_sock)
    try:
        kdc_sock.connect((cfg["kdc_ip"], cfg["kdc_port"]))
        kdc_sock.sendall(f"{cfg['id_a']}|{cfg['id_b']}|{n1}\n".encode('ascii'))
        line_a = recv_line(kdc_sock)
        if line_a.startswith("ERROR"):
            raise ValueError(f"KDC menolak: {line_a.split('|', 1)[-1]}")
        line_b = recv_line(kdc_sock)
    finally:
        kdc_sock.close()
    if not line_a or not line_b:
        raise ValueError("Tiket dari KDC tidak lengkap")
    print(f"[Langkah 2] E(Ka, ...) : {line_a}")
    print(f"[Langkah 2] E(Kb, ...) : {line_b}")

    try:
        plain = decrypt_cbc(bytes.fromhex(line_a), ka).decode('utf-8')
    except Exception:
        raise ValueError("Tiket tidak bisa didekripsi (Master Key Alice berbeda dengan di KDC?)")
    parts = plain.split("|")
    if len(parts) != 4:
        raise ValueError("Format tiket Alice tidak valid")
    ks_hex, recv_a, recv_b, recv_n1 = parts
    if (recv_a, recv_b, recv_n1) != (cfg["id_a"], cfg["id_b"], n1):
        raise ValueError("Validasi tiket gagal (ID atau N1 tidak cocok)")
    ks = bytes.fromhex(ks_hex)
    print(f"[Langkah 2] Ks = {ks.hex()}")
    return ks, line_b

def authenticate_with_bob(cfg, ks, tiket_bob_hex):
    print(f"\n[Langkah 3] Kirim ke Bob {cfg['bob_ip']}:{cfg['bob_port']} : {tiket_bob_hex}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    tune(sock)
    try:
        sock.connect((cfg["bob_ip"], cfg["bob_port"]))
        sock.sendall(tiket_bob_hex.encode('ascii') + b"\n")
        n2_hex = recv_line(sock)
        if not n2_hex:
            raise ValueError("Bob menutup koneksi (Master Key Bob salah atau tiket ditolak)")
        n2 = decrypt_cbc(bytes.fromhex(n2_hex), ks).decode('utf-8')
        print(f"[Langkah 4] E(Ks, N2) : {n2_hex}")
        print(f"[Langkah 4] N2 = {n2}")
        f_n2 = str(int(n2) + 1)
        f_hex = encrypt_cbc(f_n2.encode('utf-8'), ks).hex()
        sock.sendall(f_hex.encode('ascii') + b"\n")
        print(f"[Langkah 5] E(Ks, f(N2)) : {f_hex}")
        print(f"[Langkah 5] f(N2) = {f_n2}")
    except Exception:
        close_sock(sock)
        raise
    sock.settimeout(None)
    return sock

def connect(cfg, ka):
    close_session()
    try:
        ks, tiket_bob_hex = get_session_key(cfg, ka)
        sock = authenticate_with_bob(cfg, ks, tiket_bob_hex)
    except socket.timeout:
        print("[!] Timeout saat menghubungi KDC/Bob.")
        return
    except Exception as e:
        print(f"[!] {e}")
        return
    session["sock"] = sock
    session["ks"] = ks
    threading.Thread(target=receive_messages, args=(sock, ks), daemon=True).start()
    print("\n[SUKSES] Autentikasi selesai. Ketik pesan untuk dikirim.\n")

def show_help():
    print("Perintah: /connect  /key  /config  /help  exit   (selain itu = pesan)")

def start_alice():
    print("=" * 50)
    print("               ALICE (INISIATOR)               ")
    print("=" * 50)

    cfg = ask_config()
    ka = ask_key("Master Key Alice (16 karakter): ")
    show_help()
    connect(cfg, ka)

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
        elif low == "/connect":
            connect(cfg, ka)
        elif low == "/key":
            ka = ask_key("Master Key Alice baru (16 karakter): ")
            print("[Alice] Key diganti. Ketik /connect untuk distribusi key ulang.")
        elif low == "/config":
            cfg = ask_config()
        elif low == "/help":
            show_help()
        elif session["sock"] is None:
            print("[!] Belum terhubung. Ketik /connect.")
        else:
            try:
                packet = encrypt_cbc(msg.encode('utf-8'), session["ks"])
                session["sock"].sendall(packet.hex().encode('ascii') + b"\n")
                print(f"[Alice] Ciphertext (hex): {packet.hex()}")
            except Exception:
                print("[!] Gagal mengirim pesan.")
                close_session()
    close_session()
    print("[Alice] Selesai.")

if __name__ == "__main__":
    start_alice()
    sys.exit(0)