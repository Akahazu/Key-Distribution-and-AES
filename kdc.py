import socket
import threading
import os
from aes import encrypt_ecb
from util import recv_line, ask_key, ask_int, ask_id, tune, close_sock

HOST = "0.0.0.0"
MASTER_KEYS = {}
lock = threading.Lock()

def handle_client(conn, addr):
    print(f"\n[KDC] Koneksi masuk dari {addr[0]}:{addr[1]}")
    conn.settimeout(10)
    tune(conn)
    try:
        parts = recv_line(conn).split("|")
        if len(parts) != 3:
            conn.sendall(b"ERROR|Format request tidak valid\n")
            print("[KDC] Format request tidak valid.")
            return
        id_a, id_b, n1 = parts
        print(f"[Langkah 1] Request: {id_a} || {id_b} || {n1}")

        with lock:
            ka = MASTER_KEYS.get(id_a)
            kb = MASTER_KEYS.get(id_b)
        if ka is None or kb is None:
            conn.sendall(b"ERROR|ID tidak terdaftar di KDC\n")
            print("[KDC] Ditolak: ID tidak terdaftar.")
            return

        ks = os.urandom(16)
        print(f"[KDC] Session Key (Ks): {ks.hex()}")

        tiket_alice = encrypt_ecb(f"{ks.hex()}|{id_a}|{id_b}|{n1}".encode('utf-8'), ka)
        tiket_bob = encrypt_ecb(f"{ks.hex()}|{id_a}".encode('utf-8'), kb)
        print(f"[Langkah 2] E(Ka, ...) : {tiket_alice.hex()}")
        print(f"[Langkah 2] E(Kb, ...) : {tiket_bob.hex()}")

        conn.sendall((tiket_alice.hex() + "\n" + tiket_bob.hex() + "\n").encode('ascii'))
    except Exception as e:
        print(f"[KDC] Error: {e}")
    finally:
        close_sock(conn)

def accept_loop(server):
    while True:
        try:
            conn, addr = server.accept()
        except OSError:
            return
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

def show_help():
    print("Perintah: /add <id>  /del <id>  /list  /help  /quit")

def start_kdc():
    print("=" * 50)
    print("       KEY DISTRIBUTION CENTER (KDC)       ")
    print("=" * 50)

    port = ask_int("Masukkan Port KDC: ")

    print("Daftarkan ID dan Master Key (ID kosong = selesai)")
    while True:
        uid = input("ID: ").strip()
        if not uid:
            break
        if "|" in uid or not uid.isascii():
            print("[!] ID harus ASCII dan tanpa '|'.")
            continue
        MASTER_KEYS[uid] = ask_key(f"Master Key {uid} (16 karakter): ")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, port))
    server.listen(5)
    threading.Thread(target=accept_loop, args=(server,), daemon=True).start()
    print(f"[KDC] Menunggu koneksi di port {port}...")
    show_help()

    while True:
        try:
            cmd = input("KDC> ").strip().split(maxsplit=1)
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd:
            continue
        name = cmd[0].lower()
        if name == "/add":
            uid = cmd[1].strip() if len(cmd) > 1 else ask_id("ID: ")
            if "|" in uid or not uid.isascii():
                print("[!] ID harus ASCII dan tanpa '|'.")
                continue
            key = ask_key(f"Master Key {uid} (16 karakter): ")
            with lock:
                MASTER_KEYS[uid] = key
            print(f"[KDC] Key untuk {uid} disimpan.")
        elif name == "/del":
            uid = cmd[1].strip() if len(cmd) > 1 else ""
            with lock:
                removed = MASTER_KEYS.pop(uid, None)
            print(f"[KDC] {uid} dihapus." if removed else "[!] ID tidak ditemukan.")
        elif name == "/list":
            with lock:
                for uid, key in MASTER_KEYS.items():
                    print(f"  {uid} : {key.decode('ascii')} ({key.hex()})")
        elif name == "/help":
            show_help()
        elif name in ("/quit", "exit"):
            break
        else:
            print("[!] Perintah tidak dikenal. Ketik /help.")
    server.close()
    print("[KDC] Selesai.")

if __name__ == "__main__":
    start_kdc()