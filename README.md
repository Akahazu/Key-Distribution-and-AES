# Key Distribution Scenario: KDC, Alice, dan Bob (AES-128)

Implementasi skenario distribusi kunci simetris dengan *Key Distribution Center* (KDC). Alice (initiator) dan Bob (responder) mendapatkan session key dari KDC, saling mengautentikasi, lalu berkomunikasi dua arah dengan AES-128. AES dan KDC ditulis manual tanpa library kriptografi, hanya `socket` dan `threading` bawaan Python.

## Alur Protokol

| Langkah | Arah | Isi |
|---|---|---|
| 1 | Alice → KDC | `ID_A ‖ ID_B ‖ N1` |
| 2 | KDC → Alice | `E(Ka, [Ks ‖ ID_A ‖ ID_B ‖ N1]) ‖ E(Kb, [Ks ‖ ID_A])` |
| 3 | Alice → Bob | `E(Kb, [Ks ‖ ID_A])` |
| 4 | Bob → Alice | `E(Ks, N2)` |
| 5 | Alice → Bob | `E(Ks, f(N2))`, dengan `f(N2) = N2 + 1` |

Langkah 1-2 adalah **distribusi kunci**, langkah 3-5 adalah **autentikasi**. Setelah langkah 5 selesai, Alice dan Bob bertukar pesan terenkripsi AES memakai session key `Ks`.

- `Ka` dan `Kb` adalah master key yang sudah dibagikan sebelumnya antara KDC dengan Alice dan Bob.
- `Ks` adalah session key 16 byte acak yang dibuat KDC setiap permintaan.
- `N1` (nonce Alice) mencegah replay tiket lama dari KDC. `N2` (nonce Bob) dan `f(N2)` membuktikan bahwa Alice benar-benar memegang `Ks`.

## Struktur File

| File | Fungsi |
|---|---|
| `kdc.py` | Server KDC. Menyimpan daftar ID dan master key, membuat `Ks`, dan membentuk dua tiket terenkripsi. |
| `alice.py` | Initiator. Meminta kunci ke KDC, meneruskan tiket ke Bob, memverifikasi, lalu chat. |
| `bob.py` | Responder. Menunggu Alice, mendekripsi tiket, menantang dengan N2, lalu chat. |
| `aes.py` | Implementasi AES-128 manual: key expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey, dan inversnya. Mode CBC dengan padding PKCS7. |
| `util.py` | Fungsi bantu: pembacaan pesan per baris dari socket, penutupan socket yang bersih, dan validasi input (key, port, ID). |

## Format Data

- Key, ID, dan plaintext berformat **ASCII**. Master key harus tepat 16 karakter.
- Ciphertext dikirim dan ditampilkan dalam **hexadecimal**.
- Satu pesan = satu baris teks diakhiri `\n`. Langkah 1 memakai pemisah `|`.

## Cara Menjalankan

Python 3, tanpa dependensi tambahan. Jalankan di tiga perangkat (atau tiga terminal) dengan urutan **KDC → Bob → Alice**.

```bash
python kdc.py     # isi port, lalu daftarkan ID dan master key Alice & Bob
python bob.py     # isi port Bob dan master key Bob
python alice.py   # isi IP/port KDC, IP/port Bob, ID Alice & Bob, master key Alice
```

Master key Alice dan Bob harus **sama** dengan yang didaftarkan di KDC. Pastikan firewall mengizinkan port KDC dan port Bob.

Setelah Alice dijalankan, langkah 1-5 berjalan otomatis dan tiap langkah dicetak di konsol. Setelah muncul `[SUKSES]`, ketik pesan untuk mengirim.

## Perintah Interaktif

| Program | Perintah |
|---|---|
| KDC | `/add <id>`, `/del <id>`, `/list`, `/help`, `/quit` |
| Alice | `/connect` (ulang distribusi key), `/key` (ganti master key), `/config`, `/help`, `exit` |
| Bob | `/key` (ganti master key), `/help`, `exit` |

Contoh mengganti key: ubah dengan `/key` di Alice atau Bob, perbarui juga di KDC dengan `/add <id>`, lalu ketik `/connect` di Alice.

## Catatan Implementasi

- **Mode CBC + PKCS7**: non-deterministik (menggunakan IV acak), sehingga key dan plaintext yang sama akan menghasilkan ciphertext yang berbeda setiap kali dienkripsi. Ini meningkatkan keamanan dengan menyembunyikan pola data.
- **Dua arah**: Alice dan Bob masing-masing memakai thread penerima sehingga dapat mengirim dan menerima kapan saja.
- **Keterbatasan**: Bob melayani satu Alice dalam satu waktu, dan master key dikirim ke KDC secara manual (di luar protokol), sesuai asumsi skenario.

## Observasi dengan Wireshark

Filter yang berguna: `tcp.port == <port KDC> || tcp.port == <port Bob>`. Gunakan *Follow TCP Stream* untuk melihat ciphertext hex pada langkah 1-5 dan pesan chat.
