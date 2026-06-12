# picoCTF 2026 Writeups

Repository ini berisi dokumentasi penyelesaian challenge picoCTF 2026, khususnya kategori Web Exploitation. Setiap writeup ditulis sebagai catatan pembelajaran yang rapi, mudah diikuti, dan menjelaskan alur dari reconnaissance sampai mendapatkan flag.

## Daftar Writeup

| Challenge | Kategori | Difficulty | Poin | Writeup |
|---|---|---:|---:|---|
| Credential Stuffing | Web Exploitation | Medium | 100 | [Credential-Stuffing/Credential-Stuffing.md](Credential-Stuffing/Credential-Stuffing.md) |
| No FA / Hashgate | Web Exploitation | Medium | 100 | [Hashgate/Hashgate.md](Hashgate/Hashgate.md) |
| JAuth | Web Exploitation | Medium | 300 | [JAuth/JAuth.md](JAuth/JAuth.md) |
| No FA | Web Exploitation | Medium | 200 | [No-FA/No-FA.md](No-FA/No-FA.md) |
| Old Sessions | Web Exploitation | Easy | 100 | [Old-Sessions/Old-Sessions.md](Old-Sessions/Old-Sessions.md) |
| Secret Box | Web Exploitation | Medium | - | [Secret-Box/Secret-Box.md](Secret-Box/Secret-Box.md) |

## Struktur Repository

```text
.
|-- Credential-Stuffing/
|   |-- Credential-Stuffing.md
|   |-- creds-dump.txt
|   |-- exploit.py
|   `-- images/
|-- Hashgate/
|   |-- Hashgate.md
|   |-- exploit.py
|   `-- images/
|-- JAuth/
|   |-- JAuth.md
|   `-- README.md
|-- No-FA/
|   |-- No-FA.md
|   |-- attachment/
|   `-- images/
|-- Old-Sessions/
|   |-- Old-Sessions.md
|   `-- images/
`-- Secret-Box/
    |-- Secret-Box.md
    `-- source/
```

## Ringkasan Challenge

### Credential Stuffing

Challenge web exploitation yang membahas serangan credential stuffing terhadap service login berbasis TCP. Writeup ini mencakup:

- Analisis credential dump yang diberikan challenge.
- Identifikasi format pasangan username dan password.
- Otomatisasi percobaan login menggunakan script Python.
- Deteksi credential valid berdasarkan response service.
- Pengambilan flag setelah credential yang benar ditemukan.

Writeup lengkap: [Credential-Stuffing/Credential-Stuffing.md](Credential-Stuffing/Credential-Stuffing.md)

### No FA / Hashgate

Challenge web exploitation yang membahas IDOR ketika identifier profil user hanya disamarkan menggunakan hash MD5 dari ID numerik. Writeup ini mencakup:

- Penemuan credential guest dari komentar HTML.
- Analisis endpoint profil berbasis hash MD5.
- Verifikasi bahwa hash guest merupakan MD5 dari ID `3000`.
- Brute force rentang ID employee menggunakan script Python.
- Akses profil admin untuk mendapatkan flag.

Writeup lengkap: [Hashgate/Hashgate.md](Hashgate/Hashgate.md)

### JAuth

Challenge web exploitation yang membahas kelemahan verifikasi JWT ketika server menerima token unsigned dengan algoritma `none`. Writeup ini mencakup:

- Login menggunakan credential test yang diberikan challenge.
- Inspeksi cookie JWT melalui Browser DevTools.
- Decode header dan payload JWT untuk menemukan claim `role`.
- Penjelasan kenapa mengganti `role` saja gagal pada token `HS256`.
- Eksploitasi JWT `alg: none` dengan signature kosong dan dua separator titik.
- Penggantian cookie untuk menjadi admin dan mendapatkan flag.

Writeup lengkap: [JAuth/JAuth.md](JAuth/JAuth.md)

### No FA

Challenge web exploitation yang membahas kelemahan autentikasi ketika data sensitif tersimpan di client-side session cookie. Writeup ini mencakup:

- Analisis source code aplikasi Flask.
- Pemeriksaan database SQLite yang bocor.
- Identifikasi hash password admin menggunakan SHA-256 tanpa salt.
- Cracking hash password admin.
- Pembacaan OTP 2FA dari Flask session cookie.
- Login sebagai admin untuk mendapatkan flag.

Writeup lengkap: [No-FA/No-FA.md](No-FA/No-FA.md)

### Old Sessions

Challenge web exploitation yang membahas broken session management. Writeup ini mencakup:

- Registrasi dan login sebagai user biasa.
- Analisis hint dari dashboard aplikasi.
- Penemuan endpoint `/sessions` yang membocorkan session aktif.
- Identifikasi session token milik admin.
- Penggantian cookie session melalui browser DevTools.
- Session hijacking untuk mengakses halaman admin dan mendapatkan flag.

Writeup lengkap: [Old-Sessions/Old-Sessions.md](Old-Sessions/Old-Sessions.md)

### Secret Box

Challenge web exploitation yang membahas SQL injection pada aplikasi penyimpanan secret berbasis Node.js, Express, dan PostgreSQL. Writeup ini mencakup:

- Analisis source code aplikasi dan struktur database.
- Identifikasi query raw yang menyisipkan input user secara langsung.
- Eksploitasi SQL injection pada fitur create secret.
- Pengambilan secret milik admin dari tabel database.
- Pembahasan mitigasi menggunakan parameterized query.

Writeup lengkap: [Secret-Box/Secret-Box.md](Secret-Box/Secret-Box.md)

## Tools yang Digunakan

Beberapa tools dan teknik yang digunakan dalam writeup:

- Browser DevTools untuk inspeksi cookie dan session.
- JWT decoder untuk analisis token dan eksploitasi `alg: none`.
- `sqlite3` untuk membaca database SQLite.
- Hash analyzer untuk identifikasi tipe hash.
- MD5 lookup/decrypt untuk validasi hash ID.
- Python script untuk brute force identifier berbasis hash dan otomasi login.
- Wordlist-based cracking untuk password hash.
- Analisis source code Flask, Node.js, Express, dan EJS.
- Manipulasi cookie untuk validasi dampak celah session management.
- Analisis query SQL dan payload SQL injection.

## Catatan

Seluruh writeup di repository ini dibuat untuk tujuan pembelajaran keamanan aplikasi web dan dokumentasi penyelesaian challenge CTF. Teknik yang dijelaskan hanya boleh digunakan pada lingkungan legal, terkontrol, dan memang disediakan untuk latihan seperti CTF.

## Author

Dibuat oleh apip untuk dokumentasi pembelajaran picoCTF 2026.

