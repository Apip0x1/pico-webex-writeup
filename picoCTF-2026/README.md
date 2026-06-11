# picoCTF 2026 Writeups

Repository ini berisi dokumentasi penyelesaian challenge picoCTF 2026. Fokus utama repo ini adalah writeup yang rapi, mudah diikuti, dan dilengkapi screenshot pendukung untuk setiap tahapan eksploitasi.

## Daftar Writeup

| Challenge | Kategori | Difficulty | Poin | Writeup |
|---|---|---:|---:|---|
| No FA / Hashgate | Web Exploitation | Medium | 200 | [Hashgate/Hashgate.md](Hashgate/Hashgate.md) |
| No FA | Web Exploitation | Medium | 200 | [No-FA/No-FA.md](No-FA/No-FA.md) |
| Old Sessions | Web Exploitation | Easy | 100 | [Old-Sessions/Old-Sessions.md](Old-Sessions/Old-Sessions.md) |

## Struktur Repository

```text
.
├── Hashgate/
│   ├── Hashgate.md
│   ├── exploit.py
│   └── images/
├── No-FA/
│   ├── No-FA.md
│   ├── attachment/
│   │   ├── app.py
│   │   └── users.db
│   └── images/
└── Old-Sessions/
    ├── Old-Sessions.md
    └── images/
```

## Ringkasan Challenge

### No FA / Hashgate

Challenge web exploitation yang membahas IDOR ketika identifier profil user hanya disamarkan menggunakan hash MD5 dari ID numerik. Writeup ini mencakup:

- Penemuan credential guest dari komentar HTML.
- Analisis endpoint profil berbasis hash MD5.
- Verifikasi bahwa hash guest merupakan MD5 dari ID `3000`.
- Brute force rentang ID employee menggunakan script Python.
- Akses profil admin untuk mendapatkan flag.

Writeup lengkap: [Hashgate/Hashgate.md](Hashgate/Hashgate.md)

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

## Tools yang Digunakan

Beberapa tools dan teknik yang digunakan dalam writeup:

- Browser DevTools untuk inspeksi cookie dan session.
- `sqlite3` untuk membaca database SQLite.
- Hash analyzer untuk identifikasi tipe hash.
- MD5 lookup/decrypt untuk validasi hash ID.
- Python script untuk brute force identifier berbasis hash.
- Wordlist-based cracking untuk password hash.
- Analisis source code Flask.
- Manipulasi cookie untuk validasi dampak celah session management.

## Catatan

Seluruh writeup di repository ini dibuat untuk tujuan pembelajaran keamanan aplikasi web dan dokumentasi penyelesaian challenge CTF. Teknik yang dijelaskan hanya boleh digunakan pada lingkungan yang legal, terkontrol, dan memang disediakan untuk latihan seperti CTF.

## Author

Dibuat oleh apip untuk dokumentasi pembelajaran picoCTF 2026.
