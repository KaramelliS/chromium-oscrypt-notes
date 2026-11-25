# Chromium'un Şifreli Kasası

## OSCrypt, App-Bound Encryption ve "Her Bilgisayarda Çalışır" Yalanı

> Bu yazı bir format dokümantasyonudur. Byte seviyesinde ne olduğunu, neden öyle olduğunu ve nerede kırıldığını anlatır.

---

## 1. Özet

Chromium tabanlı tarayıcılar (Chrome, Edge, Brave, Opera, Vivaldi) kayıtlı şifreleri ve çerezleri diske **iki katmanlı** bir şemayla yazar. Dış katman işletim sisteminin anahtar kasası (Windows'ta DPAPI, macOS'ta Keychain, Linux'ta keyring). İç katman tarayıcının kendi AES anahtarı. SQLite dosyası aslında açıktır — şifreli olan sadece tek bir kolondur.

2024'te Chrome 127 bu modele üçüncü bir katman ekledi: **App-Bound Encryption (ABE)**. ABE, anahtarı makineye ve yola bağlar; TPM destekli, export edilemeyen bir CNG anahtarı üzerinden sarar. Bunun sonucu tek cümleyle şu: **şifre çözme artık taşınabilir değil.** Aynı makinede aynı kullanıcı olarak çalışırsan açılır. `Local State` dosyasını başka bir makineye kopyalarsan açılmaz.

Bu yazının en önemli iddiası şu: "her bilgisayarda çalışan" bir çıkarım aracı 2026 itibarıyla mümkün değil. Mümkün olan şey, kapsamı dürüstçe ilan edilmiş bir kütüphane. Kalan bölümler bunun nedenini byte byte gösteriyor.

---

## 2. Chromium diske ne yazıyor

Profil dizini (`%LOCALAPPDATA%\Google\Chrome\User Data\Default`, macOS'ta `~/Library/Application Support/Google/Chrome/Default`, Linux'ta `~/.config/google-chrome/Default`) içindeki ilgili dosyalar:

| Dosya | İçerik | Kritik kolon |
|---|---|---|
| `Login Data` | Kayıtlı şifreler | `logins.password_value` |
| `Network/Cookies` | Çerezler | `cookies.encrypted_value` |
| `Web Data` | Autofill, kart bilgileri | `credit_cards` |
| `History` | Gezinme geçmişi | `urls` |
| `Local State` (profil değil, kök dizin) | Anahtar sarmalı | `os_crypt.encrypted_key` |

Chrome 96'dan itibaren çerez veritabanı profil kökünden `Network/` altına taşındı. Eski araçların çoğu hâlâ kökte arıyor ve sessizce boş dönüyor — bu, "çalışmıyor" şikayetlerinin bir numaralı sebebi.

İki pratik tuzak daha:

**WAL modu.** SQLite veritabanları `-wal` ve `-shm` yan dosyalarıyla çalışır. Sadece `Cookies` dosyasını kopyalarsan son oturumun çerezlerini kaybedersin, çünkü henüz ana dosyaya yazılmamışlardır. Doğru yol SQLite backup API'si veya VSS snapshot.

**Kilit.** Tarayıcı açıkken dosya kilitli olabilir. Windows'ta `FILE_SHARE_READ` ile açmak genelde yeterli, ama tutarlı bir kopya için yine snapshot tercih edilir.

---

## 3. İki katmanlı şifreleme

```
┌──────────────────────────────────────────┐
│  SQLite dosyası (disk üzerinde açık)     │
│  ┌────────────────────────────────────┐  │
│  │ password_value / encrypted_value   │  │
│  │  = "v10" + AES-256-GCM(veri)       │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
                    ▲
                    │ 32 byte AES anahtarı
                    │
┌──────────────────────────────────────────┐
│  Local State → os_crypt.encrypted_key    │
│  = base64( "DPAPI" + DPAPI(aes_key) )    │
└──────────────────────────────────────────┘
                    ▲
                    │ DPAPI / Keychain / libsecret
                    │
┌──────────────────────────────────────────┐
│  İşletim sistemi anahtar kasası          │
│  (kullanıcı oturumuna bağlı)             │
└──────────────────────────────────────────┘
```

Tasarımın mantığı basit: SQLite dosyasını okuyabilen herkes veriyi görür, ama anahtar olmadan sadece şifreli metin görür. Anahtar da kullanıcı oturumuna bağlıdır. Yani tehdit modeli "dosyayı kopyalayan biri" — o kişi anahtarı da kopyalayamaz, çünkü anahtar dosyada değil, OS kasasında.

Bu model 2024'e kadar tutarlı çalıştı. ABE'nin kırdığı varsayım tam olarak bu: *anahtar, kullanıcı oturumuyla taşınabilir.*

---

## 4. Blob formatları

### 4.1 Windows — `v10` / `v11` (AES-256-GCM)

```
offset  0 .. 2    "v10"  veya  "v11"      (3 byte, ASCII)
offset  3 .. 14   nonce                   (12 byte)
offset 15 .. n-16 ciphertext              (n-31 byte)
offset n-16 .. n  authentication tag      (16 byte)
```

Toplam ek yük 31 byte. `v11` aynı yapı, sadece uygulama düzeyinde ayrım için kullanılır (Chromium kodu ikisini aynı şekilde işler). AES anahtarı `Local State`'ten gelir.

### 4.2 macOS / Linux — `v10` (AES-128-CBC)

```
offset  0 .. 2    "v10"                       (3 byte)
offset  3 .. 18   IV = 0x20 × 16              (16 boşluk karakteri)
offset 19 .. n    AES-128-CBC ciphertext      (PKCS#7 padded)
```

GCM yok, tag yok, nonce yok. IV sabit ve kelimenin tam anlamıyla on altı boşluk. Bu bir kriptografik zaafiyet değil (aynı anahtar altında IV tekrarı CBC'de bilgi sızdırır, ama burada anahtar kullanıcıya özel ve tek yazıcı var), yine de formatın ne kadar "elle tutulur" olduğunu gösteriyor.

Anahtar türetmesi:

```python
# macOS
key = PBKDF2_HMAC_SHA1(password_from_keychain, b"saltysalt", 1003, 16)

# Linux, basic store
key = PBKDF2_HMAC_SHA1(b"peanuts", b"saltysalt", 1, 16)
```

macOS'ta `password_from_keychain`, Keychain'deki `"Chrome Safe Storage"` girdisidir. 1003 tur sayısı 2013'ten beri değişmedi.

### 4.3 Host bağlama — sessiz format değişikliği

Chrome 130 civarında çerez veritabanının `meta` sürümü 24'e çıktı ve decrypt edilen düz metnin **başına** `SHA256(host_key)` eklendi:

```
plaintext = SHA256(host_key)[0..32] || gerçek_çerez_değeri
```

Bunu bilmeyen bir araç, çerezin başına 32 byte çöp yazar ve site çerezi reddeder. Aynı değişiklik bir yan etki doğurdu: hash çerez değerinin kendisine değil, ait olduğu host'a bağlı olduğu için, aynı host'a ait iki çerez birbiriyle değiştirilebilir hale geldi. Bu, çerez hırsızlığında "oturum sabitleme" için kullanışlı bir gevşeklik.

### 4.4 Zaman damgaları

Chromium `base::Time` kullanır: **1601-01-01 UTC'den itibaren mikrosaniye.** Unix epoch'a çevirmek için:

```python
unix_seconds = chromium_ts / 1_000_000 - 11644473600
```

`expires_utc = 0` ise çerez oturum çerezidir.

---

## 5. App-Bound Encryption — neden çıktı

2024'te bilinen bir bilgi hırsızı ailesi (infostealer) Windows'ta yaygınlaştı. Bu ailelerin ortak noktası şuydu: **kullanıcı olarak çalışıyorlardı.** Kullanıcı olarak çalıştıkları için DPAPI anahtarını sorunsuz açıyorlardı. Yani Chromium'un tüm katmanlı şifrelemesi, aynı kullanıcı bağlamında çalışan bir zararlıya karşı **hiçbir şey** ifade etmiyordu. Katmanlar dosya hırsızına karşı koruyordu, süreç hırsızına karşı değil.

Google'ın cevabı ABE oldu: anahtarı kullanıcıdan ayır, makineye bağla, sadece imzalı Chrome binary'sinin çağırabileceği bir servis üzerinden aç.

### 5.1 Mekanizma

```
Chrome  ──COM──▶  elevation_service.exe  ──▶  CNG machine key (TPM)
                         │
                         └─ çağıranın kim olduğunu doğrular:
                            • process yolu
                            • imza
                            • komut satırı
```

Kritik nokta: doğrulama **çağıran sürecin kimliğine** bakıyor. Bu yüzden topluluk çözümlerinin çoğu "Chrome'un içine gir" mantığında:

- Reflective process hollowing (`xaitax/Chrome-App-Bound-Encryption-Decryption`)
- Transacted hollowing + named pipe (`internetangel/ZeroCrumb`)
- COM sunucusuna enjeksiyon (`teng-lin/rookie-cookies`)

Hepsi aynı sorunu çözüyor: kod, Chrome sürecinin içinden çalışsın ki doğrulamayı geçsin.

### 5.2 COM arayüzü

```
Chrome : {708860E0-F641-4611-8895-7D867DD3675B}   (IElevator2)
Edge   : {1FCBE96C-1697-43AF-9140-29DB18F2E706}
```

**Bu CLSID'ler sürüme bağlıdır.** Koda gömmek yerine `HKCR\CLSID` altından oku. Sabit yazarsan bir sonraki major sürümde sessizce bozulur.

### 5.3 v20 anahtar sarmalının içi

`Local State`'teki `os_crypt.app_bound_encrypted_key` çift DPAPI sarmalından geçtikten sonra şu yapı ortaya çıkıyor:

```
[len]            kurulum yolu: "C:\Program Files\Google\Chrome"
0x01             sürüm/flags baytı
[12]             nonce
[32]             ciphertext  → 32 byte AES anahtarı
[16]             GCM tag
```

Yolun kendisinin şifreli yükün içinde olması tesadüf değil — ABE servisi çağıranın yolunu bu değerle karşılaştırıyor. Yani yol, kimlik doğrulamanın bir parçası.

32 byte ciphertext, decrypt edildiğinde tam olarak 32 byte çıkan AES-256 anahtarıdır. IV ve tag yapının geri kalanı.

### 5.4 Sürüm tredmili

ABE'nin iki yıl içindeki evrimi:

| Sürüm | Değişiklik |
|---|---|
| 127 | Çerezlerde `v20` devreye girdi. Anahtar artık kullanıcı DPAPI'siyle açılmıyor. |
| 133 | `elevation_service.exe` içinde ChaCha20-Poly1305 |
| 137 | AES-256-GCM'e dönüş, anahtar `\x03` baytından sonra |
| 157 | Yeni CNG anahtar adı `Google Chromekey2`, yeni XOR anahtarı |

Yaklaşık dört haftada bir major sürüm çıktığını düşünürsen, bu tablo net bir şey söylüyor: **offset tabanlı parser yazarsan her ay bozulur.** Bozulma sessiz olur — exception değil, yanlış çöp veri döner.

Doğru yaklaşım offset'e değil fonksiyona bağlanmak:

```javascript
// Frida — sürümden bağımsız
Interceptor.attach(Module.findExportByName("bcrypt.dll", "BCryptDecrypt"), {
  onEnter(args) {
    // args[0] = hKey, args[2] = pbInput (şifreli), args[3] = cbInput
    this.input = args[2];
    this.len = args[3].toInt32();
  },
  onLeave(retval) {
    if (retval.toInt32() === 0 && this.len === 32) {
      send({ kind: "aes_key", bytes: hexdump(this.input, { length: 32 }) });
    }
  }
});
```

Anahtar boyutu (32 byte) ve çağrı biçimi daha kararlı bir çapa noktası. İç yapı değişse de `BCryptDecrypt`'in imzası değişmiyor.

---

## 6. Kapsama matrisi

Buradaki her satır "çalışır mı" sorusuna dürüst cevap:

| Durum | Windows | macOS | Linux | Güven |
|---|---|---|---|---|
| Aynı makine, aynı kullanıcı oturumu, Chrome < 127 | ✅ | ✅ | ✅ | Yüksek |
| Aynı makine, aynı kullanıcı, Chrome 127+ (ABE) | ⚠️ | ✅ | ✅ | Şartlı |
| Aynı makine, SYSTEM/root, kullanıcı oturumu yok | ⚠️ impersonation şart | ⚠️ keychain kilitli | ⚠️ D-Bus yok | Kırılgan |
| Farklı makine, Chrome < 127 | ✅ | ✅ | ✅ | Yüksek |
| Farklı makine, Chrome 127+ | ❌ | ✅ | ✅ | İmkânsız |
| Firefox / Safari | ❌ | ❌ | ❌ | Kapsam dışı |

macOS satırlarındaki ✅'ler bir eksiklik değil, bir gözlem: ABE macOS'a yayılmadı. Keychain `"Chrome Safe Storage"` hâlâ PBKDF2 ve TPM yok. Bugün en yüksek getirili platform macOS.

---

## 7. Nerede ölüyor

### 7.1 Cross-host senaryosunun ölümü

`moonD4rk/HackBrowserData` gibi araçların `dumpkeys` / `archive` / `restore` modeli şuydu: A makinesinde anahtarı çıkar, B makinesinde veritabanını çöz. Bu, v10/v11 dünyasında tamamen geçerliydi, çünkü anahtar sadece bir AES anahtarıydı ve dosya olarak taşınabiliyordu.

ABE bu modeli öldürdü. v20 anahtarı TPM'e bağlı, export edilemeyen bir CNG anahtarıyla sarılıyor. `Local State`'i kopyalayıp başka makinede açmayı denersen TPM farklı olur ve decrypt başarısız olur — üstelik hangi aşamada başarısız olduğu da net değil, çünkü hata yüzeyi dar.

Yani "her bilgisayardan çek" fikrinin teknik ömrü 2024'te bitti. Kalan şey "her bilgisayarda, o bilgisayarın kendi bağlamında çalış" — bu farklı bir iddia.

### 7.2 Çalışmak ≠ hayatta kalmak

Üç ayrı şey var ve karıştırılıyor:

1. **Doğru sonuç üretmek.** Format bilgisi + anahtar = çalışır.
2. **Tespit edilmemek.** Reflective hollowing, COM injection, named pipe — hepsi AV/EDR için imza üretir. `rookie-cookies` bunu README'sinde açıkça yazıyor.
3. **Temiz kalmak.** Aynı kullanıcı oturumunda COM üzerinden konuşmak teknik olarak en temiz yol, ama en dar kapsamlı olan.

Bir kütüphane bu üçünü tek bir "başarılı" bayrağına indirgersen yalan söylemiş olur.

### 7.3 Linux sandığından daha kırılgan

Basic store anahtarı (`peanuts`) her zaman çalışır. Ama modern dağıtımların çoğu gnome-keyring veya kwallet kullanıyor, ve bunlar oturum D-Bus'una bağlı. `sudo` ile çalıştırırsan root'un keyring'i boştur — anahtar yoktur, decrypt başarısız olur. Bu, "Linux'ta kolay" varsayımının en sık çöktüğü yer.

### 7.4 macOS'ta keychain kilidi

FileVault açık olması sorun değil — disk zaten mount edilmiş. Sorun login keychain'in kilitli olması. Kilitliyse `"Chrome Safe Storage"` okunamaz ve şifre sorulur. Aynı kullanıcı oturumundaysan genelde açıktır.

### 7.5 Sürüm sürüklenmesi

Yukarıdaki tabloya bak: 127, 133, 137, 157. Dört değişiklik, iki yıl. Bir kütüphane bunu sürdürebilir mi? Sürdürür, ama ancak CI'da gerçek Chrome binary'lerine karşı test koşuyorsa. Aksi halde her sürümde issue yağar.

---

## 8. Tasarım sonucu: yetenek katmanları

"Her yerde çalışır" diye satmak yerine, kütüphane neyle karşılaştığını **ilan etsin**:

```rust
pub enum Capability {
    /// v10/v11 — her yerde, her zaman.
    Plain,
    /// v20, aynı kullanıcı oturumu, COM yolu — temiz.
    AbeSameUser,
    /// v20, süreç içi hook — çalışır ama AV riski taşır.
    AbeInjected,
    /// Yalnızca Plain modunda mümkün.
    CrossHost,
}

pub struct Decrypted {
    pub value: Vec<u8>,
    pub capability: Capability,
}
```

`Result<Vec<u8>>` yerine `(veri, yetenek)` döndürmek, çağıranın "elimde ne var" sorusunu cevaplamasını sağlar. Bir kütüphane kullanıcısına "başarılı" demek ile "başarılı ama enjeksiyonla" demek arasındaki fark, üretimde bir olayın olup olmaması farkıdır.

Ve README'de dürüst tablo. Abartılı vaat ilk issue'da çöker; ölçülü vaat projeyi güvenilir yapar.

---

## 9. Kendin doğrulamak için

```bash
# Windows: Local State'teki anahtarın sarmalını gör (değeri yazdırmadan)
python -c "
import base64, json, pathlib
ls = json.loads(pathlib.Path(r'%LOCALAPPDATA%/Google/Chrome/User Data/Local State').read_text())
raw = base64.b64decode(ls['os_crypt']['encrypted_key'])
print('önek:', raw[:5], 'uzunluk:', len(raw))
print('abe var mı:', 'app_bound_encrypted_key' in ls['os_crypt'])
"

# Çerez veritabanının meta sürümü
sqlite3 "Network/Cookies" "SELECT value FROM meta WHERE key='version';"

# Windows'ta bir çerezin önekini gör
sqlite3 "Network/Cookies" "SELECT substr(encrypted_value,1,3), length(encrypted_value) FROM cookies LIMIT 5;"
```

`meta` sürümü 24 ve üzerindeyse, düz metnin başında `SHA256(host_key)` var demektir. Bu tek satır, çoğu "neden çerez bozuk geliyor" sorusunu cevaplar.

---

## 10. Kaynaklar

| Proje | Ne için bakılır |
|---|---|
| `moonD4rk/HackBrowserData` | Go, cross-platform, `dumpkeys` / `archive` / `restore` — v10 döneminin cross-host modeli |
| `xaitax/Chrome-App-Bound-Encryption-Decryption` | Reflective process hollowing ile ABE bypass |
| `runassu/chrome_v20_decryption` | v20 yapısı ve sürüm değişimlerinin en iyi dokümantasyonu |
| `internetangel/ZeroCrumb` | Yetkisiz ABE, transacted hollowing + named pipe |
| `norahc-x/Margaret-Stealer` | Diske hiç dokunmayan in-memory `CookieMonster` keşfi |
| `teng-lin/rookie-cookies` | Rust core + Python/Node binding, MIT — kütüphane mimarisi için şablon |
| `mendacus/chrome-abe-decryption-bof` | Cobalt Strike BOF implementasyonu |
| `AlessandroZ/LaZagne` | Klasik çok-platform kimlik çıkarma |
| `djhohnstein/SharpChrome` | .NET tarafı |

---

## 11. Doğrulama notu

Bu yazıdaki sürüm numaraları ve yapı detayları 2026 sonu itibarıyla topluluk gözlemlerine dayanıyor. ABE iç yapısı her birkaç sürümde değişiyor ve değişimler geriye dönük duyurulmuyor. Kendi ortamında doğrulamadan üretim koduna taşıma.

Özellikle şu üç şeyi kendi makinende kontrol et:

1. `os_crypt` altında `app_bound_encrypted_key` var mı
2. Çerez `meta` sürümü kaç
3. `encrypted_value` öneki `v10` mu, `v20` mi

Bu üç değer, hangi kod yolunun çalışacağını tamamen belirler.

---

*Lisans: CC BY 4.0 — kaynak göstermek koşuluyla serbestçe kullan, çevir, dağıt.*
