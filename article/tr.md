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

### 5.2 COM arayüzü ve gerçek kayıt zinciri

Servis tabanlı COM'da `LocalServer32` alt anahtarı yoktur. Zincir şu:

```
CLSID {…}  →  AppID {…}  →  LocalService  →  elevation_service.exe (LocalSystem)
```

Bu makinede ölçülen tablo:

| Marka | CLSID = AppID | LocalService | Çalıştığı hesap |
|---|---|---|---|
| Chrome | `{708860E0-F641-4611-8895-7D867DD3675B}` | `GoogleChromeElevationService` | **LocalSystem** |
| Brave | `{576B31AF-6369-4B6B-8560-E4B203A97A8B}` | `BraveElevationService` | **LocalSystem** |
| Edge | `{CD489BAC-BF1F-4F4B-9DB9-39B823919EAC}` | `MicrosoftCopilotElevationService` | **LocalSystem** |

Chrome'un 2024'te yayınlanan GUID'i hâlâ geçerli. Edge'inki öldü: Edge 2026'da "Copilot" uygulamasına taşındı ve yeni GUID kullanıyor. Yani "CLSID sürüme bağlı" uyarısı Edge için doğru, Chrome için değil.

Buradaki en önemli satır sonuncusu: **üç servis de `LocalSystem` olarak çalışıyor.** Bir sonraki bölümdeki master key bulmacasının cevabı tam olarak bu.

`LocalServer32` arayan bir prob "CLSID kayıtlı değil" sonucuna varır. Bu, bu yazının ilk sürümünde yaptığım hataydı.

### 5.3 v20 anahtar sarmalının içi

Bu bölüm tahmin değil, ölçüm. 2026 sonunda Chrome 158, Edge 158 ve Brave 158.1 üzerinde `os_crypt.app_bound_encrypted_key` alanının gerçek byte yapısı şu:

```
4150504201000000...     "APPB" + 0x00000001
d08c9ddf0115d1118c7a00c04fc297eb...   ← DPAPI sağlayıcı GUID'i
```

`DF9D8CD0-1501-11D1-8C7A-00C04FC297EB` Windows'un standart DPAPI sağlayıcısıdır. Yani sarmal **normal bir DPAPI bloğu**, önünde sadece 4 byte'lık `APPB` işareti var. CNG yok, TPM yok, ChaCha yok — en azından bu makinede.

Bloğun içindeki master key GUID'i ayrıştırdığında tablo şu:

| Tarayıcı | master key | Kullanıcının Protect deposunda mı |
|---|---|---|
| Chrome | `DF9A3E03-…-ACE50E51608E` | **hayır** |
| Edge | `BFB9D720-…-CB821EF2222C` | **hayır** |
| Brave | `BFB9D720-…-CB821EF2222C` | **hayır** |

Karşılaştırma için aynı `Local State`'teki eski `encrypted_key` alanı `3312E042-…` anahtarını kullanıyor ve o **kullanıcının deposunda var**. Fark burada: v10 sarmalı kullanıcı hesabına, v20 sarmalı başka bir hesap bağlamına (yükseltme servisi) mühürlenmiş.

O hesabın deposu da bulundu:

```
C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\
├── df9a3e03-044f-4442-b5f1-ace50e51608e   ← Chrome ABE master key
├── bfb9d720-c655-4be8-9abc-cb821ef2222c   ← Edge/Brave ABE master key
└── Preferred
```

`S-1-5-18` LocalSystem'in SID'i. Dosyalar **okunabiliyor** — listeden görebilirsin. Ama içerikleri `DPAPI_SYSTEM` LSA sırrıyla şifreli, ve o sırrı açmak SYSTEM yetkisi ister. Yani master key kayıp değil, erişilemez.

Bunun sonucu şu: `CryptUnprotectData` orta bütünlükte `NTE_BAD_KEY_STATE` (`0x8009000B`) döner. Bu "anahtar yok" demek değil, "anahtar var, kullanma iznin yok" demek. ABE'nin duvarı kriptografik değil, **ayrıcalık sınırı**.

Sarmal açıldıktan sonra kalan yük şu yapıda:

```
[len]            kurulum yolu: "C:\Program Files\Google\Chrome"
0x01             sürüm/flags baytı
[12]             nonce
[32]             ciphertext  → 32 byte AES anahtarı
[16]             GCM tag
```

Yolun şifreli yükün içinde olması tesadüf değil — servis çağıranın yolunu bu değerle karşılaştırıyor. Yani yol, kimlik doğrulamanın bir parçası.

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

ABE bu modeli öldürdü. Ama sebep sanıldığı gibi TPM değil — TPM'siz bir makinede de çalışmıyor. Gerçek sebep şu: v20 sarmalının DPAPI master key'i kullanıcının Protect deposunda değil, başka bir hesap bağlamında. `Local State`'i kopyalayıp başka makinede açmayı denersen hem master key hem hesap bağlamı eksik olur. Üstelik hata yüzeyi dar, hangi aşamada öldüğünü göremezsin.

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

## 9. Ölçümler — 2026 sonu, gerçek bir makine

Aşağıdaki tablo bir Windows 11 makinesinde, TPM olmadan, orta bütünlük seviyesindeki normal bir kullanıcı oturumunda alındı. Kurulu sürümler: Chrome `158.0.8127.36`, Edge `158.0.4370.33`, Brave `158.1.100.59`, Opera (ABE yok).

| Ölçüm | Sonuç |
|---|---|
| TPM | yok (`Win32_Tpm` sınıfı mevcut değil) |
| Chrome çerezleri | 200 satır, **hepsi `v20`**, meta 24 |
| Edge çerezleri | 197 satır, **hepsi `v10`**, meta 24 |
| Edge çerez decrypt | **197/197 başarılı**, 197/197 host hash öneki doğru |
| Edge şifreleri | 245 satır, 183 `v10` → **183/183 decrypt** |
| Brave şifreleri | 23 satır, **hepsi `v20`** |
| Opera çerezleri | 14 satır, hepsi `v10` |
| Chrome v10 anahtarıyla v20 denemesi | **0/40** — duvar |
| Brave `Network/Cookies` | WinError 32, dosya kilitli (19 süreç çalışıyor) |
| Brave kurulum dizini kullanıcı yazılabilir mi | **evet** |
| Chrome kurulum dizini kullanıcı yazılabilir mi | hayır |
| 2024 CLSID'leri | Chrome ✓ geçerli, Edge ✗ (Copilot'a taşındı) |
| Elevation servisleri hangi hesapta | **LocalSystem**, üçü de |
| ABE master key nerede | `C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\` (okunabilir, `DPAPI_SYSTEM` ile mühürlü) |
| `elevation_service.exe` imzalayanlar | Google LLC / Brave Software, Inc. / Microsoft Corporation |

Bu tablodan çıkan üç sonuç:

**1. ABE dağıtımı düzensiz.** Edge, 158 sürümünde `app_bound_encrypted_key` alanını taşıyor ama çerezlerini ve şifrelerini hâlâ `v10` ile yazıyor. Yani Edge'de ABE var ama devrede değil. Bugün 183 şifre ve 197 çerez, hiçbir bypass olmadan, sadece DPAPI ile açılıyor. Pratikte en yumuşak hedef Chrome değil, Edge.

**2. Kilit, dosyanın kendisinde.** Brave açıkken `Network/Cookies` dosyası paylaşıma kapalı açılıyor (share mode 0). Kopyalamak, `mode=ro` ile açmak, `-wal` okumak — hiçbiri işe yaramıyor. Bu, "profili kopyala, başka yerde aç" fikrinin önündeki gerçek engel. Çözüm ya tarayıcıyı kapatmak ya VSS snapshot almak; ikincisi yönetici ister.

**3. ABE'nin duvarı hesap kapsamı.** Bu makinede TPM yok, CNG anahtarı yok, ChaCha yok. Sadece başka bir hesaba mühürlenmiş bir DPAPI bloğu var. Yani ABE'yi aşmanın iki yolu var: o hesabın bağlamında çalışmak (yükseltme) ya da o hesabın içine kod sokmak (enjeksiyon). Üçüncü bir kriptografik yol yok.

---

## 10. Kendin doğrulamak için

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

## 11. Kaynaklar

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

## 12. Doğrulama notu

Bu yazıdaki sürüm numaraları ve yapı detayları 2026 sonu itibarıyla topluluk gözlemlerine dayanıyor. ABE iç yapısı her birkaç sürümde değişiyor ve değişimler geriye dönük duyurulmuyor. Kendi ortamında doğrulamadan üretim koduna taşıma.

Özellikle şu üç şeyi kendi makinende kontrol et:

1. `os_crypt` altında `app_bound_encrypted_key` var mı
2. Çerez `meta` sürümü kaç
3. `encrypted_value` öneki `v10` mu, `v20` mi

Bu üç değer, hangi kod yolunun çalışacağını tamamen belirler.

---

*Lisans: CC BY 4.0 — kaynak göstermek koşuluyla serbestçe kullan, çevir, dağıt.*
