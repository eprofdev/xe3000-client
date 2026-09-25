# XE3000 CLIENT – ربط راوتر GL-XE3000 بسيرفرك الخارجي

سكربت مستقل (ملف واحد) لراوتر **GL.iNet GL-XE3000 (Puli AX)** بفيرموير GL 4.x / OpenWrt 21.02، ويعمل على راوترات OpenWrt الأخرى التي تستخدم fw3.
يجعل الراوتر **عميلاً** يتصل بسيرفرك الخارجي، ثم يمرر إنترنت كل الأجهزة المتصلة بالراوتر عبر النفق:

| البروتوكول | التفاصيل |
|---|---|
| **VLESS + XTLS-Vision + REALITY** | SNI (`sni`)، المفتاح العام (`pbk`)، `sid`، `spx`، بصمة المتصفح (`fp=chrome`) |
| **REALITY + ML-DSA-65** | توقيع مقاوم للحوسبة الكمية (المعامل `pqv`). يشترط أن يرسل موقع الـ REALITY في السيرفر (dest/target) سلسلة شهادات كبيرة (أكثر من 3.5 كيلوبايت تقريباً)، وإلا يفشل الاتصال |
| **VLESS Encryption** | `mlkem768x25519plus` (ML-KEM-768، مقاوم للحوسبة الكمية) مع Vision |
| XHTTP / gRPC / WS / HTTPUpgrade / TLS | أي رابط `vless://` حديث |
| **SSH** | مباشر، **SSH عبر TLS مع SNI** (Bug host)، SSH عبر WebSocket (Payload)، SSH عبر WebSocket + TLS مع SNI. المصادقة بكلمة مرور أو بمفتاح ed25519 |

المحرك هو **Xray-core الرسمي**: يُثبَّت آخر إصدار من صفحة إصدارات XTLS/Xray-core، ويُرفض الملف إن لم تطابق بصمة SHA-256 ملف `.dgst` الرسمي. أما SSH فيعمل عبر OpenSSH.
الاختبار جرى مع Xray **v26.9.9**، وهو آخر إصدار حتى 2026-09-25.

## المميزات
- **لوحة ويب** كاملة بالعربية وتعمل على الجوال: `http://192.168.8.1:8899`
  - إضافة الخوادم وتعديلها واختبارها واختيار النشط منها
  - التشغيل والإيقاف، وعرض IP الخروج والدولة ومحطة Cloudflare وزمن الاستجابة
  - عدادات الرفع والتنزيل، وكل الإعدادات، والسجلات، وتحديث Xray، ونسخة احتياطية، وتغيير كلمة المرور
- **كل أجهزة الشبكة عبر النفق** تلقائياً، بدون أي إعداد على الأجهزة. يتوفر أيضاً وكيل SOCKS5 على المنفذ `10808` ووكيل HTTP على `10809`.
- **DNS عبر النفق** حتى لا يتسرب DNS. يُحظر **QUIC** (UDP 443) و**IPv6** للأجهزة حتى لا يخرج شيء خارج النفق.
- **مفتاح القطع (Kill switch):** إذا انقطع النفق لا تخرج الأجهزة إلى الإنترنت العادي، ويمكن إطفاؤه.
- **عدة خوادم مع تبديل تلقائي (Failover):** مراقب يعمل كل دقيقتين، وإذا توقف الخادم ينتقل إلى أول خادم آخر يعمل.
- **استثناءات:** أجهزة معينة خارج النفق (`xec bypass add 192.168.8.50`)، ووجهات مباشرة مثل `domain:gov.sa` أو `1.2.3.0/24`.
- **استيراد عدة روابط دفعة واحدة**، والاسم يؤخذ من `#الملاحظة` في الرابط.
- **ثبات:** تبقى القواعد بعد إعادة تشغيل الجدار الناري ضمن fw3، ويعمل النفق تلقائياً بعد إعادة تشغيل الراوتر، وتبقى الإعدادات بعد ترقية الفيرموير.
- **الأمان:**
  - لا تظهر كلمات المرور في قائمة العمليات ولا في السجلات، والملفات بصلاحية 600.
  - تُفحص كل المدخلات قبل استخدامها.
  - لوحة الويب تعمل على الشبكة المحلية فقط، مع حماية CSRF، وقفل لمدة 5 دقائق بعد 5 محاولات خاطئة.

## التثبيت
ادخل على الراوتر: `ssh root@192.168.8.1` (بنفس كلمة مرور لوحة الراوتر)، ثم نفّذ:

```sh
wget -O /tmp/xec.sh https://raw.githubusercontent.com/eprofdev/xe3000-client/main/xe3000-client.sh && sh /tmp/xec.sh install
```

المستودع [`eprofdev/xe3000-client`](https://github.com/eprofdev/xe3000-client) عام، فلا يحتاج الرابط أي رمز وصول.
يثبّت السكربت الحزم التالية من مستودع OpenWrt: `curl` و`ca-bundle` و`unzip` و`uhttpd` و`openssh-client` و`openssh-keygen` و`sshpass` و`openssl-util`، ثم يثبّت Xray بعد فحص بصمته.
في آخر التثبيت يُطبع **رابط لوحة الويب وكلمة مرورها مرة واحدة فقط**. بعدها اكتب **`menu1`** لفتح القائمة.

خيارات مفيدة:
- `--link 'vless://...'`: إضافة الخادم وتشغيل النفق مباشرة.
- `--web-password 'كلمة'`: تحديد كلمة مرور اللوحة.
- `--no-web`: بدون لوحة الويب.
- `--no-ssh`: بدون حزم SSH.
- `--xray-version v26.9.9`: تثبيت إصدار محدد من Xray.

## الاستخدام (سطر الأوامر)
```sh
menu1                                 # القائمة التفاعلية (أو: xec menu)
xec add myvps 'vless://UUID@1.2.3.4:443?security=reality&sni=www.microsoft.com&pbk=KEY&sid=ab12&flow=xtls-rprx-vision&fp=chrome'
xec add 'ssh://user:pass@1.2.3.4:443?transport=tls&sni=bug.host.com#SSH-TLS'
xec add-ssh ws1 --host 1.2.3.4 --port 80 --user u --pass-stdin --transport ws --ws-host bug.host.com
xec add-ssh k1 --host 1.2.3.4 --user root --key && xec ssh-key   # أضف المفتاح المطبوع إلى authorized_keys في السيرفر
xec start | stop | status | test | test myvps | ping
xec use myvps | list | del NAME
xec set KILLSWITCH 0 | xec set FAILOVER 1 | xec route off | xec bypass add 192.168.8.50
xec web password | xec update-xray | xec logs | xec export > backup.txt | xec restore backup.txt
xec uninstall [--purge]
```

**Payload** لـ WebSocket (اختياري): `GET [path] HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]`
(المتغيرات المتاحة: `[host]` و`[path]` و`[sni]` و`[crlf]` و`[lf]` و`[cr]`)

**متوافق مع سيرفر EW PANEL:** الروابط التي تعطيها القائمة `27 REALITY` تعمل مباشرة، ومنها رابط `pqv`، وكذلك روابط `vlessenc` وXHTTP REALITY.
حسابات SSH تعمل عبر `tls` على المنفذ 443 مع SNI، أو عبر `ws` / `wss`.

## ملاحظات
- **UDP:** يمر DNS عبر النفق دائماً (يُحوَّل إلى DNS عبر TCP). أما UDP الآخر، مثل الألعاب والمكالمات، فيخرج مباشرة، لأن SSH لا يدعم نقل UDP. كما أن QUIC محظور حتى تستخدم المتصفحات TCP عبر النفق.
- **أوقف "VPN Client" في لوحة GL.iNet** إن كان مفعلاً، حتى لا يتعارض مع هذا السكربت.
- مع **تحقق SNI في SSH-TLS:** السكربت لا يتحقق من شهادة الـ TLS، لأن SNI في الغالب اسم مختلف (Bug host). الحماية تأتي من مفتاح SSH للسيرفر، الذي يُحفظ في أول اتصال ويُرفض الاتصال إن تغير. لإعادة ضبطه: `xec forget NAME`.
- الملفات:
  - `/usr/bin/xec`: السكربت، و`/usr/bin/menu1`: أمر القائمة
  - `/etc/xe-client/`: الإعدادات والخوادم
  - `/opt/xe-client/`: Xray ولوحة الويب
  - `/tmp/xe-client/`: السجلات

## الاختبار
`tests/run.sh` يشغّل **OpenWrt 21.02.7 الحقيقي** (نفس جيل فيرموير XE3000) مع procd في حاوية. التثبيت فيه حقيقي عبر opkg، ثم يبني شبكة كاملة: جهاز LAN وسيرفر Xray وسيرفر OpenSSH وواجهة TLS تسجّل الـ SNI الذي يصلها.
يختبر:
- REALITY + Vision، ورفض SNI خاطئ، و ML-DSA-65 (مع رفض مفتاح `pqv` خاطئ)، و VLESS Encryption ML-KEM-768، و XHTTP REALITY.
- SSH بالأوضاع مباشر و TLS+SNI و WS و WS+TLS و المفتاح، مع التأكد أن السيرفر استلم SNI و Host الصحيحين.
- مرور الإنترنت والـ DNS لجهاز LAN عبر النفق، و مفتاح القطع (بدون تسرب)، و التبديل التلقائي.
- واجهة API للوحة الويب (الجلسة و CSRF والقفل)، وإعادة التشغيل، والإزالة.

```sh
XEC_TEST_XRAY=/path/to/xray-linux-amd64 bash tests/run.sh
```

---

# English summary
Standalone OpenWrt / GL-XE3000 client. It routes the whole LAN, DNS included, through your server using either:
- **VLESS + XTLS-Vision + REALITY** with SNI, the post-quantum ML-DSA-65 signature (`pqv`), post-quantum VLESS Encryption (ML-KEM-768), and XHTTP/gRPC/WS; or
- **SSH**: direct, over TLS with SNI, over WebSocket, or over WebSocket + TLS.

It also includes a LAN web panel on port 8899, profiles with automatic failover, a kill switch, QUIC/IPv6 leak blocking, per-device bypass, traffic stats, backups and SHA-256-verified official Xray updates.
Install with `wget -O /tmp/xec.sh https://raw.githubusercontent.com/eprofdev/xe3000-client/main/xe3000-client.sh && sh /tmp/xec.sh install`, then type `menu1` (menu) or `xec help`. `tests/run.sh` tests all of it on a real OpenWrt 21.02 container.
