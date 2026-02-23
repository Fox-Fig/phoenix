# تاریخچه تغییرات (Changelog)

در این صفحه خلاصه‌ای از تمام نسخه‌های ققنوس و تغییرات هر نسخه آورده شده است.

---

## v1.0.1dev2 — جعل اثرانگشت TLS و Insecure TLS

- **[جدید]** قابلیت **جعل اثرانگشت مرورگر** (`fingerprint`) با استفاده از کتابخانه `utls` — برای عبور از DPI اپراتورهایی که ترافیک غیرمرورگری را مسدود می‌کنند
- **[جدید]** حالت **Insecure TLS** (`tls_mode = "insecure"`) — برای اتصال مستقیم به سرور با سرتیفیکت خودامضا بدون نیاز به CDN
- **[بهبود]** لاگ‌های امنیتی در startup اکنون وضعیت TLS، توکن و fingerprint را به طور کامل نمایش می‌دهند
- **[بهبود]** پشتیبانی از کلید ECDSA P256 در سرور برای سازگاری با Chrome fingerprint

## v1.0.1dev1 — پشتیبانی واقعی از Shadowsocks

- **[جدید]** پیاده‌سازی کامل Shadowsocks با AEAD (رمزنگاری احراز هویت‌شده)
- **[بهبود]** رمزنگاری‌های پشتیبانی‌شده: `aes-256-gcm`، `aes-128-gcm`، `chacha20-ietf-poly1305`
- **[جدید]** فلگ `-get-ss` برای تولید لینک اتصال `ss://` برای کلاینت‌های موبایل

---

## v1.0.0 — نسخه پایدار اول 🎉

- **[جدید]** پشتیبانی از معماری‌های بیشتر: `armv7`، `arm32`، `mips`، `mipsle`، `mips64`، `mips64le`، `riscv64`
- اکنون بیلد برای **۱۲ پلتفرم** مختلف موجود است:
  - Linux: amd64, arm64, armv7, arm32, mips, mipsle, mips64, mips64le, riscv64
  - macOS: amd64, arm64
  - Windows: amd64

---

## v1.0.0dev21

- بیلد CI برای معماری‌های ARM و MIPS اضافه شد (پیش‌نمایش v1.0.0)

## v1.0.0dev20

- **[رفع باگ]** حذف `PingTimeout` سختگیرانه و پیاده‌سازی `background flusher` هوشمند
- بهبود عملکرد: رفع مشکل buffer bloat و packet amplification

## v1.0.0dev17

- **[داکیومنت]** بازنویسی کامل مستندات با جزئیات mTLS، One-Way TLS و Circuit Breaker

## v1.0.0dev16

- **[رفع باگ]** رفع race condition در release با تفکیک build و release jobs

## v1.0.0dev15

- **[جدید]** پیکربندی multi-platform build workflow (Linux/macOS/Windows)

## v1.0.0dev14

- **[بهبود]** پیاده‌سازی Debounce برای Hard Reset جهت جلوگیری از Reset Storm

## v1.0.0dev13

- **[بهبود]** بازطراحی Client Transport برای پشتیبانی از Hard Reset هنگام خطا

## v1.0.0dev12

- **[جدید]** پیاده‌سازی **Circuit Breaker** برای بازیابی اتصالات Zombie

## v1.0.0dev11

- **[جدید]** فلگ `-gen-keys` برای کلاینت اضافه شد

## v1.0.0dev10

- **[جدید]** پیاده‌سازی **One-Way TLS** (رمزنگاری سمت سرور)

## v1.0.0dev9

- **[داکیومنت]** بروزرسانی فایل‌های کانفیگ نمونه با دستورالعمل کلیدهای mTLS

## v1.0.0dev8

- **[بهبود]** بروزرسانی Integration Tests برای معماری امنیتی جدید و speed test

## v1.0.0dev7

- **[جدید]** فلگ `-get-ss` و تنظیم cipher پیش‌فرض Shadowsocks روی `chacha20-ietf-poly1305`

## v1.0.0dev6

- **[بهبود]** بهینه‌سازی عملکرد UDP: افزایش buffer، تنظیم H2 transport، غیرفعال کردن timeout

## v1.0.0dev5

- **[رفع باگ]** رفع مشکل قطع اتصال UDP هنگام ارسال داده keep-alive

## v1.0.0dev4

- **[رفع باگ]** رفع مشکل routing و flushing در UDP Associate، افزودن integration test

## v1.0.0dev3

- **[جدید]** پشتیبانی کامل از **SOCKS5 UDP Associate** (Command 0x03)

## v1.0.0dev2

- **[رفع باگ]** رفع nil pointer dereference در مدیریت Dial کلاینت

## v1.0.0dev1

- **[جدید]** پیاده‌سازی اولیه کامل سیستم Phoenix (Server/Client/Transport/Adapters)

---

::: tip مشارکت در پروژه
برای مشاهده تمام تغییرات با جزئیات فنی به [صفحه Releases در گیت‌هاب](https://github.com/Fox-Fig/phoenix/releases) مراجعه کنید.
:::
