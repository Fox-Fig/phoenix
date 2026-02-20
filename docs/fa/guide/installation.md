# نصب و راه‌اندازی (Installation)

این راهنما بصورت کاملاً عملی و قدم‌به‌قدم نحوه نصب سرور و کلاینت ققنوس را توضیح می‌دهد.

## ۱. دانلود و نصب سرور (Server Side)

ابتدا باید نسخه **Server** را بر روی سرور مجازی (VPS) خود دانلود کنید.
لطفاً بر اساس سیستم عامل سرور خود، تب مربوطه را انتخاب و دستورات را اجرا کنید.

::: code-group

```bash [Linux AMD64]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-server-linux-amd64.zip
unzip phoenix-server-linux-amd64.zip
cp example_server.toml server.toml
chmod +x phoenix-server
```

```bash [Linux ARM64]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-server-linux-arm64.zip
unzip phoenix-server-linux-arm64.zip
cp example_server.toml server.toml
chmod +x phoenix-server
```

```powershell [Windows AMD64 (PowerShell)]
Invoke-WebRequest -Uri "https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-server-windows-amd64.zip" -OutFile "phoenix-server.zip"
Expand-Archive -Path "phoenix-server.zip" -DestinationPath "."
Copy-Item "example_server.toml" -Destination "server.toml"
```

:::


::: tip نکته مهم
فایل `server.toml` ایجاد شده است که باید در مرحله بعد (پیکربندی) تنظیم شود. فعلاً برنامه را اجرا نکنید.
:::

### پیکربندی اولیه سرور

::: tip ویرایشگر فایل لینوکس
برای ویرایش `server.toml` در محیط ترمینال لینوکس، می‌توانید از دستور `nano` استفاده کنید:
```bash
nano server.toml
```
برای ذخیره تغییرات، کلید `Ctrl+O` و سپس `Enter` را بزنید. برای خروج، `Ctrl+X` را بزنید.
:::

::: warning توجه مهم
شما **باید** تمام متغیرهای جدول زیر را تنظیم کنید (به‌جز موارد اختیاری مربوط به رمزنگاری).
:::

::: info نکته
در فایل‌های TOML، علامت `#` در ابتدای خط به معنای توضیحات (Comment) است و آن خط اجرا نمی‌شود.
:::

| متغیر (Variable) | نوع | وضعیت | توضیحات |
| :--- | :--- | :--- | :--- |
| `listen_addr` | String | **اجباری** | آدرس و پورتی که سرور روی آن گوش می‌دهد (مثال: `":443"`). |
| `[security]` | Section | **اجباری** | شروع بخش تنظیمات امنیتی و پروتکل‌ها. |
| `enable_socks5` | Boolean | **اجباری** | آیا کلاینت‌ها اجازه دارند از پروتکل SOCKS5 استفاده کنند؟ (`true` یا `false`). |
| `enable_udp` | Boolean | **اجباری** | پشتیبانی از UDP. اکثر سرویس‌های مدرن (یوتیوب، اینستاگرام) به آن نیاز دارند. تنها برای استفاده خاص مثل تلگرام (TLS-only) آن را `false` کنید. |
| `enable_shadowsocks`| Boolean | **اجباری** | فعال‌سازی پشتیبانی از پروتکل Shadowsocks. |
| `enable_ssh` | Boolean | **اجباری** | فعال‌سازی پشتیبانی از تونل SSH. |
| `private_key` | String | اختیاری | مسیر فایل کلید خصوصی سرور (فقط برای حالت‌های امن). |
| `authorized_clients`| Array | اختیاری | لیستی از کلیدهای عمومی کلاینت‌های مجاز (فقط برای mTLS). |

---

## ۲. دانلود و نصب کلاینت (Client Side)

حالا نسخه **Client** را برای سیستم شخصی خود (ویندوز، لینوکس یا مک) دانلود کنید.

::: code-group

```powershell [Windows AMD64 (PowerShell)]
Invoke-WebRequest -Uri "https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-client-windows-amd64.zip" -OutFile "phoenix-client.zip"
Expand-Archive -Path "phoenix-client.zip" -DestinationPath "."
Copy-Item "example_client.toml" -Destination "client.toml"
```

```bash [Linux AMD64]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-client-linux-amd64.zip
unzip phoenix-client-linux-amd64.zip
cp example_client.toml client.toml
chmod +x phoenix-client
```

```bash [macOS Intel]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-client-darwin-amd64.zip
unzip phoenix-client-darwin-amd64.zip
cp example_client.toml client.toml
chmod +x phoenix-client
```

```bash [macOS Silicon]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-client-darwin-arm64.zip
unzip phoenix-client-darwin-arm64.zip
cp example_client.toml client.toml
chmod +x phoenix-client
```

:::

::: warning توجه
فایل `client.toml` را اجرا نکنید! ابتدا باید آن را تنظیم کنید.
:::

### پیکربندی اولیه کلاینت

::: tip نکته
فایل `client.toml` ایجاد شده است. می‌توانید آن را با Notepad یا هر ویرایشگر متنی دیگری باز کنید.
:::

#### ۱. تنظیمات عمومی (Global)

| متغیر (Variable) | نوع | وضعیت | توضیحات |
| :--- | :--- | :--- | :--- |
| `remote_addr` | String | **اجباری** | آدرس سرور ققنوس (IP یا دامنه) و پورت. مثال: `"203.0.113.10:443"`. |
| `server_public_key` | String | اختیاری | کلید عمومی سرور (برای One-way TLS و mTLS). |
| `private_key` | String | اختیاری | مسیر فایل کلید خصوصی کلاینت (فقط برای mTLS). |

#### ۲. تنظیمات ورودی‌ها (`[[inbounds]]`)

این بخش مشخص می‌کند که کلاینت روی چه پورت‌هایی در کامپیوتر شما گوش دهد. شما می‌توانید چندین ورودی داشته باشید.

::: tip غیرفعال‌سازی ورودی
اگر می‌خواهید یک ورودی (مثلاً Socks5 یا SSH) را غیرفعال کنید، کافیست در فایل کانفیگ، علامت `#` را در ابتدای تمام خطوط مربوط به آن بلوک `[[inbounds]]` قرار دهید تا کامنت شوند.
:::

::: warning نکته مهم در مورد پشتیبانی سرور
دقت کنید تنها در صورتی inbound تعریف شده کار می‌کند که سرور از آن پشتیبانی کند. در صورت عدم پشتیبانی سرور، تنها inbound آنلاین می‌شود ولی در صورت اتصال کار نمی‌کند!
:::

| متغیر (Variable) | نوع | وضعیت | توضیحات |
| :--- | :--- | :--- | :--- |
| `protocol` | String | **اجباری** | نوع پروتکل ورودی. مقادیر مجاز: `"socks5"`, `"shadowsocks"`, `"ssh"`. |
| `local_addr` | String | **اجباری** | آدرس و پورتی که روی سیستم شما باز می‌شود. مثال: `"127.0.0.1:1080"`. |
| `enable_udp` | Boolean | اختیاری | فعال‌سازی UDP Associate (فقط برای SOCKS5). برای سرویس‌های مدرن (یوتیوب، اینستاگرام) معمولاً `true` توصیه می‌شود. |
| `auth` | String | اختیاری | اطلاعات احراز هویت (مثلاً پسورد Shadowsocks یا مسیر کلید SSH). |


---

## اجرای برنامه

::: danger هشدار امنیتی
اگر تا این مرحله فقط موارد اجباری را در فایل‌های تنظیمات پر کرده باشید، برنامه کار می‌کند و می‌توانید آن را اجرا کنید؛ **اما از هیچ امنیتی برخوردار نیست (Cleartext)!**

لذا در صورتی که قصد فعال‌سازی حالت‌های امنیتی (mTLS/One-Way TLS) را دارید، **قبل از اجرا** به صفحه **پیکربندی پیشرفته** مراجعه کنید و تنظیمات مربوطه را انجام دهید و سپس برنامه را اجرا نمایید.
:::

برای اجرای برنامه در سرور دستور زیر را بزنید:
```bash
./phoenix-server -config server.toml
```

و در کلاینت برای اجرا:
```bash
./phoenix-client -config client.toml
```

### راهنمای فلگ‌ها (Flags)

برای آشنایی با فلگ‌های مختلف برنامه می‌توانید جدول زیر را مطالعه کنید:

| فلگ (Flag) | برنامه | توضیحات |
| :--- | :--- | :--- |
| `-config` | هر دو | مسیر فایل پیکربندی را مشخص می‌کند. (پیش‌فرض: `server.toml` یا `client.toml`) |
| `-gen-keys` | هر دو | یک جفت کلید خصوصی و عمومی جدید (Ed25519) تولید می‌کند (برای mTLS/One-Way TLS). |
| `-get-ss` | کلاینت | در صورتی که اینباند Shadowsocks داشته باشید، لینک اتصال (`ss://`) را تولید و چاپ می‌کند. |

---

در صفحه بعد، نحوه **پیکربندی (Configuration)** را برای سه حالت امنیتی مختلف یاد خواهید گرفت.
