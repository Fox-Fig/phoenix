# شروع کار با ققنوس (Phoenix)

این راهنما به شما کمک می‌کند تا سرور ققنوس را روی VPS خود راه‌اندازی کنید و با کلاینت به آن متصل شوید.
هدف ما عبور از فیلترینگ شدید با حداکثر سرعت و پایداری است.

## پیش‌نیازها

1.  **یک سرور مجازی (VPS):** به یک سروری نیاز دارید که IP عمومی داشته باشد. توصیه ما Ubuntu 22.04 یا Debian 11/12 است.
2.  **دانش مقدماتی ترمینال:** باید بتوانید دستورات ساده را در ترمینال اجرا کنید.

## ۱. راه‌اندازی سرور (لینوکس VPS)

### گام اول: دانلود و نصب
با SSH به سرور خود متصل شوید و دستورات زیر را برای دانلود آخرین نسخه اجرا کنید :

```bash
# ایجاد پوشه
mkdir -p /opt/phoenix
cd /opt/phoenix

# دانلود فایل اجرایی (مثال برای Linux AMD64)
wget https://github.com/Selin2005/phoenix/releases/latest/download/phoenix-server-linux-amd64.zip
unzip phoenix-server-linux-amd64.zip
chmod +x phoenix-server-linux-amd64
mv phoenix-server-linux-amd64 phoenix-server
```

### گام دوم: تولید کلیدها (Gen Keys)
برای امنیت حداکثری و جلوگیری از شنود، یک جفت کلید Ed25519 بسازید:

```bash
./phoenix-server -gen-keys
```
*   فایل `private.key` (که ساخته شده) را نگه دارید و جایی کپی نکنید.
*   **Public Key** که در خروجی چاپ می‌شود را کپی کنید. این کلید برای کلاینت لازم است.

### گام سوم: پیکربندی (Config)
فایل `server.toml` را ویرایش کنید:

```toml
listen_addr = ":443"

[security]
enable_socks5 = true
enable_udp = true
private_key = "private.key"

# کلید عمومی کلاینت خود را اینجا وارد کنید (برای mTLS - توصیه شده)
# اگر خالی بگذارید، هر کلاینتی که کلید سرور را داشته باشد می‌تواند وصل شود (One-Way TLS).
authorized_clients = [
    "کلید_عمومی_کلاینت_شما_در_اینجا"
]
```

### گام چهارم: اجرای سرویس (Systemd)
برای اینکه ققنوس همیشه در پس‌زمینه اجرا شود و با ریبوت سرور بالا بیاید:

```bash
# ایجاد فایل سرویس
sudo nano /etc/systemd/system/phoenix.service
```

مقادیر زیر را در آن قرار دهید:
```ini
[Unit]
Description=Phoenix Tunnel Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/phoenix
ExecStart=/opt/phoenix/phoenix-server -c server.toml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

فعال‌سازی و شروع:
```bash
sudo systemctl enable phoenix
sudo systemctl start phoenix
sudo systemctl status phoenix
```

## ۲. راه‌اندازی کلاینت

### ویندوز (Windows)
1.  فایل `phoenix-client-windows-amd64.zip` را دانلود و اکسترکت کنید.
2.  فایل `example_client.toml` را باز کرده و نام آن را به `client.toml` تغییر دهید.
3.  فایل `client.toml` را ویرایش کنید:
    ```toml
    remote_addr = "IP_سرور_شما:443"
    server_public_key = "کلید_عمومی_سرور_شما"
    
    [[inbounds]]
    protocol = "socks5"
    local_addr = "127.0.0.1:1080"
    enable_udp = true
    ```
4.  در همان پوشه PowerShell یا CMD را باز کنید و اجرا کنید:
    ```powershell
    .\phoenix-client-windows-amd64.exe -c client.toml
    ```
5.  تلگرام یا مرورگر خود را روی پروکسی ساکس `127.0.0.1:1080` تنظیم کنید.

### لینوکس / مک (Linux / macOS)
1.  فایل باینری مربوطه را دانلود و اکسترکت کنید.
2.  قابلیت اجرا بدهید: `chmod +x phoenix-client*`.
3.  تولید کلید کلاینت (برای mTLS):
    ```bash
    ./phoenix-client -gen-keys
    ```
    (خروجی کلید عمومی را در کانفیگ سرور `authorized_clients` قرار دهید).
4.  فایل `client.toml` را با `server_public_key` و `private_key` (اختیاری) ویرایش کنید.
5.  اجرا کنید:
    ```bash
    ./phoenix-client -c client.toml
    ```

### اندروید (Termux)
1.  برنامه **Termux** را از F-Droid نصب کنید.
2.  دستور `pkg install wget` را بزنید.
3.  نسخه `linux-arm64` را دانلود کنید.
4.  مراحل لینوکس بالا را دنبال کنید.

## عیب‌یابی (Troubleshooting)

-   **Connection Refused:** فایروال سرور (UFW/IPTables) را چک کنید. پورت 443 باید باز باشد.
    ```bash
    sudo ufw allow 443/tcp
    ```
-   **Handshake Failure:** ساعت سیستم (Time) در سرور و کلاینت باید دقیق باشد.
-   **لاگ "Reset Storm" یا "Hard Reset":** این یعنی شبکه ناپایدار است یا اختلال وجود دارد. ققنوس به طور خودکار اتصال را ریست می‌کند تا دوباره وصل شود. این طبیعی است.
