# مدیریت با Systemd (لینوکس)

برای اطمینان از اینکه سرور ققنوس همیشه در حال اجراست و پس از ریبوت شدن سرور به صورت خودکار بالا می‌آید، بهترین راه استفاده از **Systemd** در لینوکس است.

## مراحل تنظیم سرویس

### ۱. ایجاد فایل سرویس
ابتدا با استفاده از یک ویرایشگر متن (مانند nano)، یک فایل جدید برای سرویس ققنوس ایجاد کنید:

```bash
nano /etc/systemd/system/phoenix.service
```

### ۲. قرار دادن پیکربندی
محتویات زیر را کپی کرده و در فایل قرار دهید. دقت کنید که مسیر `WorkingDirectory` و `ExecStart` باید با محل نصب برنامه شما مطابقت داشته باشد:

```ini
[Unit]
Description=Phoenix Tunnel Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/phoenix
ExecStart=/root/phoenix/phoenix-server -config server.toml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

> [!TIP]
> اگر برنامه را در مسیر دیگری نصب کرده‌اید، حتماً `/root/phoenix` را به مسیر درست تغییر دهید.

### ۳. بارگذاری و فعال‌سازی
پس از ذخیره فایل (در nano با `Ctrl+O` و سپس `Enter` و خروج با `Ctrl+X`)، دستورات زیر را به ترتیب اجرا کنید:

```bash
# بارگذاری مجدد تنظیمات سیستم
systemctl daemon-reload

# فعال‌سازی سرویس برای اجرا در هنگام بوت
systemctl enable phoenix.service

# شروع به کار سرویس
systemctl start phoenix.service

# بررسی وضعیت سرویس
systemctl status phoenix.service
```

## مدیریت سرویس
شما می‌توانید با دستورات زیر سرویس را مدیریت کنید:

- **توقف سرویس:** `systemctl stop phoenix.service`
- **راه‌اندازی مجدد:** `systemctl restart phoenix.service`
- **مشاهده لاگ‌ها:** `journalctl -u phoenix.service -f`
