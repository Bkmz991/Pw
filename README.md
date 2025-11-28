# NPPRTEAM IPv6 Proxy Installer

Скрипт для автоматической установки анонимных IPv6 прокси на Ubuntu/Debian.

## Требования

- Ubuntu 18.04+ или Debian 10+
- IPv6 подсеть (/47, /48, /56 или /64)
- Root доступ

## Установка

**Одна команда:**
```bash
wget -O- https://raw.githubusercontent.com/Bkmz991/Pw/main/NPPRPROXY_UBUNTU.sh | sudo bash
```

**Или пошагово:**
```bash
wget -O NPPRPROXY_UBUNTU.sh https://raw.githubusercontent.com/Bkmz991/Pw/main/NPPRPROXY_UBUNTU.sh
chmod +x NPPRPROXY_UBUNTU.sh
sudo ./NPPRPROXY_UBUNTU.sh
```

## После установки

- Прокси в файле: `/home/proxy-installer/proxy.txt`
- Формат: `IP:PORT:USER:PASSWORD`
- HTTP порты: 10xxx
- SOCKS5 порты: 30xxx (+20000 к HTTP порту)

## Управление

```bash
systemctl status 3proxy    # статус
systemctl restart 3proxy   # перезапуск
systemctl stop 3proxy      # остановка
```

## Возможности

- Статические или ротационные прокси
- TCP fingerprint (Windows/MacOS/Linux/Android/iPhone)
- DNS-over-HTTPS защита
- Отключение логов для анонимности
- IPv6 Privacy Extensions
- Автозапуск при перезагрузке

## Контакты NPPRTEAM

- Telegram: https://t.me/nppr_team
- VK: https://vk.com/npprteam
- Antik Browser: https://antik-browser.com/
