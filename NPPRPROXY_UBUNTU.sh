#!/bin/bash

# =====================================================
# АНОНИМНЫЙ IPv6 ПРОКСИ - ВЕРСИЯ ДЛЯ UBUNTU/DEBIAN
# Основан на NPPRPROXY от NPPRTEAM
# =====================================================

# ANSI цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Проверка root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Этот скрипт должен быть запущен от root${NC}"
   echo "Используйте: sudo ./NPPRPROXY_UBUNTU.sh"
   exit 1
fi

show_header() {
    clear
    echo -e "${RED}"
    echo "███╗   ██╗██████╗ ██████╗ ██████╗ ████████╗███████╗ █████╗ ███╗   ███╗"
    echo "████╗  ██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║"
    echo "██╔██╗ ██║██████╔╝██████╔╝██████╔╝   ██║   █████╗  ███████║██╔████╔██║"
    echo "██║╚██╗██║██╔═══╝ ██╔═══╝ ██╔══██╗   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║"
    echo "██║ ╚████║██║     ██║     ██║  ██║   ██║   ███████╗██║  ██║██║ ╚═╝ ██║"
    echo "╚═╝  ╚═══╝╚═╝     ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝"
    echo -e "${NC}"
    echo -e "${YELLOW}[UBUNTU/DEBIAN VERSION] - Максимальная анонимность${NC}"
    echo -e "${GREEN}------------------------------------------------"
    echo "Контакты NPPRTEAM:"
    echo "Telegram — https://t.me/nppr_team"
    echo "VK — https://vk.com/npprteam"
    echo "Antik Browser — https://antik-browser.com/"
    echo -e "------------------------------------------------${NC}"
}

show_header

show_progress() {
    local i=0
    local sp='/-\|'
    echo -n "$1... "
    while true; do
        printf "\b${sp:i++%${#sp}:1}"
        sleep 0.2
    done
}

start_progress() {
    show_progress "$1" &
    PROGRESS_PID=$!
}

stop_progress() {
    kill $PROGRESS_PID 2>/dev/null
    wait $PROGRESS_PID 2>/dev/null
    echo " Готово"
}

# Генерация случайных данных
array=(0 1 2 3 4 5 6 7 8 9 a b c d e f)

random() {
    tr </dev/urandom -dc A-Za-z0-9 | head -c5
    echo
}

gen_segment() {
    echo "${array[$RANDOM % 16]}${array[$RANDOM % 16]}${array[$RANDOM % 16]}${array[$RANDOM % 16]}"
}

gen64() { 
    echo "$1:$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment)"
}

gen32() { echo "$1:$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment)"; }
gen48() { echo "$1:$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment)"; }
gen56() { echo "$1:$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment)"; }

generate_ipv6() {
    local prefix=$1
    local subnet_size=$2
    case $subnet_size in
        32) gen32 $prefix ;;
        48) gen48 $prefix ;;
        56) gen56 $prefix ;;
        64) gen64 $prefix ;;
        *) gen64 $prefix ;;
    esac
}

# Определение сетевого интерфейса
detect_interface() {
    ip route get 8.8.8.8 | awk '{print $5}' | head -n1
}

main_interface=$(detect_interface)

auto_detect_ipv6_info() {
    local iface=$(ip -6 route show default | awk '{print $5}' | head -n1)
    if [ -z "$iface" ]; then
        iface=$main_interface
    fi
    local ipv6_address=$(ip -6 addr show dev "$iface" scope global | grep 'inet6' | awk '{print $2}' | head -n1)
    local ipv6_prefix=$(echo "$ipv6_address" | sed -e 's/\/.*//g' | awk -F ':' '{print $1":"$2":"$3":"$4}')
    local ipv6_subnet_size=$(echo "$ipv6_address" | grep -oP '\/\K\d+')

    if [ -z "$ipv6_address" ] || [ -z "$ipv6_subnet_size" ]; then
        return 1
    fi
    echo "$ipv6_prefix $ipv6_subnet_size"
}

# =====================================================
# УСТАНОВКА ПАКЕТОВ (UBUNTU/DEBIAN)
# =====================================================

install_packages() {
    echo ""
    start_progress "Обновление системы"
    apt-get update -y > /dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y > /dev/null 2>&1
    stop_progress

    start_progress "Установка необходимых пакетов"
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        gcc \
        g++ \
        make \
        wget \
        curl \
        nano \
        tar \
        gzip \
        zip \
        unzip \
        jq \
        net-tools \
        iptables \
        libarchive-tools \
        > /dev/null 2>&1
    stop_progress
}

# =====================================================
# УСТАНОВКА 3PROXY
# =====================================================

install_3proxy() {
    start_progress "Установка 3proxy"
    
    mkdir -p /3proxy
    cd /3proxy
    
    URL="https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz"
    wget -qO- $URL | tar -xzf-
    cd 3proxy-0.9.4
    
    make -f Makefile.Linux > /dev/null 2>&1
    
    mkdir -p /usr/local/etc/3proxy/{bin,logs,stat}
    cp bin/3proxy /usr/local/etc/3proxy/bin/
    
    # Создаем systemd сервис
    cat > /etc/systemd/system/3proxy.service << 'EOF'
[Unit]
Description=3proxy Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/etc/3proxy/bin/3proxy /usr/local/etc/3proxy/3proxy.cfg
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    
    cd $WORKDIR
    stop_progress
}

# =====================================================
# НАСТРОЙКИ АНОНИМНОСТИ
# =====================================================

setup_anonymity() {
    start_progress "Применение настроек анонимности"
    
    # Удаляем старые настройки если есть
    sed -i '/# ANON PROXY START/,/# ANON PROXY END/d' /etc/sysctl.conf
    
    cat >> /etc/sysctl.conf << 'EOF'
# ANON PROXY START
# Лимиты
fs.file-max = 1000000
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

# IPv4
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.conf.all.forwarding = 1
net.ipv4.ip_nonlocal_bind = 1
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 87380 16777216
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_tw_reuse = 1

# Скрываем от пинга
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# IPv6
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.proxy_ndp = 1
net.ipv6.ip_nonlocal_bind = 1

# IPv6 Privacy Extensions
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2

# Защита
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 0
# ANON PROXY END
EOF

    sysctl -p > /dev/null 2>&1
    
    # Увеличиваем лимиты
    cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 999999
* hard nofile 999999
root soft nofile 999999
root hard nofile 999999
EOF

    stop_progress
}

# TCP Fingerprint
set_tcp_fingerprint() {
    local os=$1
    start_progress "Применение TCP fingerprint для $os"
    
    case "$os" in
        "Windows")
            sysctl -w net.ipv4.ip_default_ttl=128 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_syn_retries=2 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_fin_timeout=30 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_keepalive_time=7200 > /dev/null 2>&1
            iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null
            ;;
        "MacOS")
            sysctl -w net.ipv4.ip_default_ttl=64 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_syn_retries=3 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_fin_timeout=15 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_keepalive_time=7200 > /dev/null 2>&1
            iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null
            ;;
        "Linux")
            sysctl -w net.ipv4.ip_default_ttl=64 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_syn_retries=6 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_fin_timeout=60 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_keepalive_time=7200 > /dev/null 2>&1
            iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null
            ;;
        "Android")
            sysctl -w net.ipv4.ip_default_ttl=64 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_syn_retries=5 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_fin_timeout=30 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_keepalive_time=600 > /dev/null 2>&1
            iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400 2>/dev/null
            ;;
        "iPhone")
            sysctl -w net.ipv4.ip_default_ttl=64 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_syn_retries=3 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_fin_timeout=30 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_keepalive_time=7200 > /dev/null 2>&1
            iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null
            ;;
    esac
    
    stop_progress
}

# =====================================================
# DNS-OVER-HTTPS
# =====================================================

install_dns_protection() {
    start_progress "Установка DNS-over-HTTPS защиты"
    
    cd /tmp
    wget -q https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/2.1.5/dnscrypt-proxy-linux_x86_64-2.1.5.tar.gz
    tar -xzf dnscrypt-proxy-linux_x86_64-2.1.5.tar.gz 2>/dev/null
    
    if [ -d "linux-x86_64" ]; then
        mv linux-x86_64/dnscrypt-proxy /usr/local/bin/
        mkdir -p /etc/dnscrypt-proxy
        
        cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml << 'EOF'
listen_addresses = ['127.0.0.1:53', '[::1]:53']
max_clients = 250
ipv4_servers = true
ipv6_servers = true
dnscrypt_servers = true
doh_servers = true
require_dnssec = true
require_nolog = true
require_nofilter = true
timeout = 5000
keepalive = 30
log_level = 0
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400

[sources]
  [sources.'public-resolvers']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']
  cache_file = '/etc/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
EOF

        cat > /etc/systemd/system/dnscrypt-proxy.service << 'EOF'
[Unit]
Description=DNSCrypt-proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/dnscrypt-proxy -config /etc/dnscrypt-proxy/dnscrypt-proxy.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

        # Отключаем systemd-resolved если есть
        systemctl stop systemd-resolved 2>/dev/null
        systemctl disable systemd-resolved 2>/dev/null
        
        systemctl daemon-reload
        systemctl enable dnscrypt-proxy > /dev/null 2>&1
        systemctl start dnscrypt-proxy > /dev/null 2>&1
        
        # Настраиваем resolv.conf
        rm -f /etc/resolv.conf
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        echo "nameserver ::1" >> /etc/resolv.conf
        chattr +i /etc/resolv.conf 2>/dev/null
    fi
    
    stop_progress
}

# =====================================================
# НАСТРОЙКА UFW/IPTABLES
# =====================================================

setup_firewall() {
    start_progress "Настройка firewall"
    
    # Отключаем UFW если есть, используем iptables напрямую
    ufw disable > /dev/null 2>&1
    
    # Сохраняем правила iptables
    iptables-save > /etc/iptables.rules 2>/dev/null
    
    stop_progress
}

# =====================================================
# ГЕНЕРАЦИЯ ДАННЫХ
# =====================================================

gen_data() {
    seq $FIRST_PORT $LAST_PORT | while read port; do
        if [[ $TYPE -eq 1 ]]; then
            echo "$USERNAME/$PASSWORD/$IP4/$port/$(gen64 $IP6)"
        else
            echo "$USERNAME/$PASSWORD/$IP4/$FIRST_PORT/$(gen64 $IP6)"
        fi
    done
}

gen_data_multiuser() {
    seq $FIRST_PORT $LAST_PORT | while read port; do
        if [[ $TYPE -eq 1 ]]; then
            echo "$(random)/$(random)/$IP4/$port/$(gen64 $IP6)"
        else
            echo "$(random)/$(random)/$IP4/$FIRST_PORT/$(gen64 $IP6)"
        fi
    done
}

# Конфигурация 3proxy (анонимная)
gen_3proxy() {
    cat <<EOF
# 3proxy ANONYMOUS configuration
daemon
maxconn 10000
nserver 127.0.0.1
nserver ::1
nscache 65536
timeouts 1 5 30 60 180 1800 15 60

# Отключаем логи для анонимности
log /dev/null
logformat ""

users $(awk -F "/" 'BEGIN{ORS="";} {print $1 ":CL:" $2 " "}' ${WORKDATA})

# HTTP proxy
$(awk -F "/" '{print "auth strong\n" \
"allow " $1 "\n" \
"proxy -64 -n -a -p" $4 " -i" $3 " -e" $5 "\n" \
"flush\n"}' ${WORKDATA})

# SOCKS5 proxy
$(awk -F "/" '{print "auth strong\n" \
"allow " $1 "\n" \
"socks -64 -n -a -p" $4+20000 " -i" $3 " -e" $5 "\n" \
"flush\n"}' ${WORKDATA})
EOF
}

gen_iptables() {
    cat <<EOF
$(awk -F "/" '{print "iptables -I INPUT -p tcp --dport " $4 " -j ACCEPT\n" \
                "iptables -I INPUT -p udp --dport " $4 " -j ACCEPT\n" \
                "iptables -I INPUT -p tcp --dport " $4+20000 " -j ACCEPT\n" \
                "iptables -I INPUT -p udp --dport " $4+20000 " -j ACCEPT"}' ${WORKDATA})
EOF
}

gen_ifconfig() {
    cat <<EOF
$(awk -F "/" '{print "ip -6 addr add " $5 "/64 dev '$main_interface'"}' ${WORKDATA})
EOF
}

gen_proxy_file() {
    cat > proxy.txt <<EOF
===========================================================================
ANONYMOUS IPv6 PROXY - NPPRTEAM (Ubuntu Version)
===========================================================================
Telegram — https://t.me/nppr_team
Antik Browser — https://antik-browser.com/
===========================================================================
HTTP прокси (формат IP:PORT:USER:PASSWORD):
$(awk -F "/" '{print $3 ":" $4 ":" $1 ":" $2 }' ${WORKDATA})

SOCKS5 прокси (порт +20000):
$(awk -F "/" '{print $3 ":" $4+20000 ":" $1 ":" $2 }' ${WORKDATA})
===========================================================================
EOF
}

upload_proxy() {
    cd $WORKDIR
    echo ""
    echo -e "${GREEN}##################################################${NC}"
    echo -e "${GREEN}# Файл с прокси: ${WORKDIR}/proxy.txt${NC}"
    echo -e "${GREEN}# Всегда ваш NPPRTEAM!${NC}"
    echo -e "${GREEN}##################################################${NC}"
}

# =====================================================
# ГЛАВНЫЙ ПРОЦЕСС
# =====================================================

echo ""
echo -e "${GREEN}Запуск установки анонимных IPv6 прокси...${NC}"
echo ""

# Установка пакетов
install_packages

# Создаем рабочую директорию
WORKDIR="/home/proxy-installer"
WORKDATA="${WORKDIR}/data.txt"
mkdir -p $WORKDIR
cd $WORKDIR

# Устанавливаем 3proxy
install_3proxy

# Применяем настройки анонимности
setup_anonymity

# Устанавливаем DNS защиту
install_dns_protection

# Получаем IP адреса
IP4=$(curl -4 -s icanhazip.com 2>/dev/null || curl -4 -s ifconfig.me 2>/dev/null)
IP6=$(curl -6 -s icanhazip.com 2>/dev/null | cut -f1-4 -d':')

show_header
echo -e "IPv4: ${GREEN}${IP4}${NC}"
echo -e "IPv6 prefix: ${GREEN}${IP6}${NC}"
echo -e "Интерфейс: ${GREEN}${main_interface}${NC}"
echo ""

# Проверяем IPv6
if [ -z "$IP6" ]; then
    echo -e "${RED}ВНИМАНИЕ: IPv6 не обнаружен!${NC}"
    echo "Для IPv6 прокси нужен сервер с IPv6 подсетью."
    echo "Продолжить только с IPv4? (y/n)"
    read -r continue_ipv4
    if [[ "$continue_ipv4" != "y" ]]; then
        exit 1
    fi
    IP6="::1"
fi

# Количество прокси
echo -e "${YELLOW}Сколько прокси создать? (например: 100)${NC}"
read COUNT
if ! [[ "$COUNT" =~ ^[0-9]+$ ]]; then
    COUNT=100
fi
echo "Создаём $COUNT прокси"

# Рандомный начальный порт
RANDOM_OFFSET=$((RANDOM % 5000))
FIRST_PORT=$((10000 + RANDOM_OFFSET))
LAST_PORT=$(($FIRST_PORT + $COUNT - 1))
echo -e "Порты: ${GREEN}${FIRST_PORT}-${LAST_PORT}${NC} (HTTP) и ${GREEN}$((FIRST_PORT+20000))-$((LAST_PORT+20000))${NC} (SOCKS5)"

# TCP Fingerprint
echo ""
echo -e "${YELLOW}Выберите TCP/IP отпечаток:${NC}"
echo "1 - Windows"
echo "2 - MacOS"
echo "3 - Linux"
echo "4 - Android"
echo "5 - iPhone"
read -p "Выбор (1-5): " os_choice

case $os_choice in
    1) os="Windows" ;;
    2) os="MacOS" ;;
    3) os="Linux" ;;
    4) os="Android" ;;
    5) os="iPhone" ;;
    *) os="Linux" ;;
esac
set_tcp_fingerprint "$os"

# Тип прокси
echo ""
echo -e "${YELLOW}Тип прокси:${NC}"
echo "1 - Статические (каждый порт = свой IPv6)"
echo "2 - Ротация (один порт, IPv6 меняется)"
read TYPE
if [[ $TYPE -ne 1 ]]; then
    TYPE=2
fi

# Логин/пароль
echo ""
echo -e "${YELLOW}Авторизация:${NC}"
echo "1 - Один логин/пароль для всех"
echo "2 - Разные для каждого прокси"
read NUSER

USERNAME=$(random)
PASSWORD=$(random)

start_progress "Генерация данных прокси"
if [[ $NUSER -eq 1 ]]; then
    gen_data > $WORKDATA
else
    gen_data_multiuser > $WORKDATA
fi
stop_progress

# Генерируем конфиги
start_progress "Создание конфигурации"
gen_iptables > $WORKDIR/boot_iptables.sh
gen_ifconfig > $WORKDIR/boot_ifconfig.sh
chmod +x $WORKDIR/boot_*.sh
gen_3proxy > /usr/local/etc/3proxy/3proxy.cfg
stop_progress

# Настройка firewall
setup_firewall

# Создаем автозапуск
cat > /etc/rc.local << EOF
#!/bin/bash
bash ${WORKDIR}/boot_iptables.sh
bash ${WORKDIR}/boot_ifconfig.sh
ulimit -n 65535
systemctl start 3proxy
exit 0
EOF
chmod +x /etc/rc.local

# Запускаем
start_progress "Запуск прокси сервера"
bash ${WORKDIR}/boot_iptables.sh > /dev/null 2>&1
bash ${WORKDIR}/boot_ifconfig.sh > /dev/null 2>&1
systemctl start 3proxy > /dev/null 2>&1
stop_progress

# Генерируем файл с прокси
gen_proxy_file

# Загружаем
upload_proxy

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}УСТАНОВКА ЗАВЕРШЕНА!${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "${YELLOW}Настройки анонимности:${NC}"
echo "• TCP fingerprint: $os"
echo "• DNS-over-HTTPS: включен"
echo "• Логи 3proxy: отключены"
echo "• IPv6 Privacy Extensions: включены"
echo "• ICMP (ping): отключен"
echo ""
echo -e "${YELLOW}Управление:${NC}"
echo "• Статус: systemctl status 3proxy"
echo "• Рестарт: systemctl restart 3proxy"
echo "• Логи: journalctl -u 3proxy"
echo -e "${GREEN}============================================${NC}"
