#!/bin/bash

# =====================================================
# УЛУЧШЕННЫЙ СКРИПТ УСТАНОВКИ IPv6 ПРОКСИ
# Версия с максимальной анонимностью
# Основан на NPPRPROXY от NPPRTEAM
# =====================================================

# ANSI цвета и стили
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Функция для отображения шапки
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
    echo -e "${YELLOW}[ANON VERSION] - Максимальная анонимность${NC}"
    echo -e "${GREEN}------------------------------------------------"
    echo "Наши контакты:"
    echo "Наш ТГ — https://t.me/nppr_team"
    echo "Наш ВК — https://vk.com/npprteam"
    echo "ТГ нашего магазина — https://t.me/npprteamshop"
    echo "Магазин аккаунтов, бизнес-менеджеров ФБ и Google — https://npprteam.shop"
    echo "Наш антидетект-браузер Antik Browser — https://antik-browser.com/"
    echo -e "------------------------------------------------${NC}"
}

show_header

show_infinite_progress_bar() {
    local i=0
    local sp='/-\|'
    local current_operation="Устанавливаем скрипт"
    echo -ne "${GREEN}${current_operation}... ${NC}"
    while true; do
        echo -ne "${RED}${sp:i++%${#sp}:1} ${NC}\b\b"
        sleep 0.2
    done
}

show_final_message() {
    local download_link=$1
    local password=$2
    local local_path=$3

    echo -e "${GREEN}##################################################${NC}"
    echo -e "${GREEN}# Ваша ссылка на скачивание архива с прокси - ${download_link}${NC}"
    echo -e "${GREEN}# Пароль к архиву - ${password}${NC}"
    echo -e "${GREEN}# Файл с прокси можно найти по адресу - ${local_path}${NC}"
    echo -e "${GREEN}# Всегда ваш NPPRTEAM!${NC}"
    echo -e "${GREEN}##################################################${NC}"
}

start_progress_bar() {
    show_infinite_progress_bar &
    progress_bar_pid=$!
}

stop_progress_bar() {
    kill $progress_bar_pid 2>/dev/null
    wait $progress_bar_pid 2>/dev/null
}

# Массив для генерации частей IPv6 адреса
array=(0 1 2 3 4 5 6 7 8 9 a b c d e f)

# Получение основного интерфейса
main_interface=$(ip route get 8.8.8.8 | awk -- '{printf $5}')

random() {
    tr </dev/urandom -dc A-Za-z0-9 | head -c5
    echo
}

gen_segment() {
    echo "${array[$RANDOM % 16]}${array[$RANDOM % 16]}${array[$RANDOM % 16]}${array[$RANDOM % 16]}"
}

gen32() { echo "$1:$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment)"; }
gen48() { echo "$1:$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment)"; }
gen56() { echo "$1:$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment)"; }
gen64() { echo "$1:$(gen_segment):$(gen_segment):$(gen_segment):$(gen_segment)"; }

generate_ipv6() {
    local prefix=$1
    local subnet_size=$2
    case $subnet_size in
        32) ipv6_generated=$(gen32 $prefix) ;;
        48) ipv6_generated=$(gen48 $prefix) ;;
        56) ipv6_generated=$(gen56 $prefix) ;;
        64) ipv6_generated=$(gen64 $prefix) ;;
        *)
            echo "Ошибка: неподдерживаемый размер подсети $subnet_size"
            return 1
            ;;
    esac
    echo $ipv6_generated
}

auto_detect_ipv6_info() {
    local main_interface=$(ip -6 route show default | awk '{print $5}' | head -n1)
    local ipv6_address=$(ip -6 addr show dev "$main_interface" | grep 'inet6' | awk '{print $2}' | head -n1)
    local ipv6_prefix=$(echo "$ipv6_address" | sed -e 's/\/.*//g' | awk -F ':' '{print $1":"$2":"$3":"$4}')
    local ipv6_subnet_size=$(echo "$ipv6_address" | grep -oP '\/\K\d+')

    if [ -z "$ipv6_address" ] || [ -z "$ipv6_subnet_size" ]; then
        echo "Не удалось определить адрес или размер подсети для интерфейса $main_interface."
        return 1
    fi
    echo "$ipv6_prefix $ipv6_subnet_size"
}

ipv6_info=$(auto_detect_ipv6_info)
if [ $? -eq 0 ]; then
    read ipv6_prefix ipv6_subnet_size <<< "$ipv6_info"
    ipv6_generated=$(generate_ipv6 $ipv6_prefix $ipv6_subnet_size)
    if [ $? -eq 0 ]; then
        echo "Сгенерированный IPv6 адрес: $ipv6_generated"
    else
        echo "Ошибка при генерации IPv6 адреса."
        exit 1
    fi
else
    echo "Ошибка при определении информации IPv6."
    exit 1
fi

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

install_3proxy() {
    echo "Устанавливаем 3proxy"
    mkdir -p /3proxy
    cd /3proxy
    URL="https://raw.githubusercontent.com/mrtoan2808/3proxy-ipv6/master/3proxy-0.9.3.tar.gz"
    wget -qO- $URL | bsdtar -xvf-
    cd 3proxy-0.9.3
    make -f Makefile.Linux
    mkdir -p /usr/local/etc/3proxy/{bin,logs,stat}
    mv /3proxy/3proxy-0.9.3/bin/3proxy /usr/local/etc/3proxy/bin/
    wget https://raw.githubusercontent.com/mrtoan2808/3proxy-ipv6/master/3proxy.service-Centos8 --output-document=/3proxy/3proxy-0.9.3/scripts/3proxy.service2
    cp /3proxy/3proxy-0.9.3/scripts/3proxy.service2 /usr/lib/systemd/system/3proxy.service
    systemctl link /usr/lib/systemd/system/3proxy.service
    systemctl daemon-reload
    cd $WORKDIR
}

# =====================================================
# УЛУЧШЕННЫЕ НАСТРОЙКИ АНОНИМНОСТИ
# =====================================================

setup_anonymity_sysctl() {
    echo "Применяем настройки анонимности..."
    
    # Очищаем старые настройки
    sed -i '/# ANON PROXY SETTINGS/,/# END ANON PROXY SETTINGS/d' /etc/sysctl.conf
    
    cat >> /etc/sysctl.conf << 'SYSCTL_EOF'
# ANON PROXY SETTINGS
# Лимиты файлов
fs.file-max = 1000000

# IPv4 настройки
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.conf.all.forwarding = 1
net.ipv4.ip_nonlocal_bind = 1

# TCP оптимизация и анонимность
net.ipv4.tcp_rmem = 8192 87380 4194304
net.ipv4.tcp_wmem = 8192 87380 4194304
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Отключаем ICMP (скрываем от пинга)
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# IPv6 настройки анонимности
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.proxy_ndp = 1
net.ipv6.ip_nonlocal_bind = 1

# IPv6 Privacy Extensions (рандомизация адресов)
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.all.temp_prefered_lft = 300
net.ipv6.conf.all.temp_valid_lft = 600

# Отключаем IPv6 ICMP
net.ipv6.icmp.echo_ignore_all = 1

# Защита от спуфинга
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Не отвечаем на ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Не логируем марсианские пакеты
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0
# END ANON PROXY SETTINGS
SYSCTL_EOF

    sysctl -p > /dev/null 2>&1
}

# Улучшенная функция TCP fingerprint
set_tcp_fingerprint() {
    local os=$1
    echo "Применяем TCP/IP отпечаток для $os..."
    
    case "$os" in
        "Windows")
            sysctl -w net.ipv4.ip_default_ttl=128 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_syn_retries=2 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_fin_timeout=30 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_keepalive_time=7200 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_window_scaling=1 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_sack=1 > /dev/null 2>&1
            # Windows-specific MSS
            iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null
            ;;
        "MacOS")
            sysctl -w net.ipv4.ip_default_ttl=64 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_syn_retries=3 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_fin_timeout=15 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_keepalive_time=7200 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_window_scaling=1 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_sack=1 > /dev/null 2>&1
            iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null
            ;;
        "Linux")
            sysctl -w net.ipv4.ip_default_ttl=64 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_syn_retries=6 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_fin_timeout=60 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_keepalive_time=7200 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_window_scaling=1 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_sack=1 > /dev/null 2>&1
            iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null
            ;;
        "Android")
            sysctl -w net.ipv4.ip_default_ttl=64 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_syn_retries=5 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_fin_timeout=30 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_keepalive_time=600 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_window_scaling=1 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_sack=1 > /dev/null 2>&1
            iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400 2>/dev/null
            ;;
        "iPhone")
            sysctl -w net.ipv4.ip_default_ttl=64 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_syn_retries=3 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_fin_timeout=30 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_keepalive_time=7200 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_window_scaling=1 > /dev/null 2>&1
            sysctl -w net.ipv4.tcp_sack=1 > /dev/null 2>&1
            iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1460 2>/dev/null
            ;;
    esac
    
    sysctl -p > /dev/null 2>&1
    echo "Настройки для $os применены."
}

# Установка DNS-over-HTTPS через dnscrypt-proxy
install_dns_protection() {
    echo "Устанавливаем защиту DNS..."
    
    # Проверяем, установлен ли уже dnscrypt-proxy
    if ! command -v dnscrypt-proxy &> /dev/null; then
        cd /tmp
        wget -q https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/2.1.5/dnscrypt-proxy-linux_x86_64-2.1.5.tar.gz
        tar -xzf dnscrypt-proxy-linux_x86_64-2.1.5.tar.gz
        mv linux-x86_64/dnscrypt-proxy /usr/local/bin/
        mkdir -p /etc/dnscrypt-proxy
        
        # Конфигурация dnscrypt-proxy для анонимности
        cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml << 'DNS_EOF'
listen_addresses = ['127.0.0.1:53', '[::1]:53']
max_clients = 250
ipv4_servers = true
ipv6_servers = true
dnscrypt_servers = true
doh_servers = true
require_dnssec = true
require_nolog = true
require_nofilter = true
force_tcp = false
timeout = 5000
keepalive = 30
log_level = 0
use_syslog = false
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600

[sources]
  [sources.'public-resolvers']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']
  cache_file = '/etc/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'

[anonymized_dns]
routes = [
    { server_name='*', via=['anon-relay-1', 'anon-relay-2'] }
]
DNS_EOF

        # Создаем systemd сервис
        cat > /etc/systemd/system/dnscrypt-proxy.service << 'SERVICE_EOF'
[Unit]
Description=DNSCrypt-proxy client
After=network.target

[Service]
ExecStart=/usr/local/bin/dnscrypt-proxy -config /etc/dnscrypt-proxy/dnscrypt-proxy.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE_EOF

        systemctl daemon-reload
        systemctl enable dnscrypt-proxy
        systemctl start dnscrypt-proxy
        
        # Настраиваем resolv.conf
        chattr -i /etc/resolv.conf 2>/dev/null
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        echo "nameserver ::1" >> /etc/resolv.conf
        chattr +i /etc/resolv.conf
    fi
    
    echo "DNS защита установлена (DNSCrypt + DoH)"
}

# Настройка firewall (вместо полного отключения)
setup_firewall() {
    echo "Настраиваем firewall..."
    
    # Проверяем наличие firewalld
    if systemctl is-active --quiet firewalld; then
        # Открываем только нужные порты вместо отключения
        firewall-cmd --permanent --add-port=${FIRST_PORT}-${LAST_PORT}/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port=${FIRST_PORT}-${LAST_PORT}/udp > /dev/null 2>&1
        # SOCKS порты (+20000)
        SOCKS_FIRST=$((FIRST_PORT + 20000))
        SOCKS_LAST=$((LAST_PORT + 20000))
        firewall-cmd --permanent --add-port=${SOCKS_FIRST}-${SOCKS_LAST}/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port=${SOCKS_FIRST}-${SOCKS_LAST}/udp > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
        echo "Firewall настроен (открыты только нужные порты)"
    else
        # Используем iptables если firewalld не активен
        echo "firewalld не активен, используем iptables"
    fi
}

# =====================================================
# УЛУЧШЕННАЯ ГЕНЕРАЦИЯ КОНФИГУРАЦИИ 3PROXY
# =====================================================

gen_3proxy() {
    cat <<EOF
# 3proxy configuration - ANONYMOUS VERSION
daemon
maxconn 10000
nserver 127.0.0.1
nserver ::1
nscache 65536
timeouts 1 5 30 60 180 1800 15 60

# АНОНИМНОСТЬ: Отключаем все логи
log /dev/null
logformat ""

# АНОНИМНОСТЬ: Скрываем информацию о прокси
# Не передаем заголовки идентификации

users $(awk -F "/" 'BEGIN{ORS="";} {print $1 ":CL:" $2 " "}' ${WORKDATA})

# HTTP proxy part - без раскрывающих заголовков
$(awk -F "/" '{print "auth strong\n" \
"allow " $1 "\n" \
"proxy -64 -n -a -p" $4 " -i" $3 " -e" $5 "\n" \
"flush\n"}' ${WORKDATA})

# SOCKS5 proxy part
$(awk -F "/" '{print "auth strong\n" \
"allow " $1 "\n" \
"socks -64 -n -a -p" $4+20000 " -i" $3 " -e" $5 "\n" \
"flush\n"}' ${WORKDATA})
EOF
}

gen_iptables() {
    cat <<EOF
$(awk -F "/" '{print "iptables -I INPUT -p tcp --dport " $4 "  -m state --state NEW -j ACCEPT\n" \
                "iptables -I INPUT -p udp --dport " $4 "  -m state --state NEW -j ACCEPT\n" \
                "iptables -I INPUT -p tcp --dport " $4+20000 "  -m state --state NEW -j ACCEPT\n" \
                "iptables -I INPUT -p udp --dport " $4+20000 "  -m state --state NEW -j ACCEPT"}' ${WORKDATA})
EOF
}

gen_ifconfig() {
    cat <<EOF
$(awk -F "/" '{print "ifconfig '$main_interface' inet6 add " $5 "/64"}' ${WORKDATA})
EOF
}

gen_proxy_file_for_user() {
    cat >proxy.txt <<EOF
===========================================================================
ANONYMOUS IPv6 PROXY - NPPRTEAM
===========================================================================
Наши контакты:
Наш ТГ — https://t.me/nppr_team
Наш ВК — https://vk.com/npprteam
ТГ нашего магазина — https://t.me/npprteamshop
Магазин аккаунтов, бизнес-менеджеров ФБ и Google— https://npprteam.shop
Наш антидетект-браузер Antik Browser — https://antik-browser.com/
===========================================================================
Формат: IP:PORT:USER:PASSWORD
===========================================================================
$(awk -F "/" '{print $3 ":" $4 ":" $1 ":" $2 }' ${WORKDATA})
EOF
}

upload_proxy() {
    cd $WORKDIR
    local PASS=$(random)
    zip --password $PASS proxy.zip proxy.txt > /dev/null 2>&1
    response=$(curl -s -F "file=@proxy.zip" https://file.io)
    URL=$(echo $response | jq -r '.link')

    if [ -z "$URL" ]; then
        echo "Ошибка: не удалось получить URL для скачивания."
        return 1
    fi

    show_final_message "$URL" "$PASS" "$(pwd)/proxy.txt"
}

# =====================================================
# ОСНОВНОЙ ПРОЦЕСС УСТАНОВКИ
# =====================================================

echo "Добро пожаловать в АНОНИМНУЮ установку прокси от NPPRTEAM"
echo ""

# Обновляем систему
show_header
echo "Обновление системы..."
start_progress_bar
sudo yum update -y > /dev/null 2>&1
stop_progress_bar

# Устанавливаем необходимые инструменты
show_header
echo "Установка инструментов..."
start_progress_bar
sudo yum install gcc make wget nano tar gzip iptables-services -y > /dev/null 2>&1
stop_progress_bar

# Устанавливаем jq
show_header
start_progress_bar
sudo yum install epel-release -y > /dev/null 2>&1
stop_progress_bar

show_header
start_progress_bar
sudo yum install jq zip -y > /dev/null 2>&1
stop_progress_bar

# Устанавливаем Development Tools
show_header
start_progress_bar
sudo yum group install "Development Tools" -y > /dev/null 2>&1
stop_progress_bar

# Устанавливаем 3proxy
show_header
start_progress_bar
yum -y install gcc net-tools bsdtar zip make > /dev/null 2>&1
stop_progress_bar

show_header
start_progress_bar
install_3proxy > /dev/null 2>&1
stop_progress_bar

# Применяем настройки анонимности
show_header
echo "Применяем настройки анонимности..."
start_progress_bar
setup_anonymity_sysctl > /dev/null 2>&1
stop_progress_bar

# Устанавливаем DNS защиту
show_header
echo "Установка DNS-over-HTTPS защиты..."
start_progress_bar
install_dns_protection > /dev/null 2>&1
stop_progress_bar

echo "Рабочая папка = /home/proxy-installer"
WORKDIR="/home/proxy-installer"
WORKDATA="${WORKDIR}/data.txt"
mkdir -p $WORKDIR && cd $_

USERNAME=$(random)
PASSWORD=$(random)
IP4=$(curl -4 -s icanhazip.com)
IP6=$(curl -6 -s icanhazip.com | cut -f1-4 -d':')

show_header
echo "Internal ip = ${IP4}. External sub for ip6 = ${IP6}"

show_header
echo "Сколько прокси вы хотите создать? Пример 500"
read COUNT
echo "Вы установили количество $COUNT proxy"

# Рандомизация начального порта для дополнительной анонимности
RANDOM_OFFSET=$((RANDOM % 5000))
FIRST_PORT=$((10000 + RANDOM_OFFSET))
LAST_PORT=$(($FIRST_PORT + $COUNT))
echo "Начальный порт: $FIRST_PORT (рандомизирован)"

# Меню выбора TCP fingerprint
echo ""
echo "Выберите TCP/IP Отпечаток для ваших прокси:"
echo "1 - Windows"
echo "2 - MacOS"
echo "3 - Linux"
echo "4 - Android"
echo "5 - iPhone"

read -p "Введите номер (1-5): " os_choice

if [[ ! $os_choice =~ ^[1-5]$ ]]; then
    echo "Неправильный выбор. Устанавливаем Linux по умолчанию."
    os_choice=3
fi

os=""
case $os_choice in
    1) os="Windows" ;;
    2) os="MacOS" ;;
    3) os="Linux" ;;
    4) os="Android" ;;
    5) os="iPhone" ;;
esac

echo "Выбранная операционная система: $os"
set_tcp_fingerprint "$os"

echo ""
echo "Какие прокси вы хотите создать?"
echo "1 - Статические"
echo "2 - С ротацией"
read TYPE

if [[ $TYPE -eq 1 ]]; then
    show_header
    echo "Вы выбрали статические прокси"
else
    show_header
    echo "Вы выбрали прокси с ротацией"
fi

echo ""
echo "Вы хотите создать один логин и пароль для всех прокси, или разные?"
echo "1 - Один"
echo "2 - Разные"
read NUSER

if [[ NUSER -eq 1 ]]; then
    show_header
    start_progress_bar
    echo "Вы выбрали один логин и пароль для всех прокси"
    gen_data >$WORKDIR/data.txt
    stop_progress_bar
else
    show_header
    start_progress_bar
    echo "Вы выбрали разные данные для прокси"
    gen_data_multiuser >$WORKDIR/data.txt
    stop_progress_bar
fi

gen_iptables >$WORKDIR/boot_iptables.sh
gen_ifconfig >$WORKDIR/boot_ifconfig.sh
echo NM_CONTROLLED="no" >> /etc/sysconfig/network-scripts/ifcfg-${main_interface}
chmod +x $WORKDIR/boot_*.sh /etc/rc.local

gen_3proxy >/usr/local/etc/3proxy/3proxy.cfg

# Настраиваем firewall
setup_firewall

cat >>/etc/rc.local <<EOF
systemctl start NetworkManager.service
bash ${WORKDIR}/boot_iptables.sh
bash ${WORKDIR}/boot_ifconfig.sh
ulimit -n 65535
/usr/local/etc/3proxy/bin/3proxy /usr/local/etc/3proxy/3proxy.cfg &
EOF

bash /etc/rc.local

gen_proxy_file_for_user

upload_proxy

echo ""
echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}АНОНИМНЫЕ ПРОКСИ УСПЕШНО УСТАНОВЛЕНЫ!${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e "${YELLOW}Улучшения анонимности:${NC}"
echo "- TCP/IP fingerprint: $os"
echo "- DNS-over-HTTPS: включен"
echo "- Логирование 3proxy: отключено"
echo "- IPv6 Privacy Extensions: включены"
echo "- ICMP (ping): отключен"
echo "- Firewall: настроен (только нужные порты)"
echo -e "${GREEN}==============================================${NC}"

cd /root
rm -f NPPRPROXY_ANON.sh 2>/dev/null
