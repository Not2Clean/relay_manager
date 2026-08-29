#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# ЦВЕТА И СТИЛИ
# ==============================================================================
C_RESET='\033[0m'
C_BOLD='\033[1m'
C_RED='\033[1;31m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_BLUE='\033[1;34m'
C_CYAN='\033[1;36m'
C_DIM='\033[2m'

# ==============================================================================
# ПУТИ И КОНФИГУРАЦИЯ
# ==============================================================================
CONF_DIR="/etc/relay-manager"
RELAYS_FILE="$CONF_DIR/relays.list"          # формат строки: LPORT:BIP:BPORT:PROTO (PROTO=tcp|udp|both)
ENV_FILE="$CONF_DIR/config.env"
EXTRA_PORTS_FILE="$CONF_DIR/extra_allowed_ports.list"   # порты сторонних служб, которым явно разрешён вход
INIT_MARKER="$CONF_DIR/.initialized"
SWAP_FILE="/swapfile"
BACKUP_DIR="/root/iptables-backups"
PRISTINE_V4="$BACKUP_DIR/pristine.v4"
PRISTINE_V6="$BACKUP_DIR/pristine.v6"
IP_REGEX='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
PORT_REGEX='^[0-9]{1,5}$'

# Имена выделенных цепочек — весь трафик relay-manager живёт только здесь.
# Это принципиально: скрипт не делает `iptables -F` по базовым таблицам
# и не трогает правила Docker/UFW/firewalld/fail2ban/VPN.
CHAIN_NAT_PRE="RELAY-PREROUTING"
CHAIN_NAT_POST="RELAY-POSTROUTING"
CHAIN_FWD="RELAY-FORWARD"

if [[ $EUID -ne 0 ]]; then
    echo -e "${C_RED}✖ Ошибка: скрипт должен запускаться от root (sudo bash setup.sh)${C_RESET}" >&2
    exit 1
fi

mkdir -p "$CONF_DIR" "$BACKUP_DIR"
touch "$RELAYS_FILE"

print_header() {
    clear
    echo -e "${C_CYAN}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║${C_BOLD}${C_GREEN}                   L4 RELAY MANAGER (IPTABLES)                ${C_RESET}${C_CYAN}║${C_RESET}"
    echo -e "${C_CYAN}║${C_DIM}         Управление высокоскоростным DNAT-пробросом           ${C_RESET}${C_CYAN}║${C_RESET}"
    echo -e "${C_CYAN}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

pause() {
    echo ""
    echo -e "${C_DIM}──────────────────────────────────────────────────────────────${C_RESET}"
    read -rp "Нажми [Enter] чтобы вернуться в меню..."
}

# ------------------------------------------------------------------------------
# Безопасно записывает/обновляет одну переменную в ENV_FILE, не затирая остальные
# (раньше файл целиком перезаписывался при каждом сохранении SSH_PORT, из-за
# чего терялись бы сохранённые "исходные" политики firewall).
# ------------------------------------------------------------------------------
set_env_var() {
    local key="$1" value="$2"
    touch "$ENV_FILE"
    if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
    else
        echo "${key}=${value}" >> "$ENV_FILE"
    fi
    chmod 600 "$ENV_FILE"
}

# ------------------------------------------------------------------------------
# Валидация IPv4 по диапазону октетов
# ------------------------------------------------------------------------------
valid_ipv4() {
    local ip="$1" IFS=. a b c d
    [[ "$ip" =~ $IP_REGEX ]] || return 1
    read -r a b c d <<< "$ip"
    for octet in "$a" "$b" "$c" "$d"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
    done
    # Отсекаем адреса, которые для DNAT-цели бессмысленны/опасны
    if [[ "$a" == "0" || "$a" == "127" || "$a" -ge 224 ]]; then
        return 1
    fi
    return 0
}

# Читает текущую политику по умолчанию для цепочки (ACCEPT/DROP), безопасно
# для `set -e` — при любой ошибке просто вернёт пустую строку.
get_policy() {
    local cmd="$1" chain="$2" pol=""
    pol=$("$cmd" -S "$chain" 2>/dev/null | head -n1 | awk '{print $3}') || true
    echo "$pol"
}

# ------------------------------------------------------------------------------
# Сохраняет состояние firewall ДО первого вмешательства скрипта — только один
# раз. Без этого "полное удаление" не знало бы, к каким политикам возвращаться.
# ------------------------------------------------------------------------------
save_pristine_state() {
    if [[ -f "$INIT_MARKER" ]]; then
        return 0
    fi

    echo -e "${C_DIM}Сохраняю исходное состояние firewall (нужно для последующего полного удаления)...${C_RESET}"

    set_env_var ORIG_INPUT_POLICY   "$(get_policy iptables INPUT)"
    set_env_var ORIG_FORWARD_POLICY "$(get_policy iptables FORWARD)"
    set_env_var ORIG_OUTPUT_POLICY  "$(get_policy iptables OUTPUT)"
    set_env_var ORIG6_INPUT_POLICY   "$(get_policy ip6tables INPUT)"
    set_env_var ORIG6_FORWARD_POLICY "$(get_policy ip6tables FORWARD)"
    set_env_var ORIG6_OUTPUT_POLICY  "$(get_policy ip6tables OUTPUT)"

    [[ -f "$PRISTINE_V4" ]] || iptables-save  > "$PRISTINE_V4" 2>/dev/null || true
    [[ -f "$PRISTINE_V6" ]] || ip6tables-save > "$PRISTINE_V6" 2>/dev/null || true

    touch "$INIT_MARKER"
}

init_system() {
    export DEBIAN_FRONTEND=noninteractive
    if ! dpkg -s iptables-persistent >/dev/null 2>&1; then
        print_header
        echo -e "${C_YELLOW}⚙ Установка необходимых пакетов (iptables-persistent)...${C_RESET}"
        if ! apt-get update -y > /dev/null 2>&1; then
            echo -e "${C_RED}✖ Не удалось обновить списки пакетов (проблема с сетью?). Повтори позже.${C_RESET}" >&2
            exit 1
        fi
        if ! apt-get install -y iptables-persistent netfilter-persistent > /dev/null 2>&1; then
            echo -e "${C_RED}✖ Не удалось установить пакеты. Повтори позже.${C_RESET}" >&2
            exit 1
        fi
        systemctl enable netfilter-persistent > /dev/null 2>&1 || true
        echo -e "${C_GREEN}✔ Пакеты установлены.${C_RESET}"
    fi

    for cmd in iptables ip6tables ss swapon fallocate mkswap; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${C_RED}✖ Не найдена команда '$cmd'. Установи её и запусти скрипт снова.${C_RESET}" >&2
            exit 1
        fi
    done

    cat << 'SYSCTL_EOF' > /etc/sysctl.d/99-relay.conf
net.ipv4.ip_forward = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 10000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_tw_reuse = 1
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 600
SYSCTL_EOF
    sysctl --system > /dev/null 2>&1 || echo -e "${C_YELLOW}! Некоторые sysctl-параметры не применились (нормально для контейнеров/старых ядер).${C_RESET}"
}

load_or_ask_ssh_port() {
    if [[ -f "$ENV_FILE" ]]; then
        chmod 600 "$ENV_FILE" 2>/dev/null || true
        # shellcheck source=/dev/null
        source "$ENV_FILE"
        # Санитизация значения из env-файла: если оно не похоже на порт — не доверяем ему
        if [[ ! "${SSH_PORT:-}" =~ $PORT_REGEX ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
            unset SSH_PORT
        fi
    fi

    if [[ -z "${SSH_PORT:-}" ]]; then
        print_header
        DETECTED_SSH_PORT=$(ss -tlnp 2>/dev/null | grep -E 'sshd|ssh' | awk '{print $4}' | awk -F: '{print $NF}' | head -n1 || true)
        DEFAULT_SSH_PORT="${DETECTED_SSH_PORT:-22}"

        echo -e "${C_YELLOW}Первичная настройка доступа:${C_RESET}"
        echo -e "${C_DIM}Проверь, что указанный порт совпадает с 'Port' в /etc/ssh/sshd_config${C_RESET}"
        while true; do
            read -rp "$(echo -e "${C_BOLD}Введи порт SSH сервера [${C_GREEN}$DEFAULT_SSH_PORT${C_RESET}${C_BOLD}]: ${C_RESET}")" INPUT_SSH
            INPUT_SSH="${INPUT_SSH:-$DEFAULT_SSH_PORT}"
            if [[ "$INPUT_SSH" =~ $PORT_REGEX ]] && (( INPUT_SSH >= 1 && INPUT_SSH <= 65535 )); then
                SSH_PORT="$INPUT_SSH"
                set_env_var SSH_PORT "$SSH_PORT"
                break
            fi
            echo -e "${C_RED}✖ Некорректный порт. Попробуй ещё раз.${C_RESET}"
        done
    fi
}

# ------------------------------------------------------------------------------
# Ищет порты, на которых слушают ЧУЖИЕ службы (не SSH и не relay-входы).
# Печатает строки "PROTO PORT PROCESS". Это эвристика поверх `ss`, не идеальная,
# но покрывает основной случай — прямые сервисы вроде Xray/nginx на хосте.
# ------------------------------------------------------------------------------
list_foreign_listeners() {
    local relay_ports
    relay_ports=$(awk -F: '$0 !~ /^#/ && NF>=1 && length($1)>0 {print $1}' "$RELAYS_FILE" 2>/dev/null | sort -u)

    { ss -Htlnp 2>/dev/null | awk '{print "TCP", $4, $6}'
      ss -Hulnp 2>/dev/null | awk '{print "UDP", $4, $6}'
    } | while read -r proto laddr proc; do
        local port="${laddr##*:}"
        # Весь диапазон 127.0.0.0/8 — loopback (например, systemd-resolved
        # слушает DNS-stub на 127.0.0.53, а не только на 127.0.0.1).
        [[ "$laddr" == 127.*:* || "$laddr" == "[::1]:"* ]] && continue
        [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]] && continue
        [[ "$port" == "${SSH_PORT:-}" ]] && continue
        if echo "$relay_ports" | grep -qx "$port"; then continue; fi
        printf '%s %s %s\n' "$proto" "$port" "${proc:-неизвестно}"
    done | sort -u -k2,2n
}

# ------------------------------------------------------------------------------
# Перед включением DROP-политики предупреждает о сторонних службах, которые
# иначе окажутся отрезаны от внешнего мира. Возвращает:
#   0 — можно жёстко блокировать (конфликтов нет либо пользователь их разрешил)
#   1 — пользователь попросил НЕ включать блокировку в этом запуске
#   2 — пользователь отменил операцию полностью
# ------------------------------------------------------------------------------
confirm_lockdown_or_skip() {
    local conflicts
    conflicts="$(list_foreign_listeners)"

    [[ -z "$conflicts" ]] && return 0

    local pending=()
    while read -r proto port proc; do
        [[ -z "$proto" ]] && continue
        if [[ -f "$EXTRA_PORTS_FILE" ]] && grep -qx "${port}:${proto,,}" "$EXTRA_PORTS_FILE" 2>/dev/null; then
            continue
        fi
        pending+=("$proto $port $proc")
    done <<< "$conflicts"

    (( ${#pending[@]} == 0 )) && return 0

    print_header
    echo -e "${C_RED}⚠ ВНИМАНИЕ: обнаружены другие службы, слушающие порты, не связанные с relay-manager:${C_RESET}"
    echo ""
    printf '  %-6s %-8s %s\n' "ПРОТО" "ПОРТ" "ПРОЦЕСС"
    local line p port proc
    for line in "${pending[@]}"; do
        read -r p port proc <<< "$line"
        printf "  ${C_YELLOW}%-6s %-8s${C_RESET} %s\n" "$p" "$port" "$proc"
    done
    echo ""
    echo -e "${C_RED}Если продолжить с жёсткой блокировкой (INPUT/FORWARD DROP по умолчанию),${C_RESET}"
    echo -e "${C_RED}эти службы станут недоступны снаружи — для них нет разрешающих правил.${C_RESET}"
    echo ""
    echo -e "${C_BOLD}Что делать?${C_RESET}"
    echo -e " ${C_GREEN}1)${C_RESET} Разрешить входящие подключения на эти порты и продолжить блокировку (рекомендуется)"
    echo -e " ${C_YELLOW}2)${C_RESET} Не включать жёсткую блокировку сейчас (INPUT/FORWARD останутся как есть)"
    echo -e " ${C_RED}3)${C_RESET} Отмена — ничего не менять в этом запуске"
    echo ""
    read -rp "$(echo -e "${C_BOLD}Выбери [1-3]: ${C_RESET}")" LOCK_CHOICE

    case "$LOCK_CHOICE" in
        1)
            touch "$EXTRA_PORTS_FILE"
            for line in "${pending[@]}"; do
                read -r p port proc <<< "$line"
                local pl="${p,,}"
                iptables  -C INPUT -p "$pl" --dport "$port" -j ACCEPT 2>/dev/null || \
                    iptables  -A INPUT -p "$pl" --dport "$port" -j ACCEPT
                ip6tables -C INPUT -p "$pl" --dport "$port" -j ACCEPT 2>/dev/null || \
                    ip6tables -A INPUT -p "$pl" --dport "$port" -j ACCEPT
                echo "${port}:${pl}" >> "$EXTRA_PORTS_FILE"
            done
            sort -u -o "$EXTRA_PORTS_FILE" "$EXTRA_PORTS_FILE"
            echo -e "${C_GREEN}✔ Порты разрешены, продолжаю настройку блокировки.${C_RESET}"
            sleep 1
            return 0
            ;;
        2)
            echo -e "${C_YELLOW}⚠ Жёсткая блокировка НЕ включена в этом запуске.${C_RESET}"
            echo -e "${C_YELLOW}  Relay-пробросы и базовые правила (SSH/lo/established) всё равно будут добавлены.${C_RESET}"
            sleep 2
            return 1
            ;;
        *)
            echo -e "${C_RED}Отмена. Firewall не изменён.${C_RESET}"
            sleep 1
            return 2
            ;;
    esac
}

# ------------------------------------------------------------------------------
# БАЗОВЫЙ ФАЙРВОЛ — выполняется идемпотентно и ОТДЕЛЬНО от пересборки relay-правил.
# Здесь и только здесь меняются политики цепочек. Порядок жёстко фиксирован:
#   1) создать резервную копию текущего состояния
#   2) добавить ACCEPT-правило для SSH ДО того, как выставится политика DROP
#   3) предупредить о сторонних службах, которые иначе будут отрезаны (НОВОЕ)
#   4) обернуть блок в trap ERR, который откатывает backup при любой ошибке
# Возвращает 0 при полном успехе, 1 если блокировка пропущена по решению
# пользователя, 2 если пользователь всё отменил (состояние откатывается).
# ------------------------------------------------------------------------------
setup_base_firewall() {
    echo -e "${C_YELLOW}⚙ Проверка базовой конфигурации firewall...${C_RESET}"

    local backup_v4="$BACKUP_DIR/pre-base-$(date +%Y%m%d-%H%M%S).v4"
    local backup_v6="$BACKUP_DIR/pre-base-$(date +%Y%m%d-%H%M%S).v6"
    iptables-save > "$backup_v4" 2>/dev/null || true
    ip6tables-save > "$backup_v6" 2>/dev/null || true

    local rollback_done=0
    rollback_base() {
        if (( rollback_done == 1 )); then return; fi
        rollback_done=1
        echo -e "${C_RED}✖ Откатываю к состоянию до этого запуска...${C_RESET}" >&2
        iptables-restore < "$backup_v4" 2>/dev/null || true
        ip6tables-restore < "$backup_v6" 2>/dev/null || true
        echo -e "${C_YELLOW}Состояние восстановлено. Ничего не потеряно.${C_RESET}" >&2
    }
    trap rollback_base ERR

    # Гарантируем ACCEPT-политику на время настройки — так безопаснее,
    # чем DROP-политика с недостающими правилами.
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    # Создаём выделенные цепочки, если их ещё нет (никаких -F/-X на базовых таблицах!)
    iptables -t nat -N "$CHAIN_NAT_PRE" 2>/dev/null || true
    iptables -t nat -N "$CHAIN_NAT_POST" 2>/dev/null || true
    iptables -N "$CHAIN_FWD" 2>/dev/null || true

    # Прописываем jump в наши цепочки один раз
    iptables -t nat -C PREROUTING -j "$CHAIN_NAT_PRE" 2>/dev/null || \
        iptables -t nat -A PREROUTING -j "$CHAIN_NAT_PRE"
    iptables -t nat -C POSTROUTING -j "$CHAIN_NAT_POST" 2>/dev/null || \
        iptables -t nat -A POSTROUTING -j "$CHAIN_NAT_POST"
    iptables -C FORWARD -j "$CHAIN_FWD" 2>/dev/null || \
        iptables -A FORWARD -j "$CHAIN_FWD"

    # Базовые правила INPUT: loopback, established/related, SSH.
    iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -i lo -j ACCEPT
    iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    iptables -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    if ! iptables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null; then
        echo -e "${C_RED}✖ Не удалось подтвердить ACCEPT-правило для SSH-порта $SSH_PORT. Отмена.${C_RESET}" >&2
        false
    fi

    ip6tables -P INPUT ACCEPT
    ip6tables -P FORWARD ACCEPT
    ip6tables -P OUTPUT ACCEPT
    ip6tables -C INPUT -i lo -j ACCEPT 2>/dev/null || ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
        ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -C INPUT -p ipv6-icmp -j ACCEPT 2>/dev/null || \
        ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
    ip6tables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || \
        ip6tables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    # Снимаем ловушку ошибок на время интерактивного диалога — read/меню сами
    # по себе не являются "ошибками", которые нужно откатывать.
    trap - ERR

    local lockdown_choice=0
    confirm_lockdown_or_skip || lockdown_choice=$?

    if (( lockdown_choice == 2 )); then
        rollback_base
        return 2
    fi

    trap rollback_base ERR
    if (( lockdown_choice == 0 )); then
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
        ip6tables -P INPUT DROP
        ip6tables -P FORWARD DROP
        ip6tables -P OUTPUT ACCEPT
        echo -e "${C_GREEN}✔ Базовый firewall настроен (жёсткая блокировка активна), SSH-доступ подтверждён.${C_RESET}"
    else
        echo -e "${C_DIM}Политики INPUT/FORWARD оставлены без изменений по решению пользователя.${C_RESET}"
    fi
    trap - ERR

    return "$lockdown_choice"
}

# ------------------------------------------------------------------------------
# Пересборка ТОЛЬКО relay-правил в выделенных цепочках. Не трогает
# INPUT/политику/чужие правила вообще.
# ------------------------------------------------------------------------------
apply_relay_rules() {
    echo -e "${C_YELLOW}⚙ Применение relay-правил...${C_RESET}"

    local backup_v4="$BACKUP_DIR/pre-relay-$(date +%Y%m%d-%H%M%S).v4"
    iptables-save > "$backup_v4" 2>/dev/null || true

    local rollback_done=0
    rollback_relay() {
        if (( rollback_done == 1 )); then return; fi
        rollback_done=1
        echo -e "${C_RED}✖ Ошибка при применении relay-правил — откатываю...${C_RESET}" >&2
        iptables-restore < "$backup_v4" 2>/dev/null || true
        echo -e "${C_YELLOW}Relay-правила восстановлены к предыдущему состоянию.${C_RESET}" >&2
    }
    trap rollback_relay ERR

    iptables -t nat -F "$CHAIN_NAT_PRE"
    iptables -t nat -F "$CHAIN_NAT_POST"
    iptables -F "$CHAIN_FWD"

    if [[ -s "$RELAYS_FILE" ]]; then
        while IFS=':' read -r LPORT BIP BPORT PROTO; do
            [[ -z "$LPORT" || "$LPORT" =~ ^# ]] && continue
            PROTO="${PROTO:-tcp}"

            local protos=()
            case "$PROTO" in
                tcp)  protos=("tcp") ;;
                udp)  protos=("udp") ;;
                both) protos=("tcp" "udp") ;;
                *)    protos=("tcp") ;;
            esac

            for P in "${protos[@]}"; do
                iptables -t nat -A "$CHAIN_NAT_PRE" -p "$P" --dport "$LPORT" -j DNAT --to-destination "$BIP:$BPORT"
                iptables -t nat -A "$CHAIN_NAT_POST" -p "$P" -d "$BIP" --dport "$BPORT" -j MASQUERADE

                iptables -A "$CHAIN_FWD" -p "$P" -d "$BIP" --dport "$BPORT" -m conntrack --ctstate NEW \
                    -m hashlimit --hashlimit-above 100/sec --hashlimit-burst 200 \
                    --hashlimit-mode srcip --hashlimit-name "rl_${LPORT}_${P}" -j DROP
                iptables -A "$CHAIN_FWD" -p "$P" -d "$BIP" --dport "$BPORT" -j ACCEPT
            done
        done < "$RELAYS_FILE"
    fi

    netfilter-persistent save > /dev/null 2>&1 || true
    trap - ERR
    echo -e "${C_GREEN}✔ Relay-правила обновлены.${C_RESET}"
}

# Полное принудительное применение: сначала база (идемпотентно), потом relay-правила.
apply_all_rules() {
    local rc=0
    setup_base_firewall || rc=$?
    if (( rc == 2 )); then
        echo -e "${C_RED}Изменения отменены — relay-правила не применялись.${C_RESET}"
        return 1
    fi
    apply_relay_rules
}

proto_label() {
    case "$1" in
        tcp)  echo "TCP" ;;
        udp)  echo "UDP" ;;
        both) echo "TCP+UDP" ;;
        *)    echo "TCP" ;;
    esac
}

render_table() {
    echo -e "${C_CYAN}┌──────┬──────────────┬──────────────────────┬──────────────┬─────────┐${C_RESET}"
    echo -e "${C_CYAN}│${C_BOLD}  №   │  ВХОД (ПОРТ) │      BACKEND IP      │ БЭКЕНД ПОРТ  │ ПРОТОКОЛ${C_RESET}${C_CYAN}│${C_RESET}"
    echo -e "${C_CYAN}├──────┼──────────────┼──────────────────────┼──────────────┼─────────┤${C_RESET}"

    local i=1
    if [[ ! -s "$RELAYS_FILE" ]]; then
        echo -e "${C_CYAN}│${C_RESET}          ${C_DIM}Нет настроенных релей-пробросов${C_RESET}                       ${C_CYAN}│${C_RESET}"
    else
        while IFS=':' read -r LPORT BIP BPORT PROTO; do
            [[ -z "$LPORT" || "$LPORT" =~ ^# ]] && continue
            PROTO="${PROTO:-tcp}"
            printf "${C_CYAN}│${C_RESET} %-4s ${C_CYAN}│${C_RESET} %-12s ${C_CYAN}│${C_RESET} %-20s ${C_CYAN}│${C_RESET} %-12s ${C_CYAN}│${C_RESET} %-7s ${C_CYAN}│${C_RESET}\n" \
                "$i" "$LPORT" "$BIP" "$BPORT" "$(proto_label "$PROTO")"
            ((i++))
        done < "$RELAYS_FILE"
    fi
    echo -e "${C_CYAN}└──────┴──────────────┴──────────────────────┴──────────────┴─────────┘${C_RESET}"
    echo -e "${C_DIM}SSH-порт сервера:${C_RESET} ${C_GREEN}$SSH_PORT${C_RESET}"

    local cur_policy
    cur_policy="$(get_policy iptables INPUT)"
    if [[ "$cur_policy" == "DROP" ]]; then
        echo -e "${C_DIM}Firewall:${C_RESET} ${C_GREEN}жёсткая блокировка активна (INPUT/FORWARD DROP)${C_RESET}"
    else
        echo -e "${C_DIM}Firewall:${C_RESET} ${C_YELLOW}жёсткая блокировка НЕ активна (INPUT ${cur_policy:-ACCEPT})${C_RESET}"
    fi
    if [[ -s "$EXTRA_PORTS_FILE" ]]; then
        echo -e "${C_DIM}Доп. разрешённые порты сторонних служб:${C_RESET} $(tr '\n' ' ' < "$EXTRA_PORTS_FILE")"
    fi
}

add_relay() {
    print_header
    echo -e "${C_BOLD}${C_YELLOW}➜ Добавление нового L4-проброса${C_RESET}"
    echo ""

    while true; do
        read -rp "$(echo -e "${C_BOLD}Входящий порт на этом сервере [${C_GREEN}443${C_RESET}${C_BOLD}]: ${C_RESET}")" IN_PORT
        IN_PORT="${IN_PORT:-443}"

        if [[ ! "$IN_PORT" =~ $PORT_REGEX ]] || (( IN_PORT < 1 || IN_PORT > 65535 )); then
            echo -e "${C_RED}✖ Некорректный порт.${C_RESET}"
            continue
        fi
        if [[ "$IN_PORT" == "$SSH_PORT" ]]; then
            echo -e "${C_RED}✖ Этот порт занят под SSH! Выбери другой.${C_RESET}"
            continue
        fi
        if grep -q "^${IN_PORT}:" "$RELAYS_FILE" 2>/dev/null; then
            echo -e "${C_RED}✖ На порту $IN_PORT уже настроен релей!${C_RESET}"
            continue
        fi
        break
    done

    # Проверка: не занят ли этот порт локальной службой. DNAT перехватывает
    # трафик в PREROUTING ДО того, как он попадёт в локальный сокет — если
    # тут что-то уже слушает, relay его фактически "отрежет" от внешнего мира.
    local listener=""
    listener=$(ss -Htlnp 2>/dev/null | awk -v p=":${IN_PORT}\$" '$4 ~ p {print; exit}') || true
    if [[ -z "$listener" ]]; then
        listener=$(ss -Hulnp 2>/dev/null | awk -v p=":${IN_PORT}\$" '$4 ~ p {print; exit}') || true
    fi
    if [[ -n "$listener" ]]; then
        echo ""
        echo -e "${C_RED}⚠ ВНИМАНИЕ: на порту $IN_PORT уже слушает локальный процесс:${C_RESET}"
        echo -e "  ${C_YELLOW}${listener}${C_RESET}"
        echo -e "${C_RED}DNAT-правило перехватит трафик ДО того, как он дойдёт до этого процесса —${C_RESET}"
        echo -e "${C_RED}служба на этом порту, скорее всего, перестанет быть доступна снаружи.${C_RESET}"
        read -rp "$(echo -e "${C_BOLD}Всё равно продолжить и создать relay на порту $IN_PORT? (y/N): ${C_RESET}")" PORT_CONF
        if [[ ! "$PORT_CONF" =~ ^[YyДд]$ ]]; then
            echo "Отменено."
            pause
            return
        fi
    fi

    while true; do
        read -rp "$(echo -e "${C_BOLD}IP-адрес backend-ноды (куда слать): ${C_RESET}")" TARGET_IP
        if valid_ipv4 "$TARGET_IP"; then
            break
        fi
        echo -e "${C_RED}✖ Некорректный или недопустимый IPv4-адрес (проверь диапазон октетов, loopback/multicast запрещены).${C_RESET}"
    done

    while true; do
        read -rp "$(echo -e "${C_BOLD}Порт на backend-ноде [${C_GREEN}$IN_PORT${C_RESET}${C_BOLD}]: ${C_RESET}")" TARGET_PORT
        TARGET_PORT="${TARGET_PORT:-$IN_PORT}"
        if [[ "$TARGET_PORT" =~ $PORT_REGEX ]] && (( TARGET_PORT >= 1 && TARGET_PORT <= 65535 )); then
            break
        fi
        echo -e "${C_RED}✖ Некорректный порт.${C_RESET}"
    done

    echo ""
    echo -e "${C_BOLD}Протокол проброса:${C_RESET}"
    echo -e " ${C_GREEN}1)${C_RESET} TCP (по умолчанию)"
    echo -e " ${C_YELLOW}2)${C_RESET} UDP"
    echo -e " ${C_CYAN}3)${C_RESET} TCP + UDP (оба)"
    read -rp "$(echo -e "${C_BOLD}Выбери [1-3, по умолчанию 1]: ${C_RESET}")" PROTO_CHOICE
    case "$PROTO_CHOICE" in
        2) PROTO="udp" ;;
        3) PROTO="both" ;;
        *) PROTO="tcp" ;;
    esac

    echo ""
    echo "${IN_PORT}:${TARGET_IP}:${TARGET_PORT}:${PROTO}" >> "$RELAYS_FILE"
    apply_relay_rules

    if [[ "$PROTO" == "tcp" || "$PROTO" == "both" ]]; then
        echo -e "${C_YELLOW}Проверка сетевой доступности бэкенда (TCP)...${C_RESET}"
        if timeout 3 bash -c "cat < /dev/null > /dev/tcp/$TARGET_IP/$TARGET_PORT" 2>/dev/null; then
            echo -e "${C_GREEN}✔ Соединение успешно: $TARGET_IP:$TARGET_PORT отвечает!${C_RESET}"
        else
            echo -e "${C_RED}! Предупреждение: $TARGET_IP:$TARGET_PORT сейчас не ответил (проверь сервис/файрвол на бэкенде)${C_RESET}"
        fi
    else
        echo -e "${C_DIM}Проброс чисто UDP — автоматическая проверка доступности не выполняется (UDP без ответа неотличим от недоступности).${C_RESET}"
    fi
    pause
}

delete_relay() {
    print_header
    echo -e "${C_BOLD}${C_YELLOW}➜ Удаление релея${C_RESET}"
    echo ""
    render_table
    echo ""

    if [[ ! -s "$RELAYS_FILE" ]]; then
        pause
        return
    fi

    mapfile -t VALID_LINES < <(grep -v -E '^[[:space:]]*(#|$)' "$RELAYS_FILE" || true)
    local total=${#VALID_LINES[@]}

    if (( total == 0 )); then
        echo -e "${C_DIM}Нет настроенных релей-пробросов.${C_RESET}"
        pause
        return
    fi

    read -rp "$(echo -e "${C_BOLD}Введи номер (№) для удаления [${C_RED}0 для отмены${C_RESET}${C_BOLD}]: ${C_RESET}")" DEL_NUM
    if [[ "$DEL_NUM" == "0" || ! "$DEL_NUM" =~ ^[0-9]+$ ]]; then
        echo "Отмена."
        sleep 1
        return
    fi

    if (( DEL_NUM < 1 || DEL_NUM > total )); then
        echo -e "${C_RED}Неверный номер строки.${C_RESET}"
        sleep 1
        return
    fi

    unset 'VALID_LINES[DEL_NUM-1]'
    printf '%s\n' "${VALID_LINES[@]}" > "$RELAYS_FILE"
    echo -e "${C_GREEN}✔ Запись удалена.${C_RESET}"
    apply_relay_rules
    pause
}

show_stats() {
    print_header
    echo -e "${C_BOLD}${C_YELLOW}➜ Мониторинг трафика и статус${C_RESET}"
    echo ""
    render_table
    echo ""
    echo -e "${C_BOLD}Счётчики пакетов ядра (iptables NAT, цепочка $CHAIN_NAT_PRE):${C_RESET}"
    echo -e "${C_DIM}──────────────────────────────────────────────────────────────${C_RESET}"
    iptables -t nat -L "$CHAIN_NAT_PRE" -n -v --line-numbers 2>/dev/null || echo -e "${C_DIM}Цепочка ещё не создана — примени правила (пункт 5).${C_RESET}"
    pause
}

manage_swap() {
    while true; do
        print_header
        echo -e "${C_BOLD}${C_YELLOW}➜ Управление swap-файлом${C_RESET}"
        echo ""
        if swapon --show=NAME --noheadings 2>/dev/null | grep -qx "$SWAP_FILE"; then
            local CUR_SIZE
            CUR_SIZE=$(swapon --show=NAME,SIZE --noheadings 2>/dev/null | awk -v f="$SWAP_FILE" '$1==f{print $2}')
            echo -e "Статус: ${C_GREEN}включён${C_RESET} (${C_BOLD}$SWAP_FILE${C_RESET}, размер: ${C_GREEN}${CUR_SIZE:-?}${C_RESET})"
        else
            echo -e "Статус: ${C_RED}выключен${C_RESET}"
        fi
        echo ""
        echo -e "${C_DIM}Память и swap сейчас:${C_RESET}"
        free -h | sed -n '1,3p'
        echo ""
        echo -e "${C_BOLD}Действия:${C_RESET}"
        echo -e " ${C_GREEN}1)${C_RESET} Создать/пересоздать swap-файл (указать размер)"
        echo -e " ${C_RED}2)${C_RESET} Отключить и удалить swap-файл"
        echo -e " ${C_DIM}0)${C_RESET} Назад в меню"
        echo ""
        read -rp "$(echo -e "${C_BOLD}Выбери пункт [0-2]: ${C_RESET}")" SWAP_CHOICE

        case "$SWAP_CHOICE" in
            1) create_swap ;;
            2) disable_swap ;;
            0) return ;;
            *) echo -e "${C_RED}Неверный пункт.${C_RESET}"; sleep 1 ;;
        esac
    done
}

create_swap() {
    echo ""
    local SIZE_MB
    while true; do
        read -rp "$(echo -e "${C_BOLD}Размер swap в MB [${C_GREEN}1024${C_RESET}${C_BOLD}]: ${C_RESET}")" SIZE_MB
        SIZE_MB="${SIZE_MB:-1024}"
        if [[ "$SIZE_MB" =~ ^[0-9]+$ ]] && (( SIZE_MB >= 16 )); then
            break
        fi
        echo -e "${C_RED}✖ Введи целое число MB, минимум 16.${C_RESET}"
    done

    local AVAIL_KB NEEDED_KB
    AVAIL_KB=$(df --output=avail -k / | tail -n1 | tr -d ' ')
    NEEDED_KB=$(( SIZE_MB * 1024 ))
    if (( NEEDED_KB > AVAIL_KB )); then
        echo -e "${C_RED}✖ Недостаточно места: доступно $(( AVAIL_KB / 1024 )) MB, нужно $SIZE_MB MB.${C_RESET}"
        pause
        return
    fi

    if swapon --show=NAME --noheadings 2>/dev/null | grep -qx "$SWAP_FILE"; then
        echo -e "${C_YELLOW}⚙ Уже есть активный swap на $SWAP_FILE — отключаю перед пересозданием...${C_RESET}"
        swapoff "$SWAP_FILE" 2>/dev/null || true
    fi

    echo -e "${C_YELLOW}⚙ Создаю swap-файл ($SIZE_MB MB)...${C_RESET}"
    rm -f "$SWAP_FILE"

    if ! fallocate -l "${SIZE_MB}M" "$SWAP_FILE" 2>/dev/null; then
        echo -e "${C_DIM}  fallocate не сработал (бывает на некоторых ФС), использую dd...${C_RESET}"
        dd if=/dev/zero of="$SWAP_FILE" bs=1M count="$SIZE_MB" status=none
    fi

    chmod 600 "$SWAP_FILE"
    mkswap "$SWAP_FILE" > /dev/null
    swapon "$SWAP_FILE"

    if ! grep -qF "$SWAP_FILE" /etc/fstab 2>/dev/null; then
        echo "$SWAP_FILE none swap sw 0 0" >> /etc/fstab
    fi

    echo -e "${C_GREEN}✔ Swap-файл создан и включён ($SIZE_MB MB), запись добавлена в /etc/fstab.${C_RESET}"
    pause
}

disable_swap() {
    echo ""
    if ! swapon --show=NAME --noheadings 2>/dev/null | grep -qx "$SWAP_FILE"; then
        echo -e "${C_DIM}Swap-файл $SWAP_FILE и так не активен.${C_RESET}"
    else
        read -rp "$(echo -e "${C_BOLD}Точно отключить и удалить $SWAP_FILE? (y/n): ${C_RESET}")" SWAP_CONF
        if [[ ! "$SWAP_CONF" =~ ^[YyДд]$ ]]; then
            echo "Отменено."
            pause
            return
        fi
        swapoff "$SWAP_FILE" 2>/dev/null || true
    fi

    sed -i "\|^${SWAP_FILE}[[:space:]]|d" /etc/fstab 2>/dev/null || true
    rm -f "$SWAP_FILE"
    echo -e "${C_GREEN}✔ Swap-файл отключён и удалён, запись в /etc/fstab убрана.${C_RESET}"
    pause
}

change_ssh_port() {
    print_header
    echo -e "${C_BOLD}${C_YELLOW}➜ Указать актуальный SSH-порт для файрвола${C_RESET}"
    echo ""
    echo -e "${C_RED}⚠ ВНИМАНИЕ: это ТОЛЬКО открывает порт в iptables.${C_RESET}"
    echo -e "${C_RED}  Сам sshd (/etc/ssh/sshd_config, директива Port) этот пункт НЕ трогает.${C_RESET}"
    echo -e "${C_RED}  Если введёшь порт, на котором sshd реально не слушает —${C_RESET}"
    echo -e "${C_RED}  старый порт закроется, и ты рискуешь потерять доступ к серверу.${C_RESET}"
    echo -e "${C_DIM}  Сначала поменяй Port в sshd_config и перезапусти sshd,${C_RESET}"
    echo -e "${C_DIM}  и только потом синхронизируй значение здесь.${C_RESET}"
    echo -e "${C_DIM}  Старое ACCEPT-правило для прежнего порта останется в таблице —${C_RESET}"
    echo -e "${C_DIM}  оно не мешает, но при необходимости его можно убрать вручную.${C_RESET}"
    echo ""
    read -rp "$(echo -e "${C_BOLD}Введи актуальный SSH-порт [${C_GREEN}$SSH_PORT${C_RESET}${C_BOLD}]: ${C_RESET}")" NEW_SSH
    NEW_SSH="${NEW_SSH:-$SSH_PORT}"

    if [[ "$NEW_SSH" =~ $PORT_REGEX ]] && (( NEW_SSH >= 1 && NEW_SSH <= 65535 )); then
        read -rp "$(echo -e "${C_BOLD}Подтверди, что sshd уже слушает порт $NEW_SSH (y/n): ${C_RESET}")" SSH_CONFIRM
        if [[ ! "$SSH_CONFIRM" =~ ^[YyДд]$ ]]; then
            echo "Отменено."
            pause
            return
        fi
        SSH_PORT="$NEW_SSH"
        set_env_var SSH_PORT "$SSH_PORT"
        apply_all_rules || echo -e "${C_YELLOW}Изменения не были применены полностью.${C_RESET}"
    else
        echo -e "${C_RED}✖ Некорректный порт.${C_RESET}"
    fi
    pause
}

# ------------------------------------------------------------------------------
# Полное удаление: откатывает ТОЛЬКО то, что добавил сам скрипт. Правила
# сторонних систем (Docker/UFW/firewalld/Xray и т.п.) не трогаются.
# ------------------------------------------------------------------------------
uninstall_relay_manager() {
    print_header
    echo -e "${C_RED}${C_BOLD}══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_RED}${C_BOLD}           ПОЛНОЕ УДАЛЕНИЕ RELAY-MANAGER                       ${C_RESET}"
    echo -e "${C_RED}${C_BOLD}══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    echo -e "Будут отменены ${C_BOLD}только${C_RESET} изменения, сделанные этим скриптом:"
    echo -e "  • цепочки $CHAIN_NAT_PRE / $CHAIN_NAT_POST / $CHAIN_FWD и jump-правила на них;"
    echo -e "  • правила INPUT/FORWARD для lo, established/related, SSH-порта и"
    echo -e "    дополнительно разрешённых портов сторонних служб;"
    echo -e "  • политики INPUT/FORWARD/OUTPUT вернутся к значениям, которые были"
    echo -e "    ДО самого первого запуска скрипта на этом сервере;"
    echo -e "  • файл /etc/sysctl.d/99-relay.conf."
    echo ""
    echo -e "${C_DIM}Конфигурация, swap-файл и сам скрипт удаляются только по отдельному${C_RESET}"
    echo -e "${C_DIM}подтверждению ниже. Правила Docker/UFW/firewalld/Xray и т.п. не трогаются.${C_RESET}"
    echo ""

    # Подтверждение случайным числовым кодом — надёжнее фиксированного слова:
    # код каждый раз новый, поэтому его нельзя ввести "на автомате" или случайно
    # вставить из буфера обмена.
    local CONF_CODE CONF_INPUT
    CONF_CODE=$(( RANDOM % 9000 + 1000 ))
    read -rp "$(echo -e "${C_RED}${C_BOLD}Для подтверждения введи код ${CONF_CODE}: ${C_RESET}")" CONF_INPUT
    if [[ "$CONF_INPUT" != "$CONF_CODE" ]]; then
        echo "Код не совпадает. Отменено."
        pause
        return
    fi

    echo ""
    echo -e "${C_YELLOW}⚙ Удаляю jump-правила...${C_RESET}"
    while iptables -t nat -D PREROUTING -j "$CHAIN_NAT_PRE" 2>/dev/null; do :; done
    while iptables -t nat -D POSTROUTING -j "$CHAIN_NAT_POST" 2>/dev/null; do :; done
    while iptables -D FORWARD -j "$CHAIN_FWD" 2>/dev/null; do :; done

    echo -e "${C_YELLOW}⚙ Удаляю цепочки relay-manager...${C_RESET}"
    iptables -t nat -F "$CHAIN_NAT_PRE" 2>/dev/null || true
    iptables -t nat -X "$CHAIN_NAT_PRE" 2>/dev/null || true
    iptables -t nat -F "$CHAIN_NAT_POST" 2>/dev/null || true
    iptables -t nat -X "$CHAIN_NAT_POST" 2>/dev/null || true
    iptables -F "$CHAIN_FWD" 2>/dev/null || true
    iptables -X "$CHAIN_FWD" 2>/dev/null || true

    echo -e "${C_YELLOW}⚙ Удаляю базовые INPUT/FORWARD правила...${C_RESET}"
    while iptables -D INPUT -i lo -j ACCEPT 2>/dev/null; do :; done
    while iptables -D INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done
    while iptables -D INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null; do :; done
    while iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done

    while ip6tables -D INPUT -i lo -j ACCEPT 2>/dev/null; do :; done
    while ip6tables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done
    while ip6tables -D INPUT -p ipv6-icmp -j ACCEPT 2>/dev/null; do :; done
    while ip6tables -D INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null; do :; done

    if [[ -f "$EXTRA_PORTS_FILE" ]]; then
        echo -e "${C_YELLOW}⚙ Удаляю правила для дополнительно разрешённых портов...${C_RESET}"
        while IFS=: read -r xport xproto; do
            [[ -z "$xport" ]] && continue
            while iptables  -D INPUT -p "$xproto" --dport "$xport" -j ACCEPT 2>/dev/null; do :; done
            while ip6tables -D INPUT -p "$xproto" --dport "$xport" -j ACCEPT 2>/dev/null; do :; done
        done < "$EXTRA_PORTS_FILE"
    fi

    echo -e "${C_YELLOW}⚙ Восстанавливаю исходные политики цепочек...${C_RESET}"
    # shellcheck source=/dev/null
    [[ -f "$ENV_FILE" ]] && source "$ENV_FILE"
    iptables  -P INPUT   "${ORIG_INPUT_POLICY:-ACCEPT}"
    iptables  -P FORWARD "${ORIG_FORWARD_POLICY:-ACCEPT}"
    iptables  -P OUTPUT  "${ORIG_OUTPUT_POLICY:-ACCEPT}"
    ip6tables -P INPUT   "${ORIG6_INPUT_POLICY:-ACCEPT}"
    ip6tables -P FORWARD "${ORIG6_FORWARD_POLICY:-ACCEPT}"
    ip6tables -P OUTPUT  "${ORIG6_OUTPUT_POLICY:-ACCEPT}"

    netfilter-persistent save > /dev/null 2>&1 || true

    if [[ -f /etc/sysctl.d/99-relay.conf ]]; then
        rm -f /etc/sysctl.d/99-relay.conf
        sysctl --system > /dev/null 2>&1 || true
        echo -e "${C_GREEN}✔ sysctl-параметры relay-manager удалены.${C_RESET}"
    fi

    echo ""
    echo -e "${C_GREEN}✔ Правила firewall и sysctl откачены к исходному состоянию.${C_RESET}"
    echo ""

    read -rp "$(echo -e "${C_BOLD}Удалить swap-файл $SWAP_FILE (если он был создан через этот скрипт)? (y/N): ${C_RESET}")" SWAP_ANS
    if [[ "$SWAP_ANS" =~ ^[YyДд]$ ]]; then
        swapoff "$SWAP_FILE" 2>/dev/null || true
        sed -i "\|^${SWAP_FILE}[[:space:]]|d" /etc/fstab 2>/dev/null || true
        rm -f "$SWAP_FILE"
        echo -e "${C_GREEN}✔ Swap-файл удалён.${C_RESET}"
    fi

    read -rp "$(echo -e "${C_BOLD}Удалить конфигурацию и резервные копии ($CONF_DIR, $BACKUP_DIR)? (y/N): ${C_RESET}")" CONF_ANS
    if [[ "$CONF_ANS" =~ ^[YyДд]$ ]]; then
        rm -rf "$CONF_DIR" "$BACKUP_DIR"
        echo -e "${C_GREEN}✔ Конфигурация и бэкапы удалены.${C_RESET}"
    fi

    read -rp "$(echo -e "${C_BOLD}Удалить сам файл скрипта? (y/N): ${C_RESET}")" SELF_ANS
    if [[ "$SELF_ANS" =~ ^[YyДд]$ ]]; then
        local self_path
        self_path="$(readlink -f "$0" 2>/dev/null || echo "$0")"
        echo -e "${C_GREEN}✔ Удаляю $self_path и выхожу.${C_RESET}"
        rm -f -- "$self_path"
        exit 0
    fi

    echo ""
    echo -e "${C_GREEN}${C_BOLD}Готово. Relay-manager деинсталлирован.${C_RESET}"
    pause
}

save_pristine_state
init_system
load_or_ask_ssh_port

if ! setup_base_firewall; then
    rc=$?
    if (( rc == 2 )); then
        echo -e "${C_RED}Настройка отменена. Запусти скрипт снова, когда будешь готов.${C_RESET}"
        exit 1
    fi
fi

if [[ ! -s "$RELAYS_FILE" ]]; then
    add_relay
else
    apply_relay_rules
fi

while true; do
    print_header
    render_table
    echo ""
    echo -e "${C_BOLD}Доступные действия:${C_RESET}"
    echo -e " ${C_GREEN}1)${C_RESET} Добавить новый релей (TCP/UDP)"
    echo -e " ${C_RED}2)${C_RESET} Удалить релей"
    echo -e " ${C_CYAN}3)${C_RESET} Показать статистику трафика (iptables counters)"
    echo -e " ${C_YELLOW}4)${C_RESET} Изменить SSH-порт"
    echo -e " ${C_BLUE}5)${C_RESET} Принудительно переприменить правила"
    echo -e " ${C_CYAN}6)${C_RESET} Управление swap-файлом"
    echo -e " ${C_RED}7)${C_RESET} Полностью удалить relay-manager"
    echo -e " ${C_DIM}0)${C_RESET} Выход"
    echo ""
    read -rp "$(echo -e "${C_BOLD}Выбери пункт [0-7]: ${C_RESET}")" CHOICE

    case "$CHOICE" in
        1) add_relay ;;
        2) delete_relay ;;
        3) show_stats ;;
        4) change_ssh_port ;;
        5)
            print_header
            apply_all_rules || echo -e "${C_YELLOW}Изменения не были применены полностью.${C_RESET}"
            pause
            ;;
        6) manage_swap ;;
        7) uninstall_relay_manager ;;
        0)
            clear
            echo -e "${C_GREEN}Сессия завершена.${C_RESET}"
            exit 0
            ;;
        *)
            echo -e "${C_RED}Неверный пункт меню.${C_RESET}"
            sleep 1
            ;;
    esac
done
