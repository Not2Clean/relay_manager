# L4 Relay Manager

Bash-скрипт для настройки TCP/UDP-пробросов через `iptables`.

## Возможности

- TCP, UDP или TCP+UDP relay;
- DNAT на backend-сервер;
- ограничение новых подключений;
- сохранение правил после перезагрузки;
- просмотр счётчиков трафика;
- управление swap-файлом;
- автоматическое резервное копирование правил.

## Требования

- Debian или Ubuntu;
- права `root`;
- установленный `apt`;
- IPv4-адрес backend-сервера.

> ⚠️ Скрипт изменяет настройки firewall. Перед запуском убедитесь, что знаете текущий SSH-порт и имеете доступ к консоли сервера.

## Установка

```bash
sudo curl -fsSL https://raw.githubusercontent.com/Not2Clean/relay_manager/main/relay_install.bash \
  -o /usr/local/sbin/relay-manager && \
sudo chmod 755 /usr/local/sbin/relay-manager && \
sudo relay-manager
