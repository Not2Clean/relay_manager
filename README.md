# L4 Relay Manager

Bash-скрипт для настройки TCP/UDP-пробросов через `iptables`.

## Возможности

- TCP, UDP или TCP+UDP relay;
- DNAT-проброс на backend-сервер;
- ограничение новых подключений;
- сохранение правил после перезагрузки;
- просмотр счётчиков трафика;
- управление swap-файлом;
- автоматическое создание резервных копий.

## Требования

- Debian или Ubuntu;
- доступ к серверу через `root` или `sudo`;
- установленный `apt`;
- IPv4-адрес backend-сервера.

> ⚠️ Скрипт изменяет настройки firewall. Перед запуском проверьте текущий SSH-порт и убедитесь, что у вас есть доступ к консоли сервера.

## Установка

Выполните одну команду:

```bash
sudo curl -fsSL https://raw.githubusercontent.com/Not2Clean/relay_manager/main/relay_install.bash \
  -o /usr/local/sbin/relay-manager && \
sudo chmod 755 /usr/local/sbin/relay-manager && \
sudo relay-manager
```

Если нет доступа к `sudo`, установите в домашнюю директорию:

```bash
curl -fsSL https://raw.githubusercontent.com/Not2Clean/relay_manager/main/relay_install.bash \
  -o ~/.local/bin/relay-manager && \
chmod 755 ~/.local/bin/relay-manager && \
~/.local/bin/relay-manager
```
​```
