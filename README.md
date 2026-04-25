> [!IMPORTANT]
> **Дисклеймер.** TPROXY Manager не является средством обхода блокировок, сокрытия действий пользователя или нарушения правил доступа к информационным ресурсам. Автор проекта выступает против использования программы для нарушения действующих законов любой страны. Этот проект предназначен для администрирования локального роутера: аккуратного управления маршрутами, прозрачной обработки трафика, технической оптимизации сетевой нагрузки и обслуживания собственных proxy-сервисов в рамках законных сценариев.

# TPROXY Manager for OpenWrt

TPROXY Manager — это LuCI-панель и набор системных скриптов для OpenWrt. Проект помогает управлять прозрачным перехватом трафика через `nftables`, списками обхода, конфигами Xray/Mihomo, GEO-базами и автоматическим переключением VLESS outbound через Watchdog.

Проект ориентирован на роутер, где proxy daemon уже установлен отдельно. Это может быть Xray, Mihomo или другой сервис, который умеет работать с подготовленными конфигами и списками.

Основные возможности:

- настройка TPROXY-правил и policy routing через LuCI;
- редактирование списков портов, адресов и источников трафика;
- управление сервисами Xray и Mihomo;
- редакторы JSON/JSONC и YAML с серверной проверкой перед сохранением;
- загрузка `geoip.dat` и `geosite.dat` из настраиваемых источников;
- cron-обновление GEO-баз;
- встроенный `vless2json.sh` для генерации outbound из VLESS-ссылок;
- Watchdog для проверки ссылок, исключения нерабочих узлов и автоматической ротации;
- сборка пакетов без OpenWrt SDK: `.ipk` для OpenWrt 24.10 и `.apk` для OpenWrt 25.12.

Низкоуровневая документация по TPROXY-движку: [docs/tproxy-doc.md](docs/tproxy-doc.md).  
Документация по встроенному VLESS-конвертеру: [docs/vless2json.md](docs/vless2json.md).

## Установка

Пакеты публикуются на GitHub Pages:

- OpenWrt 24.10: [https://rico-x.github.io/tproxy-manager/24.10/](https://rico-x.github.io/tproxy-manager/24.10/)
- OpenWrt 25.12: [https://rico-x.github.io/tproxy-manager/25.12/](https://rico-x.github.io/tproxy-manager/25.12/)

После установки откройте LuCI: `Network -> TPROXY Manager`.

Сначала проверьте версию OpenWrt:

```sh
cat /etc/openwrt_release
```

Выбор пакета зависит от ветки OpenWrt:

| Версия OpenWrt | Менеджер пакетов | Формат пакета | Feed |
| --- | --- | --- | --- |
| `24.10.x` и старее | `opkg` | `.ipk` | `/24.10/` |
| `25.12.x` и новее | `apk` | `.apk` | `/25.12/` |

Не смешивайте инструкции: OpenWrt 25.12 использует `apk`, поэтому команды `opkg` для этой ветки не подходят. OpenWrt 24.10 использует `opkg`, поэтому `apk add` на этой ветке обычно недоступен.

### OpenWrt 24.10.x

Для локальной установки скачайте `.ipk` из [последнего release](https://github.com/rico-x/tproxy-manager/releases/latest) и установите его:

```sh
opkg install /tmp/tproxy-manager.ipk
```

Для установки из feed:

```sh
wget -O /tmp/usign.pub https://rico-x.github.io/tproxy-manager/24.10/keys/usign.pub
opkg-key add /tmp/usign.pub
echo 'src/gz tproxy https://rico-x.github.io/tproxy-manager/24.10' >> /etc/opkg/customfeeds.conf
opkg update
opkg install tproxy-manager
```

### OpenWrt 25.12.x

Для локальной установки скачайте `.apk` из [последнего release](https://github.com/rico-x/tproxy-manager/releases/latest) и установите его:

```sh
apk add --allow-untrusted /tmp/tproxy-manager.apk
```

Для установки из feed:

```sh
wget -O /etc/apk/keys/tproxy-manager.pem https://rico-x.github.io/tproxy-manager/25.12/keys/tproxy-manager.pem
echo 'https://rico-x.github.io/tproxy-manager/25.12/packages.adb' > /etc/apk/repositories.d/customfeeds.list
apk update
apk add tproxy-manager
```

Если ключ feed уже добавлен, повторно скачивать его не нужно. Для обновления достаточно выполнить:

```sh
apk update
apk upgrade tproxy-manager
```

### Что делает установка

`postinst` выполняет начальную подготовку системы:

- запускает `/etc/uci-defaults/90_tproxy_manager`;
- создаёт `/etc/tproxy-manager`;
- создаёт `/usr/share/tproxy-manager`;
- создаёт базовые файлы списков;
- создаёт `/etc/tproxy-manager/geo-sources.conf`, если файл отсутствует или пустой;
- копирует watchdog-шаблоны в `/etc/tproxy-manager`, если их ещё нет;
- делает исполняемыми init.d-скрипты и `/usr/bin/vless2json.sh`;
- включает и запускает `/etc/init.d/tproxy-manager`;
- не включает и не запускает Watchdog без явного действия пользователя.

По умолчанию `geo-sources.conf` получает два источника:

```json
[
  {
    "dest": "/usr/share/tproxy-manager/geoip.dat",
    "url": "https://github.com/Loyalsoldier/geoip/releases/latest/download/geoip.dat",
    "name": "GeoIP"
  },
  {
    "dest": "/usr/share/tproxy-manager/geosite.dat",
    "url": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    "name": "GeoSite"
  }
]
```

После установки настройте ваш proxy daemon на каталог GEO-баз `/usr/share/tproxy-manager/`. Для Xray это обычно выглядит так:

```sh
uci set xray.config.datadir='/usr/share/tproxy-manager/'
uci commit xray
/etc/init.d/xray restart
```

Если ваш Xray установлен без UCI-обёртки, задайте аналогичный `datadir` в конфиге или параметрах запуска используемого init.d-сервиса.

## Вкладки LuCI

Вкладка `TPROXY` доступна всегда. Остальные вкладки включаются в сворачиваемом блоке `Дополнительные настройки`.

Доступные вкладки:

- `TPROXY`
- `XRAY`
- `MIHOMO`
- `Обновление геобаз`
- `WATCHDOG`

По умолчанию `WATCHDOG` выключен.

Если в редакторах есть несохранённые изменения, интерфейс предупреждает перед переключением вкладок.

## TPROXY

Вкладка `TPROXY` управляет прозрачным перехватом трафика и списками маршрутизации.

Здесь настраиваются:

- LAN-интерфейсы, с которых перехватывается трафик;
- IPv6;
- единый TPROXY-порт или отдельные TCP/UDP-порты;
- `fwmark` для TCP и UDP;
- routing table id для TCP и UDP;
- режим по портам: `bypass` или `only`;
- режим по источникам: `off`, `only`, `bypass`;
- пути до файлов списков.

Дефолтная `nftables` table проекта: `tp_mgr`.

Файлы списков:

- `/etc/tproxy-manager/tproxy-manager.ports`
- `/etc/tproxy-manager/tproxy-manager.v4`
- `/etc/tproxy-manager/tproxy-manager.v6`
- `/etc/tproxy-manager/tproxy-manager.src4.only`
- `/etc/tproxy-manager/tproxy-manager.src6.only`
- `/etc/tproxy-manager/tproxy-manager.src4.bypass`
- `/etc/tproxy-manager/tproxy-manager.src6.bypass`

Встроенный редактор позволяет править эти файлы прямо из LuCI. Для SRC-списков есть быстрое добавление IP из DHCP-аренд.

Допустимые строки в списках:

```txt
80
1000-2000
192.168.1.0/24
2001:db8::/32
# комментарий
```

После изменения настроек нажмите сохранение и перезапустите сервис `TPROXY` из вкладки или командой:

```sh
/etc/init.d/tproxy-manager restart
```

## XRAY

Вкладка `XRAY` нужна для базового обслуживания Xray из LuCI.

Возможности:

- запуск, остановка и автозапуск сервиса `xray`;
- просмотр общего `logread`;
- редактор `*.json` в `/etc/xray`;
- создание и удаление JSON-файлов;
- JSONC-валидация перед сохранением;
- проверка всей конфигурации через `xray -test -format json -confdir /etc/xray`.

Лог последней проверки:

```txt
/tmp/tproxy_manager_xray_test.log
```

## MIHOMO

Вкладка `MIHOMO` работает с YAML-конфигами Mihomo.

Возможности:

- запуск, остановка и автозапуск сервиса `mihomo`;
- просмотр общего `logread`;
- редактор `*.yaml` в `/etc/mihomo`;
- создание и удаление YAML-файлов;
- проверка выбранного конфига через `mihomo -t -f`;
- серверная валидация перед сохранением.

Если проверка YAML не проходит, файл не записывается на диск.

Лог последней проверки:

```txt
/tmp/tproxy_manager_mihomo_test.log
```

## Обновление геобаз

Модуль GEO работает с файлом:

```txt
/etc/tproxy-manager/geo-sources.conf
```

Он генерирует updater-скрипт:

```txt
/usr/bin/tproxy-manager-geo-update.sh
```

По умолчанию GEO-базы скачиваются в:

```txt
/usr/share/tproxy-manager/geoip.dat
/usr/share/tproxy-manager/geosite.dat
```

Во вкладке доступны:

- таблица источников `name / url / dest`;
- добавление, редактирование и удаление источников;
- обновление одного источника;
- обновление всех источников;
- JSON/JSONC-редактор полного списка;
- пересоздание updater-скрипта;
- настройка cron-расписания.

При сохранении JSON/JSONC проверяется сервером. Если синтаксис сломан, старый файл не затирается.

Cron проверяется по полям и диапазонам. Примеры:

```txt
0 5 * * *
*/30 * * * *
30 4 * * 0
0 3 1 * *
```

После первого обновления GEO-баз убедитесь, что ваш proxy daemon использует `/usr/share/tproxy-manager/` как каталог данных. Для Xray:

```sh
uci set xray.config.datadir='/usr/share/tproxy-manager/'
uci commit xray
/etc/init.d/xray restart
```

## WATCHDOG

Watchdog — это отдельная вкладка и отдельный сервис:

```txt
/etc/init.d/tproxy-manager-watchdog
/usr/bin/tproxy-manager-watchdog.sh
```

Он проверяет текущий proxy через `CHECK_URL`. Если проверка несколько раз подряд завершается ошибкой, Watchdog выбирает другую VLESS-ссылку, проверяет её отдельным test-instance, генерирует outbound и перезапускает указанный сервис.

Основной сценарий:

1. Заполните список VLESS-ссылок.
2. Нажмите `Проверить все ссылки`.
3. Убедитесь, что хотя бы часть ссылок живая.
4. При необходимости настройте outbound-шаблон.
5. При необходимости настройте test-template.
6. Запустите сервис Watchdog.

### Список VLESS-ссылок

Файл по умолчанию:

```txt
/etc/tproxy-manager/watchdog.links
```

Поддерживаемый формат:

```txt
vless://...#Комментарий
vless://... # внешний комментарий
```

В таблице показываются:

- комментарий;
- ссылка без комментария;
- статус `Живая / Не живая / Не проверялась`;
- время последней проверки;
- кнопки `Применить`, `Проверить`, `Ред.`, `Удалить`, `Вверх`, `Вниз`.

Под таблицей есть сворачиваемый массовый редактор `LINKS_FILE` для вставки большого числа ссылок.

### Режим выбора ссылки

Доступны два режима:

- `по порядку` — ссылки перебираются по списку циклически;
- `случайно` — кандидат выбирается случайно.

Можно включить временное исключение нерабочих ссылок. Тогда ссылка со статусом `dead` не участвует в автоматическом переключении до истечения заданного периода.

### Outbound-шаблон

Файл по умолчанию:

```txt
/etc/tproxy-manager/watchdog-outbound.template.jsonc
```

Watchdog не хранит outbound внутри shell-скрипта. Шаблон редактируется во вкладке и передаётся встроенному конвертеру:

```sh
vless2json.sh -r LINKS_FILE -t TEMPLATE_FILE
```

Встроенный конвертер находится здесь:

```txt
/usr/bin/vless2json.sh
```

Описание плейсхолдеров шаблона: [docs/vless2json.md](docs/vless2json.md).

### Test-template

Для проверки ссылок используется отдельный временный конфиг test-instance.

Файл по умолчанию:

```txt
/etc/tproxy-manager/watchdog-test-config.template.jsonc
```

Базовые плейсхолдеры:

- `__TEST_PORT__` — локальный порт временного SOCKS inbound;
- `__OUTBOUNDS__` — массив outbounds, полученный из конвертера;
- `__OUTBOUND_TAG__` — `tag` первого outbound.

Команда тестового запуска по умолчанию:

```sh
/usr/bin/xray -c {config}
```

Если используется не Xray, поменяйте и `TEST_COMMAND`, и test-template.

### Runtime-команды

```sh
/usr/bin/tproxy-manager-watchdog.sh status
/usr/bin/tproxy-manager-watchdog.sh once
/usr/bin/tproxy-manager-watchdog.sh check-all
/usr/bin/tproxy-manager-watchdog.sh test-rotate
/usr/bin/tproxy-manager-watchdog.sh reset
```

Логи и состояние:

```txt
/tmp/tproxy-manager-watchdog.log
/tmp/tproxy-manager-watchdog.state
/tmp/tproxy-manager-watchdog-links/*.state
```

## Полезные пути

| Назначение | Путь |
| --- | --- |
| UCI-конфиг | `/etc/config/tproxy-manager` |
| Основной init.d | `/etc/init.d/tproxy-manager` |
| Основной runtime | `/usr/bin/tproxy-manager.sh` |
| Watchdog init.d | `/etc/init.d/tproxy-manager-watchdog` |
| Watchdog runtime | `/usr/bin/tproxy-manager-watchdog.sh` |
| Watchdog internal libs | `/usr/libexec/tproxy-manager/watchdog/*` |
| VLESS-конвертер | `/usr/bin/vless2json.sh` |
| GEO updater | `/usr/bin/tproxy-manager-geo-update.sh` |
| Пользовательские списки | `/etc/tproxy-manager` |
| GEO datadir | `/usr/share/tproxy-manager` |
| Xray configs | `/etc/xray` |
| Mihomo configs | `/etc/mihomo` |

## Сборка

Пакет собирается напрямую из общего payload-корня:

```txt
pkg/tproxy-manager/
```

OpenWrt SDK не используется.

Скрипты:

```sh
./scripts/build-ipk.sh ./pkg/tproxy-manager ./dist/24.10 25.12.2-1 ./ipkg-build
./scripts/build-apk.sh ./pkg/tproxy-manager ./dist/25.12 25.12.2-r1 ./.apk-tools/apk.static
```

Получить `ipkg-build`:

```sh
curl -fsSL https://raw.githubusercontent.com/openwrt/openwrt/openwrt-24.10/scripts/ipkg-build -o ipkg-build
chmod +x ipkg-build
```

Получить `apk.static`:

```sh
./scripts/fetch-apk-static.sh ./.apk-tools/apk.static
```

`scripts/fetch-apk-static.sh` использует Docker и вытаскивает `apk.static` из `alpine:edge`.

## Скриншоты

Ссылки оставлены как плейсхолдеры. Замените файлы в `docs/screenshots/` своими изображениями или поменяйте пути в этом разделе.

- Главная панель: `docs/screenshots/placeholder-dashboard.png`
- Навигация: `docs/screenshots/placeholder-navigation.png`
- TPROXY: `docs/screenshots/placeholder-tproxy-main.png`
- XRAY: `docs/screenshots/placeholder-xray-editor.png`
- MIHOMO: `docs/screenshots/placeholder-mihomo-editor.png`
- GEO: `docs/screenshots/placeholder-geo-table.png`
- Watchdog overview: `docs/screenshots/placeholder-watchdog-overview.png`
- Watchdog links: `docs/screenshots/placeholder-watchdog-links.png`
- Watchdog outbounds template: `docs/screenshots/placeholder-watchdog-outbounds-template.png`
- Watchdog test template: `docs/screenshots/placeholder-watchdog-test-template.png`
- Watchdog settings: `docs/screenshots/placeholder-watchdog-settings.png`

## Рекомендации после установки

### Обновите GEO-базы

Откройте вкладку `Обновление геобаз` и нажмите `Обновить все`.

После этого настройте proxy daemon на datadir:

```sh
uci set xray.config.datadir='/usr/share/tproxy-manager/'
uci commit xray
/etc/init.d/xray restart
```

### Проверьте системные оптимизации

В пакет входят два вспомогательных скрипта:

```sh
/usr/bin/optimize-sysctl.sh
/usr/bin/setup-bbr.sh
```

`postinst` запускает их один раз без остановки установки при ошибках. После обновления ядра, смены прошивки или ручной правки sysctl их можно запустить повторно:

```sh
/usr/bin/optimize-sysctl.sh
/usr/bin/setup-bbr.sh
```

`optimize-sysctl.sh` записывает поддержанные параметры в `/etc/sysctl.d/66-tproxy-manager.conf`.  
`setup-bbr.sh` включает TCP BBR, если ядро и модуль `kmod-tcp-bbr` это поддерживают.

### Защитите DNS от утечек

Чтобы DNS-запросы не раскрывали реальные адреса через провайдера, рекомендуется установить HTTPS DNS proxy и LuCI-интерфейс:

OpenWrt 24.10:

```sh
opkg update
opkg install https-dns-proxy luci-app-https-dns-proxy luci-i18n-https-dns-proxy-ru
```

OpenWrt 25.12:

```sh
apk update
apk add https-dns-proxy luci-app-https-dns-proxy luci-i18n-https-dns-proxy-ru
```

После установки настройте провайдера DNS-over-HTTPS в LuCI и убедитесь, что клиенты LAN используют DNS роутера.

## Диагностика

Проверить TPROXY:

```sh
/etc/init.d/tproxy-manager status
/etc/init.d/tproxy-manager diag
```

Проверить Watchdog:

```sh
/usr/bin/tproxy-manager-watchdog.sh status
/usr/bin/tproxy-manager-watchdog.sh check-all
```

Проверить системные логи:

```sh
logread | tail -n 100
```
