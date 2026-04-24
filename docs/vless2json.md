# vless2json.sh

`vless2json.sh` — встроенный конвертер проекта для `WATCHDOG`.

Скрипт входит в пакет и устанавливается в:

- `/usr/bin/vless2json.sh`

Это штатный конвертер по умолчанию для `watchdog_vless2json`. Его задача простая:

1. прочитать файл со ссылками;
2. взять первую валидную VLESS-ссылку;
3. распарсить ссылку;
4. подставить её значения в JSON/JSONC-шаблон;
5. вывести итоговый JSON в `stdout`.

## Использование

```sh
vless2json.sh -r /etc/tproxy-manager/watchdog.links -t /etc/tproxy-manager/watchdog-outbound.template.jsonc
```

Обязательные аргументы:

- `-r <links_file>` — файл со ссылками;
- `-t <template_file>` — JSON/JSONC-шаблон.

Справка:

```sh
vless2json.sh --help
```

## Поведение

Скрипт:

- игнорирует пустые строки;
- игнорирует строки, начинающиеся с `#`;
- поддерживает строки вида `vless://...` и `vless://... # comment`;
- использует первую валидную VLESS-ссылку из файла;
- читает шаблон как JSONC;
- удаляет комментарии из шаблона перед разбором;
- печатает на выходе уже чистый JSON.

Это осознанное поведение. Для `WATCHDOG` при тестировании и применении всегда используется временный файл с одной ссылкой, поэтому пакетный конвертер не пытается “склеивать” несколько ссылок в один multi-outbound конфиг.

## Формат links_file

Поддерживаются строки:

```txt
vless://uuid@example.com:443?...#Comment
```

или

```txt
vless://uuid@example.com:443?... # Comment
```

Внешний комментарий после ` space # space ` используется только как fallback, если внутри самой ссылки нет `#fragment`.

## Поддерживаемые поля VLESS

Из ссылки извлекаются:

- `address`
- `port`
- `uuid`
- `encryption`
- `flow`
- `type` / `network`
- `security`
- `sni` / `serverName`
- `fp` / `fingerprint`
- `pbk` / `publicKey`
- `sid` / `shortId`
- `spx` / `spiderX`
- `headerType`
- `path`
- `host`
- `authority`
- `serviceName`
- `mode`
- `allowinsecure`
- `alpn`
- `#fragment` как `remarks`

## Плейсхолдеры шаблона

В шаблоне поддерживаются такие плейсхолдеры:

- `__REMARKS__`
- `__ADDRESS__`
- `__HOST__`
- `__PORT__`
- `__UUID__`
- `__USER_ID__`
- `__ENCRYPTION__`
- `__FLOW__`
- `__NETWORK__`
- `__TYPE__`
- `__SECURITY__`
- `__SERVER_NAME__`
- `__SNI__`
- `__FINGERPRINT__`
- `__FP__`
- `__PUBLIC_KEY__`
- `__PBK__`
- `__SHORT_ID__`
- `__SID__`
- `__SPIDER_X__`
- `__HEADER_TYPE__`
- `__PATH__`
- `__WS_PATH__`
- `__HOST_HEADER__`
- `__AUTHORITY__`
- `__SERVICE_NAME__`
- `__MODE__`
- `__ALLOW_INSECURE__`
- `__ALLOW_INSECURE_BOOL__`
- `__ALPN__`
- `__ALPN_ARRAY__`

## Типы подстановки

Если строка шаблона равна плейсхолдеру целиком, конвертер подставляет типизированное значение:

- `__PORT__` превращается в число;
- `__ALLOW_INSECURE_BOOL__` превращается в boolean;
- `__ALPN_ARRAY__` превращается в массив строк.

Если плейсхолдер встроен внутрь другой строки, подстановка выполняется как текстовая.

Пример:

```json
{
  "remarks": "__REMARKS__",
  "port": "__PORT__",
  "tls": "__SECURITY__",
  "label": "Node: __REMARKS__"
}
```

Результат:

```json
{
  "remarks": "My node",
  "port": 443,
  "tls": "reality",
  "label": "Node: My node"
}
```

## Базовый шаблон

Пакет поставляет seed-шаблон:

- `/usr/share/tproxy-manager/watchdog-outbound.template.jsonc`

При первом установочном прогоне он копируется в:

- `/etc/tproxy-manager/watchdog-outbound.template.jsonc`

Этот шаблон включает:

- основной `vless` outbound с `tag: proxy`;
- `freedom` outbound `direct`;
- `blackhole` outbound `block`.

Редактировать рабочую копию нужно в `/etc/tproxy-manager`, а не в `/usr/share`.

## Ограничения

- Встроенный конвертер не удаляет автоматически “лишние” блоки из шаблона. Если вы используете, например, не `reality`, а другой тип транспорта, шаблон должен соответствовать этому сам.
- Если в `links_file` несколько ссылок, используется только первая валидная.
- Если нужен другой формат генерации, можно переопределить `watchdog_vless2json` на свой скрипт.

## Связь с Watchdog

`WATCHDOG` использует `vless2json.sh` в двух местах:

1. для генерации рабочего `OUTBOUND_FILE`;
2. для генерации временного test-instance конфига.

Поэтому для штатной работы `WATCHDOG` пакетный `vless2json.sh`, outbound-шаблон и test-template должны быть согласованы между собой.
