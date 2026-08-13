# shellcheck shell=sh

probe_proxy_url() {
    proxy_url="$1"
    probe_proxy_url_with_time "$proxy_url" | awk -F '\t' '{print $1}'
}

probe_proxy_url_with_time() {
    proxy_url="$1"
    result="$(curl -sS -o /dev/null -w '%{http_code}\t%{time_total}' \
        --proxy "$proxy_url" \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$MAX_TIME" \
        "$CHECK_URL" 2>/dev/null)"
    rc=$?
    http_code="$(printf '%s\n' "$result" | awk -F '\t' '{print $1}')"
    time_total="$(printf '%s\n' "$result" | awk -F '\t' '{print $2}')"
    if [ $rc -ne 0 ] || ! validate_number "$http_code"; then
        http_code="000"
        request_ms=0
        request_text="timeout"
    else
        request_ms="$(awk -v t="$time_total" 'BEGIN { if (t ~ /^[0-9]+([.][0-9]+)?$/) printf "%d", (t * 1000) + 0.5; else printf "0" }')"
        validate_number "$request_ms" || request_ms=0
        request_text="${request_ms} ms"
    fi
    printf '%s\t%s\t%s\n' "$http_code" "$request_ms" "$request_text"
}

generate_rendered_config() {
    single_links_file="$1"
    rendered_file="$2"
    source_link="${3:-}"
    render_template="$(outbound_template_for_link "$source_link")"

    if [ ! -x "$VLESS2JSON" ]; then
        log_msg "ошибка: не найден исполняемый скрипт $VLESS2JSON"
        return 1
    fi
    if [ ! -f "$single_links_file" ]; then
        log_msg "ошибка: не найден файл ссылок $single_links_file"
        return 1
    fi
    if [ ! -f "$render_template" ]; then
        log_msg "ошибка: не найден файл шаблона $render_template"
        return 1
    fi

    if "$VLESS2JSON" -r "$single_links_file" -t "$render_template" > "$rendered_file"; then
        if grep -q '^[[:space:]]*\[[[:space:]]*$\|^[[:space:]]*\[' "$rendered_file" 2>/dev/null || grep -q '^[[:space:]]*{' "$rendered_file" 2>/dev/null; then
            return 0
        fi
        log_msg "ошибка: конвертер вернул неожидаемый формат шаблона/outbounds"
        return 1
    fi

    log_msg "ошибка: не удалось сгенерировать конфиг через $VLESS2JSON"
    return 1
}

extract_outbounds_array() {
    rendered_file="$1"
    array_file="$2"

    if grep -q '^[[:space:]]*\[' "$rendered_file" 2>/dev/null; then
        cp "$rendered_file" "$array_file"
        return 0
    fi

    if grep -q '^[[:space:]]*{' "$rendered_file" 2>/dev/null; then
        tmp_array="${array_file}.tmp.$$"
        if jsonfilter -i "$rendered_file" -e '@.outbounds' > "$tmp_array" 2>/dev/null && grep -q '^[[:space:]]*\[' "$tmp_array" 2>/dev/null; then
            mv "$tmp_array" "$array_file"
            return 0
        fi
        rm -f "$tmp_array"
    fi

    log_msg "ошибка: в сгенерированном конфиге нет валидного массива outbounds"
    return 1
}

first_outbound_tag() {
    tag="$(jsonfilter -i "$1" -e '@.outbounds[0].tag' 2>/dev/null | sed -n '1p')"
    [ -n "$tag" ] || tag="$(jsonfilter -a -i "$1" -e '@[0].tag' 2>/dev/null | sed -n '1p')"
    [ -n "$tag" ] || tag="$(grep -o '"tag"[[:space:]]*:[[:space:]]*"[^"]*"' "$1" 2>/dev/null | sed -n '1{s/.*:[[:space:]]*"\([^"]*\)"/\1/p}')"
    printf '%s\n' "$tag"
}

# render_wrapped_outbounds: только рендерит в tmp-файл рядом с target_file,
# НЕ подменяет живой файл — вызывающий код решает, промоутить ли его
# (после валидации), см. apply_generated_outbounds().
render_wrapped_outbounds() {
    rendered_file="$1"
    target_file="$2"
    tmp_file="${target_file}.tmp.$$"

    if grep -q '^[[:space:]]*{' "$rendered_file" 2>/dev/null; then
        cp "$rendered_file" "$tmp_file" || {
            rm -f "$tmp_file"
            return 1
        }
    else
        if ! {
            printf '{\n'
            printf '  "outbounds": '
            cat "$rendered_file"
            printf '\n}\n'
        } > "$tmp_file"; then
            rm -f "$tmp_file"
            return 1
        fi
    fi
    printf '%s\n' "$tmp_file"
}

# write_wrapped_outbounds: как раньше — рендерит и сразу промоутит в
# target_file. Оставлена для обратной совместимости (не используется в этом
# файле после добавления pre-flight валидации, см. apply_generated_outbounds).
write_wrapped_outbounds() {
    tmp_file="$(render_wrapped_outbounds "$1" "$2")" || return 1
    mv "$tmp_file" "$2" || { rm -f "$tmp_file"; return 1; }
}

# find_xray_bin: те же пути, что и get_xray_bin() в xray.lua.
find_xray_bin() {
    if command -v xray >/dev/null 2>&1; then
        command -v xray
    elif [ -x "/usr/bin/xray" ]; then
        printf '%s\n' "/usr/bin/xray"
    elif [ -x "/usr/sbin/xray" ]; then
        printf '%s\n' "/usr/sbin/xray"
    fi
}

render_test_config() {
    array_file="$1"
    config_file="$2"
    port="$3"
    source_link="${4:-}"
    test_template="$(test_template_for_link "$source_link")"

    if [ ! -f "$test_template" ]; then
        log_msg "ошибка: не найден тестовый шаблон $test_template"
        return 1
    fi

    first_tag="$(first_outbound_tag "$array_file")"
    [ -n "$first_tag" ] || first_tag="proxy"
    port_esc="$(printf '%s' "$port" | sed 's/[\/&]/\\&/g')"
    tag_esc="$(printf '%s' "$first_tag" | sed 's/[\/&]/\\&/g')"
    : > "$config_file"
    while IFS= read -r line || [ -n "$line" ]; do
        rendered_line="$(printf '%s\n' "$line" | sed \
            -e "s/__TEST_PORT__/$port_esc/g" \
            -e "s/__OUTBOUND_TAG__/$tag_esc/g")"
        case "$rendered_line" in
            *"__OUTBOUNDS__"*)
                prefix="${rendered_line%%__OUTBOUNDS__*}"
                suffix="${rendered_line#*__OUTBOUNDS__}"
                printf '%s' "$prefix" >> "$config_file"
                cat "$array_file" >> "$config_file"
                printf '%s\n' "$suffix" >> "$config_file"
                ;;
            *)
                printf '%s\n' "$rendered_line" >> "$config_file"
                ;;
        esac
    done < "$test_template"
}

# Перезапуск активного ядра после подмены управляемого фрагмента. Одна функция на
# три пути применения: раньше это было переписано в каждом, и вызов из mihomo/
# sing-box ссылался на функцию, которой не существовало.
restart_engine_service() {
    if [ ! -x "$SERVICE_PATH" ]; then
        log_msg "ошибка: сервис не найден или не исполняем: $SERVICE_PATH"
        return 1
    fi
    if "$SERVICE_PATH" "$RESTART_CMD"; then
        return 0
    fi
    log_msg "ошибка: команда рестарта завершилась неуспешно: $SERVICE_PATH $RESTART_CMD"
    return 1
}

restore_previous_file() {
    restore_target="$1"
    restore_backup="$2"
    restore_existed="$3"
    if [ "$restore_existed" = "1" ]; then
        cp -p "$restore_backup" "$restore_target"
    else
        rm -f "$restore_target"
    fi
}

apply_mihomo_legacy() {
    single_links_file="$1"
    provider_file="${MIHOMO_PROVIDER_FILE:-$OUTBOUND_FILE}"
    config_file="${MIHOMO_CONFIG_FILE:-/etc/mihomo/tproxy-manager.yaml}"
    mkdir -p "$(dirname "$provider_file")" "$(dirname "$config_file")" 2>/dev/null || {
        log_msg "ошибка: не удалось создать каталог legacy-конфига Mihomo"
        return 1
    }
    provider_tmp="${provider_file}.tmp.$$"
    config_tmp="${config_file}.tmp.$$"
    set -- "$PROXY2MIHOMO" -r "$single_links_file" \
        --vless-template "$MIHOMO_VLESS_OUTBOUND_TEMPLATE_FILE" \
        --hy2-template "$MIHOMO_HY2_OUTBOUND_TEMPLATE_FILE"
    if ! "$@" --provider > "$provider_tmp" 2>>"$LOG_FILE" \
        || ! "$@" --runtime --tproxy-port "$TPROXY_PORT" > "$config_tmp" 2>>"$LOG_FILE"; then
        rm -f "$provider_tmp" "$config_tmp"
        log_msg "ошибка: не удалось сгенерировать legacy-конфиг Mihomo"
        return 1
    fi
    mihomo_bin="$(command -v mihomo 2>/dev/null || true)"
    if [ ! -x "$mihomo_bin" ] \
        || ! "$mihomo_bin" -d "$(dirname "$config_file")" -t -f "$config_tmp" >>"$LOG_FILE" 2>&1; then
        rm -f "$provider_tmp" "$config_tmp"
        log_msg "ошибка: generated legacy-конфиг Mihomo не прошёл проверку"
        return 1
    fi

    config_backup="$config_file.pre-managed"
    backup_created=""
    if [ -s "$config_file" ] && [ ! -e "$config_backup" ] \
        && ! grep -q 'MATCH,TPROXY-MANAGER' "$config_file"; then
        cp -p "$config_file" "$config_backup" || {
            rm -f "$provider_tmp" "$config_tmp"
            log_msg "ошибка: не удалось сохранить пользовательский конфиг Mihomo"
            return 1
        }
        backup_created=1
    fi
    provider_rollback="${provider_file}.rollback.$$"
    config_rollback="${config_file}.rollback.$$"
    provider_existed=0; config_existed=0
    if [ -e "$provider_file" ]; then
        cp -p "$provider_file" "$provider_rollback" || {
            [ -n "$backup_created" ] && rm -f "$config_backup"
            rm -f "$provider_tmp" "$config_tmp" "$provider_rollback"
            return 1
        }
        provider_existed=1
    fi
    if [ -e "$config_file" ]; then
        cp -p "$config_file" "$config_rollback" || {
            [ -n "$backup_created" ] && rm -f "$config_backup"
            rm -f "$provider_tmp" "$config_tmp" "$provider_rollback" "$config_rollback"
            return 1
        }
        config_existed=1
    fi
    if ! mv "$provider_tmp" "$provider_file" || ! mv "$config_tmp" "$config_file"; then
        restore_previous_file "$provider_file" "$provider_rollback" "$provider_existed" || true
        restore_previous_file "$config_file" "$config_rollback" "$config_existed" || true
        [ -n "$backup_created" ] && rm -f "$config_backup"
        rm -f "$provider_tmp" "$config_tmp" "$provider_rollback" "$config_rollback"
        log_msg "ошибка: не удалось атомарно применить legacy-конфиг Mihomo"
        return 1
    fi
    if ! restart_engine_service; then
        restore_previous_file "$provider_file" "$provider_rollback" "$provider_existed" || true
        restore_previous_file "$config_file" "$config_rollback" "$config_existed" || true
        restart_engine_service >/dev/null 2>&1 || true
        [ -n "$backup_created" ] && rm -f "$config_backup"
        rm -f "$provider_rollback" "$config_rollback"
        return 1
    fi
    rm -f "$provider_rollback" "$config_rollback"
    return 0
}

apply_singbox_legacy() {
    single_links_file="$1"
    outbounds_file="${SINGBOX_OUTBOUNDS_FILE:-$OUTBOUND_FILE}"
    config_file="${SINGBOX_CONFIG_FILE:-/etc/sing-box/tproxy-manager.json}"
    mkdir -p "$(dirname "$outbounds_file")" "$(dirname "$config_file")" 2>/dev/null || {
        log_msg "ошибка: не удалось создать каталог legacy-конфига sing-box"
        return 1
    }
    outbounds_tmp="${outbounds_file}.tmp.$$"
    config_tmp="${config_file}.tmp.$$"
    set -- "$PROXY2SINGBOX" -r "$single_links_file" \
        --vless-template "$SINGBOX_VLESS_OUTBOUND_TEMPLATE_FILE" \
        --hy2-template "$SINGBOX_HY2_OUTBOUND_TEMPLATE_FILE"
    if ! "$@" --outbounds > "$outbounds_tmp" 2>>"$LOG_FILE" \
        || ! "$@" --runtime --tproxy-port "$TPROXY_PORT" > "$config_tmp" 2>>"$LOG_FILE"; then
        rm -f "$outbounds_tmp" "$config_tmp"
        log_msg "ошибка: не удалось сгенерировать legacy-конфиг sing-box"
        return 1
    fi
    singbox_bin="$(command -v sing-box 2>/dev/null || true)"
    if [ ! -x "$singbox_bin" ] || ! "$singbox_bin" check -c "$config_tmp" >>"$LOG_FILE" 2>&1; then
        rm -f "$outbounds_tmp" "$config_tmp"
        log_msg "ошибка: generated legacy-конфиг sing-box не прошёл проверку"
        return 1
    fi

    config_backup="$config_file.pre-managed"
    backup_created=""
    if [ -s "$config_file" ] && [ ! -e "$config_backup" ] \
        && ! { grep -q '"mixed-in"' "$config_file" && grep -q '"tproxy-in"' "$config_file"; }; then
        cp -p "$config_file" "$config_backup" || {
            rm -f "$outbounds_tmp" "$config_tmp"
            log_msg "ошибка: не удалось сохранить пользовательский конфиг sing-box"
            return 1
        }
        backup_created=1
    fi
    outbounds_rollback="${outbounds_file}.rollback.$$"
    config_rollback="${config_file}.rollback.$$"
    outbounds_existed=0; config_existed=0
    if [ -e "$outbounds_file" ]; then
        cp -p "$outbounds_file" "$outbounds_rollback" || {
            [ -n "$backup_created" ] && rm -f "$config_backup"
            rm -f "$outbounds_tmp" "$config_tmp" "$outbounds_rollback"
            return 1
        }
        outbounds_existed=1
    fi
    if [ -e "$config_file" ]; then
        cp -p "$config_file" "$config_rollback" || {
            [ -n "$backup_created" ] && rm -f "$config_backup"
            rm -f "$outbounds_tmp" "$config_tmp" "$outbounds_rollback" "$config_rollback"
            return 1
        }
        config_existed=1
    fi
    if ! mv "$outbounds_tmp" "$outbounds_file" || ! mv "$config_tmp" "$config_file"; then
        restore_previous_file "$outbounds_file" "$outbounds_rollback" "$outbounds_existed" || true
        restore_previous_file "$config_file" "$config_rollback" "$config_existed" || true
        [ -n "$backup_created" ] && rm -f "$config_backup"
        rm -f "$outbounds_tmp" "$config_tmp" "$outbounds_rollback" "$config_rollback"
        log_msg "ошибка: не удалось атомарно применить legacy-конфиг sing-box"
        return 1
    fi
    if ! restart_engine_service; then
        restore_previous_file "$outbounds_file" "$outbounds_rollback" "$outbounds_existed" || true
        restore_previous_file "$config_file" "$config_rollback" "$config_existed" || true
        restart_engine_service >/dev/null 2>&1 || true
        [ -n "$backup_created" ] && rm -f "$config_backup"
        rm -f "$outbounds_rollback" "$config_rollback"
        return 1
    fi
    rm -f "$outbounds_rollback" "$config_rollback"
    return 0
}

apply_generated_outbounds() {
    rendered_file="$1"
    outdir="$(dirname "$OUTBOUND_FILE")"
    if [ ! -d "$outdir" ]; then
        log_msg "ошибка: каталог для outbounds не найден: $outdir"
        return 1
    fi

    outbound_tmp="$(render_wrapped_outbounds "$rendered_file" "$OUTBOUND_FILE")" || {
        log_msg "ошибка: не удалось подготовить сгенерированный outbounds-файл"
        return 1
    }

    # Pre-flight валидация (как у mihomo/sing-box, apply_mihomo_generated/
    # apply_singbox_generated ниже): проверяем итоговый merge конфигурации
    # Xray ДО того, как заменить живой outbounds-файл. Xray собирает конфиг
    # из ВСЕХ *.json в --confdir, поэтому проверяем на теневой копии каталога,
    # не трогая реальный $outdir, пока не убедимся, что всё валидно.
    xray_bin="$(find_xray_bin)"
    if [ -z "$xray_bin" ]; then
        rm -f "$outbound_tmp"
        log_msg "ошибка: не найден исполняемый файл Xray для проверки конфигурации"
        return 1
    fi
    shadow_dir="$(mktemp -d /tmp/tproxy-manager-xray.XXXXXX)" || {
        rm -f "$outbound_tmp"
        log_msg "ошибка: не удалось создать временный каталог Xray"
        return 1
    }
    if ! cp -a "$outdir"/. "$shadow_dir"/ 2>>"$LOG_FILE" \
        || ! cp "$outbound_tmp" "$shadow_dir/$(basename "$OUTBOUND_FILE")" 2>>"$LOG_FILE"; then
        rm -rf "$shadow_dir"
        rm -f "$outbound_tmp"
        log_msg "ошибка: не удалось подготовить теневой каталог Xray"
        return 1
    fi
    if ! "$xray_bin" -test -format json -confdir "$shadow_dir" >>"$LOG_FILE" 2>&1; then
        rm -rf "$shadow_dir"
        rm -f "$outbound_tmp"
        log_msg "ошибка: generated Xray config (outbounds) не прошёл проверку -test"
        return 1
    fi
    rm -rf "$shadow_dir"

    outbound_backup="${OUTBOUND_FILE}.rollback.$$"
    outbound_existed=0
    if [ -e "$OUTBOUND_FILE" ]; then
        cp -p "$OUTBOUND_FILE" "$outbound_backup" || {
            rm -f "$outbound_tmp" "$outbound_backup"
            log_msg "ошибка: не удалось сохранить предыдущий outbounds-файл"
            return 1
        }
        outbound_existed=1
    fi

    mv "$outbound_tmp" "$OUTBOUND_FILE" || {
        rm -f "$outbound_backup"
        log_msg "ошибка: не удалось применить сгенерированный outbounds-файл"
        return 1
    }

    if ! restart_engine_service; then
        restore_previous_file "$OUTBOUND_FILE" "$outbound_backup" "$outbound_existed" \
            || log_msg "ошибка: не удалось восстановить предыдущий outbounds-файл Xray"
        restart_engine_service >/dev/null 2>&1 || true
        rm -f "$outbound_backup"
        return 1
    fi
    rm -f "$outbound_backup"
    return 0
}

apply_mihomo_generated() {
    single_links_file="$1"
    # Ровно один файл: тот, что подключён провайдером из каталога фрагментов.
    # Скелетон, пользовательские прокси, группы и правила принадлежат пользователю
    # и здесь не трогаются -- раньше перезаписывался весь конфиг, и рукописный
    # профиль пропадал целиком.
    managed_file="${MIHOMO_MANAGED_FILE:-${MIHOMO_PROVIDER_FILE:-$OUTBOUND_FILE}}"
    if [ ! -x "$PROXY2MIHOMO" ]; then
        log_msg "ошибка: не найден конвертер $PROXY2MIHOMO"
        return 1
    fi
    if [ ! -f "$MIHOMO_VLESS_OUTBOUND_TEMPLATE_FILE" ] || [ ! -f "$MIHOMO_HY2_OUTBOUND_TEMPLATE_FILE" ]; then
        log_msg "ошибка: не найдены outbound-шаблоны Mihomo"
        return 1
    fi
    if [ ! -d "$MIHOMO_CONFIG_DIR" ]; then
        apply_mihomo_legacy "$single_links_file"
        return $?
    fi
    mkdir -p "$(dirname "$managed_file")" 2>/dev/null || {
        log_msg "ошибка: не удалось создать каталог для $managed_file"
        return 1
    }
    managed_tmp="${managed_file}.tmp.$$"
    set -- "$PROXY2MIHOMO" -r "$single_links_file" --provider \
        --vless-template "$MIHOMO_VLESS_OUTBOUND_TEMPLATE_FILE" \
        --hy2-template "$MIHOMO_HY2_OUTBOUND_TEMPLATE_FILE"
    if ! "$@" > "$managed_tmp" 2>>"$LOG_FILE"; then
        rm -f "$managed_tmp"
        log_msg "ошибка: не удалось сгенерировать управляемый фрагмент Mihomo"
        return 1
    fi
    assembler="${ASSEMBLE_CONFIG:-/usr/libexec/tproxy-manager/assemble-config}"
    if [ ! -x "$assembler" ]; then
        rm -f "$managed_tmp"
        log_msg "ошибка: не найден сборщик конфигурации Mihomo"
        return 1
    fi
    if ! TPM_MIHOMO_MANAGED_CANDIDATE="$managed_tmp" "$assembler" mihomo --check >>"$LOG_FILE" 2>&1; then
        rm -f "$managed_tmp"
        log_msg "ошибка: полная конфигурация Mihomo с новым provider не прошла проверку"
        return 1
    fi

    managed_backup="${managed_file}.rollback.$$"
    managed_existed=0
    if [ -e "$managed_file" ]; then
        cp -p "$managed_file" "$managed_backup" || {
            rm -f "$managed_tmp" "$managed_backup"
            log_msg "ошибка: не удалось сохранить предыдущий provider Mihomo"
            return 1
        }
        managed_existed=1
    fi
    if ! mv "$managed_tmp" "$managed_file"; then
        rm -f "$managed_tmp" "$managed_backup"
        log_msg "ошибка: не удалось применить управляемый фрагмент Mihomo"
        return 1
    fi
    if ! "$assembler" mihomo >>"$LOG_FILE" 2>&1; then
        restore_previous_file "$managed_file" "$managed_backup" "$managed_existed" || true
        "$assembler" mihomo >>"$LOG_FILE" 2>&1 || true
        rm -f "$managed_backup"
        log_msg "ошибка: не удалось собрать рабочую конфигурацию Mihomo; provider восстановлен"
        return 1
    fi
    if ! restart_engine_service; then
        restore_previous_file "$managed_file" "$managed_backup" "$managed_existed" || true
        "$assembler" mihomo >>"$LOG_FILE" 2>&1 || true
        restart_engine_service >/dev/null 2>&1 || true
        rm -f "$managed_backup"
        return 1
    fi
    rm -f "$managed_backup"
    return 0
}

apply_singbox_generated() {
    single_links_file="$1"
    # Тот же принцип: пишется только управляемый фрагмент каталога. sing-box
    # сливает массивы между фрагментами сам, поэтому пользовательские outbound
    # из своего файла остаются на месте.
    managed_file="${SINGBOX_MANAGED_FILE:-${SINGBOX_OUTBOUNDS_FILE:-$OUTBOUND_FILE}}"
    if [ ! -x "$PROXY2SINGBOX" ]; then
        log_msg "ошибка: не найден конвертер $PROXY2SINGBOX"
        return 1
    fi
    if [ ! -f "$SINGBOX_VLESS_OUTBOUND_TEMPLATE_FILE" ] || [ ! -f "$SINGBOX_HY2_OUTBOUND_TEMPLATE_FILE" ]; then
        log_msg "ошибка: не найдены outbound-шаблоны sing-box"
        return 1
    fi
    if [ ! -d "$SINGBOX_CONFIG_DIR" ]; then
        apply_singbox_legacy "$single_links_file"
        return $?
    fi
    mkdir -p "$(dirname "$managed_file")" 2>/dev/null || {
        log_msg "ошибка: не удалось создать каталог для $managed_file"
        return 1
    }
    managed_tmp="${managed_file}.tmp.$$"
    set -- "$PROXY2SINGBOX" -r "$single_links_file" --outbounds \
        --vless-template "$SINGBOX_VLESS_OUTBOUND_TEMPLATE_FILE" \
        --hy2-template "$SINGBOX_HY2_OUTBOUND_TEMPLATE_FILE"
    outbounds_tmp="${managed_tmp}.outbounds"
    if ! "$@" > "$outbounds_tmp" 2>>"$LOG_FILE"; then
        rm -f "$managed_tmp" "$outbounds_tmp"
        log_msg "ошибка: не удалось сгенерировать outbound sing-box"
        return 1
    fi
    # Фрагмент каталога -- объект с ключом outbounds, а не голый массив: слияние
    # у sing-box идёт по ключам верхнего уровня.
    {
        printf '{\n  "outbounds": '
        cat "$outbounds_tmp"
        printf '\n}\n'
    } > "$managed_tmp" 2>>"$LOG_FILE" || {
        rm -f "$managed_tmp" "$outbounds_tmp"
        log_msg "ошибка: не удалось сгенерировать управляемый фрагмент sing-box"
        return 1
    }
    rm -f "$outbounds_tmp"

    singbox_bin="$(command -v sing-box 2>/dev/null || true)"
    if [ ! -x "$singbox_bin" ]; then
        rm -f "$managed_tmp"
        log_msg "ошибка: не найден исполняемый файл sing-box для проверки конфигурации"
        return 1
    fi
    shadow_dir="$(mktemp -d /tmp/tproxy-manager-singbox.XXXXXX)" || {
        rm -f "$managed_tmp"
        log_msg "ошибка: не удалось создать временный каталог sing-box"
        return 1
    }
    if ! cp -a "$SINGBOX_CONFIG_DIR"/. "$shadow_dir"/ 2>>"$LOG_FILE" \
        || ! cp "$managed_tmp" "$shadow_dir/$(basename "$managed_file")" 2>>"$LOG_FILE"; then
        rm -rf "$shadow_dir"
        rm -f "$managed_tmp"
        log_msg "ошибка: не удалось подготовить теневой каталог sing-box"
        return 1
    fi
    if ! "$singbox_bin" check -C "$shadow_dir" >>"$LOG_FILE" 2>&1; then
        rm -rf "$shadow_dir"
        rm -f "$managed_tmp"
        log_msg "ошибка: полная конфигурация sing-box с новым outbound не прошла проверку"
        return 1
    fi
    rm -rf "$shadow_dir"

    managed_backup="${managed_file}.rollback.$$"
    managed_existed=0
    if [ -e "$managed_file" ]; then
        cp -p "$managed_file" "$managed_backup" || {
            rm -f "$managed_tmp" "$managed_backup"
            log_msg "ошибка: не удалось сохранить предыдущий outbound sing-box"
            return 1
        }
        managed_existed=1
    fi
    if ! mv "$managed_tmp" "$managed_file"; then
        rm -f "$managed_tmp" "$managed_backup"
        log_msg "ошибка: не удалось применить управляемый фрагмент sing-box"
        return 1
    fi
    if ! restart_engine_service; then
        restore_previous_file "$managed_file" "$managed_backup" "$managed_existed" || true
        restart_engine_service >/dev/null 2>&1 || true
        rm -f "$managed_backup"
        return 1
    fi
    rm -f "$managed_backup"
    return 0
}

apply_link_runtime() {
    hash="$1"
    link="$2"

    probe_link_runtime "$hash" "$link" || {
        log_msg "ссылка $hash не прошла тест, применение отменено"
        return 1
    }

    single_links_file="$TEST_DIR/one-link.txt"
    case "$PROXY_ENGINE" in
        mihomo)
            apply_mihomo_generated "$single_links_file" || return 1
            set_last_success_hash "$hash"
            set_last_applied_hash "$hash"
            return 0
            ;;
        singbox)
            apply_singbox_generated "$single_links_file" || return 1
            set_last_success_hash "$hash"
            set_last_applied_hash "$hash"
            return 0
            ;;
    esac

    rendered_file="$TEST_DIR/rendered.json"
    [ -f "$rendered_file" ] || return 1
    apply_generated_outbounds "$rendered_file" || return 1
    set_last_success_hash "$hash"
    set_last_applied_hash "$hash"
    return 0
}
