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
        cp "$rendered_file" "$tmp_file"
    else
        {
            printf '{\n'
            printf '  "outbounds": '
            cat "$rendered_file"
            printf '\n}\n'
        } > "$tmp_file"
    fi
    printf '%s\n' "$tmp_file"
}

# write_wrapped_outbounds: как раньше — рендерит и сразу промоутит в
# target_file. Оставлена для обратной совместимости (не используется в этом
# файле после добавления pre-flight валидации, см. apply_generated_outbounds).
write_wrapped_outbounds() {
    tmp_file="$(render_wrapped_outbounds "$1" "$2")"
    mv "$tmp_file" "$2"
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

apply_generated_outbounds() {
    rendered_file="$1"
    outdir="$(dirname "$OUTBOUND_FILE")"
    if [ ! -d "$outdir" ]; then
        log_msg "ошибка: каталог для outbounds не найден: $outdir"
        return 1
    fi

    outbound_tmp="$(render_wrapped_outbounds "$rendered_file" "$OUTBOUND_FILE")"

    # Pre-flight валидация (как у mihomo/sing-box, apply_mihomo_generated/
    # apply_singbox_generated ниже): проверяем итоговый merge конфигурации
    # Xray ДО того, как заменить живой outbounds-файл. Xray собирает конфиг
    # из ВСЕХ *.json в --confdir, поэтому проверяем на теневой копии каталога,
    # не трогая реальный $outdir, пока не убедимся, что всё валидно.
    xray_bin="$(find_xray_bin)"
    if [ -n "$xray_bin" ]; then
        shadow_dir="$(mktemp -d)"
        cp -a "$outdir"/. "$shadow_dir"/ 2>/dev/null
        cp "$outbound_tmp" "$shadow_dir/$(basename "$OUTBOUND_FILE")"
        if ! "$xray_bin" -test -format json -confdir "$shadow_dir" >>"$LOG_FILE" 2>&1; then
            rm -rf "$shadow_dir"
            rm -f "$outbound_tmp"
            log_msg "ошибка: generated Xray config (outbounds) не прошёл проверку -test"
            return 1
        fi
        rm -rf "$shadow_dir"
    fi

    mv "$outbound_tmp" "$OUTBOUND_FILE" || {
        log_msg "ошибка: не удалось применить сгенерированный outbounds-файл"
        return 1
    }

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

apply_mihomo_generated() {
    single_links_file="$1"
    provider_file="${MIHOMO_PROVIDER_FILE:-$OUTBOUND_FILE}"
    config_file="${MIHOMO_CONFIG_FILE:-/etc/mihomo/tproxy-manager.yaml}"
    if [ ! -x "$PROXY2MIHOMO" ]; then
        log_msg "ошибка: не найден исполняемый конвертер $PROXY2MIHOMO"
        return 1
    fi
    provider_dir="$(dirname "$provider_file")"
    config_dir="$(dirname "$config_file")"
    mkdir -p "$provider_dir" "$config_dir" 2>/dev/null || {
        log_msg "ошибка: не удалось создать каталог managed-конфига Mihomo"
        return 1
    }
    provider_tmp="${provider_file}.tmp.$$"
    config_tmp="${config_file}.tmp.$$"
    if "$PROXY2MIHOMO" -r "$single_links_file" --provider > "$provider_tmp" \
        && "$PROXY2MIHOMO" -r "$single_links_file" --runtime --tproxy-port "$TPROXY_PORT" > "$config_tmp"; then
        mihomo_bin="$(command -v mihomo 2>/dev/null || true)"
        if [ -n "$mihomo_bin" ] && ! "$mihomo_bin" -t -f "$config_tmp" >> "$LOG_FILE" 2>&1; then
            rm -f "$provider_tmp" "$config_tmp"
            log_msg "ошибка: generated Mihomo config не прошёл проверку"
            return 1
        fi
        # A config this package did not generate is somebody's own profile:
        # providers, sniffer, GEOSITE rules. Replacing it without a copy destroyed
        # it silently on the first applied link, with no way back. Generated
        # configs carry the MATCH,TPROXY-MANAGER signature and are reproducible,
        # so only foreign ones are copied.
        #
        # The copy has ONE dedicated name rather than a dated .bak.*: this must not
        # be suppressed by unrelated backups the editor or the operator left in the
        # directory, and it must not accumulate a file per applied link. Written
        # once, then left alone -- it holds the last content that was not ours.
        config_backup="$config_file.pre-managed"
        backup_created=""
        if [ -s "$config_file" ] && [ ! -e "$config_backup" ] \
            && ! grep -q 'MATCH,TPROXY-MANAGER' "$config_file"; then
            if cp "$config_file" "$config_backup" 2>/dev/null; then
                backup_created=1
                log_msg "сохранена копия пользовательского конфига Mihomo перед заменой: $config_backup"
            else
                log_msg "ошибка: не удалось сохранить копию конфига Mihomo, замена отменена"
                rm -f "$provider_tmp" "$config_tmp"
                return 1
            fi
        fi
        if ! { mv "$provider_tmp" "$provider_file" && mv "$config_tmp" "$config_file"; }; then
            # The live config was not replaced, so the slot must not stay spent:
            # the next attempt has to be free to copy whatever is there by then.
            [ -n "$backup_created" ] && rm -f "$config_backup"
            rm -f "$provider_tmp" "$config_tmp"
            log_msg "ошибка: не удалось применить сгенерированный конфиг Mihomo"
            return 1
        fi
    else
        rm -f "$provider_tmp" "$config_tmp"
        log_msg "ошибка: не удалось сгенерировать managed-конфиг Mihomo"
        return 1
    fi
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

apply_singbox_generated() {
    single_links_file="$1"
    outbounds_file="${SINGBOX_OUTBOUNDS_FILE:-$OUTBOUND_FILE}"
    config_file="${SINGBOX_CONFIG_FILE:-/etc/sing-box/tproxy-manager.json}"
    if [ ! -x "$PROXY2SINGBOX" ]; then
        log_msg "ошибка: не найден исполняемый конвертер $PROXY2SINGBOX"
        return 1
    fi
    outbounds_dir="$(dirname "$outbounds_file")"
    config_dir="$(dirname "$config_file")"
    mkdir -p "$outbounds_dir" "$config_dir" 2>/dev/null || {
        log_msg "ошибка: не удалось создать каталог managed-конфига sing-box"
        return 1
    }
    outbounds_tmp="${outbounds_file}.tmp.$$"
    config_tmp="${config_file}.tmp.$$"
    if "$PROXY2SINGBOX" -r "$single_links_file" --outbounds > "$outbounds_tmp" \
        && "$PROXY2SINGBOX" -r "$single_links_file" --runtime --tproxy-port "$TPROXY_PORT" > "$config_tmp"; then
        singbox_bin="$(command -v sing-box 2>/dev/null || true)"
        if [ -n "$singbox_bin" ] && ! "$singbox_bin" check -c "$config_tmp" >> "$LOG_FILE" 2>&1; then
            rm -f "$outbounds_tmp" "$config_tmp"
            log_msg "ошибка: generated sing-box config не прошёл проверку"
            return 1
        fi
        # Same hazard as Mihomo above: this path is the managed config BY
        # CONVENTION, not by proof -- nothing stops an operator from writing it by
        # hand, and the first applied link would replace their work with no way
        # back.
        #
        # sing-box rejects unknown JSON fields, so the generated config cannot
        # carry a marker of its own; what identifies it is the inbound pair the
        # generator always emits. A hand-written config that copies both of those
        # tags is read as ours and loses its copy -- the same outcome as before
        # this check, and the only case it does not improve.
        config_backup="$config_file.pre-managed"
        backup_created=""
        if [ -s "$config_file" ] && [ ! -e "$config_backup" ] \
            && ! { grep -q '"mixed-in"' "$config_file" && grep -q '"tproxy-in"' "$config_file"; }; then
            if cp "$config_file" "$config_backup" 2>/dev/null; then
                backup_created=1
                log_msg "сохранена копия пользовательского конфига sing-box перед заменой: $config_backup"
            else
                log_msg "ошибка: не удалось сохранить копию конфига sing-box, замена отменена"
                rm -f "$outbounds_tmp" "$config_tmp"
                return 1
            fi
        fi
        if ! { mv "$outbounds_tmp" "$outbounds_file" && mv "$config_tmp" "$config_file"; }; then
            [ -n "$backup_created" ] && rm -f "$config_backup"
            rm -f "$outbounds_tmp" "$config_tmp"
            log_msg "ошибка: не удалось применить сгенерированный конфиг sing-box"
            return 1
        fi
    else
        rm -f "$outbounds_tmp" "$config_tmp"
        log_msg "ошибка: не удалось сгенерировать managed-конфиг sing-box"
        return 1
    fi
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
