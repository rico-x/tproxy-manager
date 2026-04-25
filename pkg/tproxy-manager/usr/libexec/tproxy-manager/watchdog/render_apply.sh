# shellcheck shell=sh

probe_proxy_url() {
    proxy_url="$1"
    http_code="$(curl -sS -o /dev/null -w '%{http_code}' \
        --proxy "$proxy_url" \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$MAX_TIME" \
        "$CHECK_URL" 2>/dev/null)"
    if [ $? -ne 0 ] || ! validate_number "$http_code"; then
        http_code="000"
    fi
    printf '%s\n' "$http_code"
}

generate_rendered_config() {
    single_links_file="$1"
    rendered_file="$2"

    if [ ! -x "$VLESS2JSON" ]; then
        log_msg "ошибка: не найден исполняемый скрипт $VLESS2JSON"
        return 1
    fi
    if [ ! -f "$single_links_file" ]; then
        log_msg "ошибка: не найден файл ссылок $single_links_file"
        return 1
    fi
    if [ ! -f "$TEMPLATE_FILE" ]; then
        log_msg "ошибка: не найден файл шаблона $TEMPLATE_FILE"
        return 1
    fi

    if "$VLESS2JSON" -r "$single_links_file" -t "$TEMPLATE_FILE" > "$rendered_file"; then
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

write_wrapped_outbounds() {
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
    mv "$tmp_file" "$target_file"
}

render_test_config() {
    array_file="$1"
    config_file="$2"
    port="$3"

    if [ ! -f "$TEST_TEMPLATE_FILE" ]; then
        log_msg "ошибка: не найден тестовый шаблон $TEST_TEMPLATE_FILE"
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
    done < "$TEST_TEMPLATE_FILE"
}

apply_generated_outbounds() {
    rendered_file="$1"
    outdir="$(dirname "$OUTBOUND_FILE")"
    if [ ! -d "$outdir" ]; then
        log_msg "ошибка: каталог для outbounds не найден: $outdir"
        return 1
    fi
    write_wrapped_outbounds "$rendered_file" "$OUTBOUND_FILE" || return 1
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

    rendered_file="$TEST_DIR/rendered.json"
    [ -f "$rendered_file" ] || return 1
    apply_generated_outbounds "$rendered_file" || return 1
    set_last_success_hash "$hash"
    set_last_applied_hash "$hash"
    return 0
}
