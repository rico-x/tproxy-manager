# shellcheck shell=sh

# One converter call for every engine whose probe config is generated rather than
# filled into an Xray template. A template is passed only when the user actually
# has one on disk; without it the converter uses its built-in layout, which is
# what every install did before those settings became real.
render_engine_test_config() {
    converter="$1"
    links_file="$2"
    out_file="$3"
    template="$4"
    label="$5"
    engine="${6:-${PROBE_KIND:-}}"

    set -- -r "$links_file" --test --port "$TEST_PORT"
    if [ -n "$template" ] && [ -f "$template" ]; then
        set -- "$@" --template "$template"
    fi
    case "$engine" in
        mihomo)
            [ -f "$MIHOMO_VLESS_OUTBOUND_TEMPLATE_FILE" ] \
                && set -- "$@" --vless-template "$MIHOMO_VLESS_OUTBOUND_TEMPLATE_FILE"
            [ -f "$MIHOMO_HY2_OUTBOUND_TEMPLATE_FILE" ] \
                && set -- "$@" --hy2-template "$MIHOMO_HY2_OUTBOUND_TEMPLATE_FILE"
            ;;
        singbox)
            [ -f "$SINGBOX_VLESS_OUTBOUND_TEMPLATE_FILE" ] \
                && set -- "$@" --vless-template "$SINGBOX_VLESS_OUTBOUND_TEMPLATE_FILE"
            [ -f "$SINGBOX_HY2_OUTBOUND_TEMPLATE_FILE" ] \
                && set -- "$@" --hy2-template "$SINGBOX_HY2_OUTBOUND_TEMPLATE_FILE"
            ;;
    esac
    # Kept out of the log until we know the exit code: on rc 3 the converter's own
    # words are the useful answer ("unsupported sing-box VLESS transport: xhttp" is
    # far more actionable than "vless is unsupported"), so they are handed back to
    # the caller rather than only appended to the log.
    converter_err="${out_file}.err"
    "$converter" "$@" > "$out_file" 2>"$converter_err"
    rc=$?
    RENDER_UNSUPPORTED_REASON=""
    if [ "$rc" -eq 0 ]; then
        [ -s "$converter_err" ] && cat "$converter_err" >> "$LOG_FILE"
        rm -f "$converter_err"
        return 0
    fi
    [ -s "$converter_err" ] && cat "$converter_err" >> "$LOG_FILE"
    # 3 means the engine itself cannot run this link -- a transport it does not
    # implement, not a server that is down. Kept distinct all the way up so the
    # caller can report it instead of burying it as a failed check.
    if [ "$rc" -eq 3 ]; then
        RENDER_UNSUPPORTED_REASON="$(sed -n 's/^skipping link: //p' "$converter_err" | head -1)"
        rm -f "$converter_err"
        return 3
    fi
    rm -f "$converter_err"
    log_msg "ошибка: не удалось сгенерировать тестовый конфиг $label"
    return 1
}

build_test_command() {
    config_file="$1"
    config_q="$(shellescape "$config_file")"
    case "$TEST_COMMAND" in
        *"{config}"*)
            printf '%s' "$TEST_COMMAND" | sed "s|{config}|$config_q|g"
            ;;
        *)
            printf '%s %s' "$TEST_COMMAND" "$config_q"
            ;;
    esac
}

start_test_instance() {
    config_file="$1"
    log_file="$2"
    cmd="$(build_test_command "$config_file")"
    if [ -z "$cmd" ]; then
        log_msg "ошибка: не задана команда запуска test-instance"
        return 1
    fi

    log_msg "test-instance command: $cmd"
    sh -c "$cmd" > "$log_file" 2>&1 &
    TEST_PID="$!"
    sleep 2
    if ! kill -0 "$TEST_PID" 2>/dev/null; then
        rc=0
        wait "$TEST_PID" >/dev/null 2>&1 || rc=$?
        log_msg "ошибка: test-instance завершился преждевременно, rc=$rc"
        return 1
    fi
    return 0
}

probe_link_runtime() {
    hash="$1"
    link="$2"

    TEST_DIR="$(mktemp -d /tmp/tproxy-manager-watchdog-test.XXXXXX 2>/dev/null || printf '')"
    if [ -z "$TEST_DIR" ] || [ ! -d "$TEST_DIR" ]; then
        log_msg "ошибка: не удалось создать временный каталог для test-instance"
        return 1
    fi

    single_links_file="$TEST_DIR/one-link.txt"
    rendered_file="$TEST_DIR/rendered.json"
    array_file="$TEST_DIR/outbounds.json"
    config_file="$TEST_DIR/test-config.${PROBE_CONFIG_EXT:-json}"
    log_file="$TEST_DIR/${PROBE_LOG_NAME:-engine-test.log}"

    printf '%s\n' "$link" > "$single_links_file"

    # A link the active engine cannot run is not a dead link. Marking it dead
    # would put it on cooldown and hide it from rotation, as if the server were
    # down, when the only thing missing is support in the engine now in use.
    protocol="$(link_protocol "$link")"
    if ! engine_supports_protocol "$protocol"; then
        mark_link_unsupported "$hash" "$protocol"
        log_msg "ссылка $hash: протокол $protocol не поддерживается ядром $PROBE_LABEL"
        return 1
    fi

    # Which renderer builds the probe config is a property of the engine, taken
    # from its own definition. Keying this on the engine NAME here is what used to
    # send anything unrecognised down the Xray path with Xray's test command.
    case "$PROBE_KIND" in
        mihomo)
            if [ ! -x "$PROXY2MIHOMO" ]; then
                log_msg "ошибка: не найден исполняемый конвертер $PROXY2MIHOMO"
                return 1
            fi
            render_engine_test_config "$PROXY2MIHOMO" "$single_links_file" "$config_file" \
                "$(probe_template_for mihomo single)" "Mihomo" "mihomo"
            case $? in
                0) : ;;
                3)
                    # The converter knows the engine's real limits: sing-box, for one,
                    # implements no XHTTP transport while Xray and Mihomo both do.
                    mark_link_unsupported "$hash" "${RENDER_UNSUPPORTED_REASON:-$protocol}"
                    log_msg "ссылка $hash не поддерживается ядром $PROBE_LABEL: ${RENDER_UNSUPPORTED_REASON:-$protocol}"
                    return 1
                    ;;
                *)
                    mark_link_dead "$hash" "000" "0" "render error"
                    return 1
                    ;;
            esac
            ;;
        singbox)
            if [ ! -x "$PROXY2SINGBOX" ]; then
                log_msg "ошибка: не найден исполняемый конвертер $PROXY2SINGBOX"
                return 1
            fi
            render_engine_test_config "$PROXY2SINGBOX" "$single_links_file" "$config_file" \
                "$(probe_template_for singbox single)" "sing-box" "singbox"
            case $? in
                0) : ;;
                3)
                    # The converter knows the engine's real limits: sing-box, for one,
                    # implements no XHTTP transport while Xray and Mihomo both do.
                    mark_link_unsupported "$hash" "${RENDER_UNSUPPORTED_REASON:-$protocol}"
                    log_msg "ссылка $hash не поддерживается ядром $PROBE_LABEL: ${RENDER_UNSUPPORTED_REASON:-$protocol}"
                    return 1
                    ;;
                *)
                    mark_link_dead "$hash" "000" "0" "render error"
                    return 1
                    ;;
            esac
            ;;
        template)
            generate_rendered_config "$single_links_file" "$rendered_file" "$link" || {
                mark_link_dead "$hash" "000" "0" "render error"
                return 1
            }
            extract_outbounds_array "$rendered_file" "$array_file" || {
                mark_link_dead "$hash" "000" "0" "render error"
                return 1
            }
            render_test_config "$array_file" "$config_file" "$TEST_PORT" "$link" || {
                mark_link_dead "$hash" "000" "0" "render error"
                return 1
            }
            ;;
        *)
            log_msg "ошибка: неизвестный способ проверки '$PROBE_KIND' для ядра $PROBE_LABEL"
            return 1
            ;;
    esac
    start_test_instance "$config_file" "$log_file" || {
        mark_link_dead "$hash" "000" "0" "test start error"
        return 1
    }

    probe_result="$(probe_proxy_url_with_time "socks5h://127.0.0.1:$TEST_PORT")"
    code="$(printf '%s\n' "$probe_result" | awk -F '\t' '{print $1}')"
    request_ms="$(printf '%s\n' "$probe_result" | awk -F '\t' '{print $2}')"
    request_text="$(printf '%s\n' "$probe_result" | awk -F '\t' '{print $3}')"
    if [ "$code" = "200" ]; then
        mark_link_alive "$hash" "$code" "$request_ms" "$request_text"
        return 0
    fi

    mark_link_dead "$hash" "$code" "$request_ms" "$request_text"
    return 1
}
