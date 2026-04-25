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
    config_file="$TEST_DIR/test-config.json"
    log_file="$TEST_DIR/xray-test.log"

    printf '%s\n' "$link" > "$single_links_file"

    generate_rendered_config "$single_links_file" "$rendered_file" || return 1
    extract_outbounds_array "$rendered_file" "$array_file" || return 1
    render_test_config "$array_file" "$config_file" "$TEST_PORT" || return 1
    start_test_instance "$config_file" "$log_file" || return 1

    code="$(probe_proxy_url "socks5h://127.0.0.1:$TEST_PORT")"
    if [ "$code" = "200" ]; then
        mark_link_alive "$hash" "$code"
        return 0
    fi

    mark_link_dead "$hash" "$code"
    return 1
}
