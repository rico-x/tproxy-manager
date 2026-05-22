# shellcheck shell=sh

batch_tag_for_hash() {
    printf 'proxy-%s\n' "$(printf '%s' "$1" | cut -c1-8)"
}

batch_inbound_tag_for_hash() {
    printf 'probe-%s\n' "$(printf '%s' "$1" | cut -c1-8)"
}

append_json_file_entry() {
    target="$1"
    item="$2"
    if [ -s "$target" ]; then
        printf ',\n' >> "$target"
    fi
    cat "$item" >> "$target"
}

append_json_text_entry() {
    target="$1"
    text="$2"
    if [ -s "$target" ]; then
        printf ',\n' >> "$target"
    fi
    printf '%s' "$text" >> "$target"
}

wrap_json_array() {
    entries="$1"
    output="$2"
    {
        printf '[\n'
        cat "$entries"
        printf '\n]\n'
    } > "$output"
}

render_batch_test_config() {
    inbounds_file="$1"
    outbounds_file="$2"
    rules_file="$3"
    config_file="$4"

    if [ ! -f "$BATCH_TEST_TEMPLATE_FILE" ]; then
        log_msg "ошибка: не найден batch-шаблон $BATCH_TEST_TEMPLATE_FILE"
        return 1
    fi

    inbounds_json="$(cat "$inbounds_file")"
    outbounds_json="$(cat "$outbounds_file")"
    rules_json="$(cat "$rules_file")"

    : > "$config_file"
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            *"__BATCH_INBOUNDS__"*)
                prefix="${line%%__BATCH_INBOUNDS__*}"
                suffix="${line#*__BATCH_INBOUNDS__}"
                printf '%s%s%s\n' "$prefix" "$inbounds_json" "$suffix" >> "$config_file"
                ;;
            *"__BATCH_OUTBOUNDS__"*)
                prefix="${line%%__BATCH_OUTBOUNDS__*}"
                suffix="${line#*__BATCH_OUTBOUNDS__}"
                printf '%s%s%s\n' "$prefix" "$outbounds_json" "$suffix" >> "$config_file"
                ;;
            *"__BATCH_RULES__"*)
                prefix="${line%%__BATCH_RULES__*}"
                suffix="${line#*__BATCH_RULES__}"
                printf '%s%s%s\n' "$prefix" "$rules_json" "$suffix" >> "$config_file"
                ;;
            *)
                printf '%s\n' "$line" >> "$config_file"
                ;;
        esac
    done < "$BATCH_TEST_TEMPLATE_FILE"
}

build_batch_config() {
    chunk_file="$1"
    config_file="$2"
    probe_map="$3"

    inbounds_entries="$TEST_DIR/inbounds.entries"
    outbounds_entries="$TEST_DIR/outbounds.entries"
    rules_entries="$TEST_DIR/rules.entries"
    inbounds_json="$TEST_DIR/inbounds.json"
    outbounds_json="$TEST_DIR/outbounds.json"
    rules_json="$TEST_DIR/rules.json"
    generated_count=0
    idx=0

    : > "$inbounds_entries"
    : > "$outbounds_entries"
    : > "$rules_entries"
    : > "$probe_map"

    while IFS="$(printf '\t')" read -r hash link comment lineno; do
        [ -n "$hash" ] || continue
        tag="$(batch_tag_for_hash "$hash")"
        inbound_tag="$(batch_inbound_tag_for_hash "$hash")"
        port=$((BATCH_CHECK_PORT_START + idx))
        idx=$((idx + 1))

        if [ "$port" -gt 65535 ]; then
            mark_link_dead "$hash" "000" "0" "port-overflow"
            continue
        fi

        single_link_file="$TEST_DIR/link-$tag.txt"
        outbound_file="$TEST_DIR/outbound-$tag.json"
        printf '%s\n' "$link" > "$single_link_file"

        if ! "$VLESS2JSON" -r "$single_link_file" -t "$TEMPLATE_FILE" --one-outbound --tag "$tag" > "$outbound_file" 2>"$TEST_DIR/render-$tag.err"; then
            mark_link_dead "$hash" "000" "0" "render-error"
            log_msg "batch: не удалось сгенерировать outbound для $hash"
            continue
        fi
        if ! grep -q '^[[:space:]]*{' "$outbound_file" 2>/dev/null; then
            mark_link_dead "$hash" "000" "0" "render-error"
            log_msg "batch: конвертер вернул неожидаемый outbound для $hash"
            continue
        fi

        append_json_text_entry "$inbounds_entries" "{\"tag\":\"$inbound_tag\",\"listen\":\"127.0.0.1\",\"port\":$port,\"protocol\":\"socks\",\"settings\":{\"auth\":\"noauth\",\"udp\":true}}"
        append_json_file_entry "$outbounds_entries" "$outbound_file"
        append_json_text_entry "$rules_entries" "{\"type\":\"field\",\"inboundTag\":[\"$inbound_tag\"],\"outboundTag\":\"$tag\"}"
        printf '%s\t%s\t%s\n' "$hash" "$port" "$tag" >> "$probe_map"
        generated_count=$((generated_count + 1))
    done < "$chunk_file"

    if [ "$generated_count" -eq 0 ]; then
        log_msg "batch: нет сгенерированных outbound в пачке"
        return 1
    fi

    wrap_json_array "$inbounds_entries" "$inbounds_json"
    wrap_json_array "$outbounds_entries" "$outbounds_json"
    wrap_json_array "$rules_entries" "$rules_json"
    render_batch_test_config "$inbounds_json" "$outbounds_json" "$rules_json" "$config_file"
}

probe_batch_chunk() {
    chunk_file="$1"
    chunk_no="$2"

    TEST_DIR="$BATCH_DIR/run-$chunk_no"
    mkdir -p "$TEST_DIR" || return 1

    config_file="$TEST_DIR/batch-test-config.json"
    probe_map="$TEST_DIR/probe-map.tsv"
    log_file="$TEST_DIR/batch-test.log"
    result_dir="$TEST_DIR/results"
    mkdir -p "$result_dir" || return 1

    build_batch_config "$chunk_file" "$config_file" "$probe_map" || return 1
    start_test_instance "$config_file" "$log_file" || return 1

    running=0
    pid_file="$TEST_DIR/curl-pids"
    : > "$pid_file"
    while IFS="$(printf '\t')" read -r hash port tag; do
        [ -n "$hash" ] || continue
        (
            result="$(probe_proxy_url_with_time "socks5h://127.0.0.1:$port")"
            printf '%s\n' "$result" > "$result_dir/$hash"
        ) &
        printf '%s\n' "$!" >> "$pid_file"
        running=$((running + 1))
        if [ "$running" -ge "$BATCH_CHECK_CONCURRENCY" ]; then
            while IFS= read -r pid; do
                [ -n "$pid" ] || continue
                wait "$pid" 2>/dev/null || true
            done < "$pid_file"
            : > "$pid_file"
            running=0
        fi
    done < "$probe_map"
    while IFS= read -r pid; do
        [ -n "$pid" ] || continue
        wait "$pid" 2>/dev/null || true
    done < "$pid_file"

    BATCH_CHUNK_ALIVE=0
    while IFS="$(printf '\t')" read -r hash port tag; do
        [ -n "$hash" ] || continue
        if [ -f "$result_dir/$hash" ]; then
            result="$(cat "$result_dir/$hash")"
            code="$(printf '%s\n' "$result" | awk -F '\t' '{print $1}')"
            request_ms="$(printf '%s\n' "$result" | awk -F '\t' '{print $2}')"
            request_text="$(printf '%s\n' "$result" | awk -F '\t' '{print $3}')"
        else
            code="000"
            request_ms="0"
            request_text="timeout"
        fi
        if [ "$code" = "200" ]; then
            mark_link_alive "$hash" "$code" "$request_ms" "$request_text"
            BATCH_CHUNK_ALIVE=$((BATCH_CHUNK_ALIVE + 1))
        else
            mark_link_dead "$hash" "$code" "$request_ms" "$request_text"
        fi
    done < "$probe_map"

    cleanup_test_instance
    return 0
}

probe_links_batch_runtime() {
    input_file="$1"
    BATCH_ALIVE=0
    BATCH_TOTAL=0
    BATCH_CHUNKS=0

    [ "$BATCH_CHECK_ENABLED" = "1" ] || return 1
    [ -x "$VLESS2JSON" ] || return 1
    [ -f "$BATCH_TEST_TEMPLATE_FILE" ] || return 1

    BATCH_DIR="$(mktemp -d /tmp/tproxy-manager-watchdog-batch.XXXXXX 2>/dev/null || printf '')"
    if [ -z "$BATCH_DIR" ] || [ ! -d "$BATCH_DIR" ]; then
        log_msg "batch: не удалось создать временный каталог"
        return 1
    fi

    started="$(now_ts)"
    chunk_file="$BATCH_DIR/chunk-1.tsv"
    : > "$chunk_file"
    chunk_count=0
    chunk_no=1

    while IFS="$(printf '\t')" read -r hash link comment lineno; do
        [ -n "$hash" ] || continue
        printf '%s\t%s\t%s\t%s\n' "$hash" "$link" "$comment" "$lineno" >> "$chunk_file"
        BATCH_TOTAL=$((BATCH_TOTAL + 1))
        chunk_count=$((chunk_count + 1))

        if [ "$chunk_count" -ge "$BATCH_CHECK_BATCH_SIZE" ]; then
            BATCH_CHUNKS=$((BATCH_CHUNKS + 1))
            if ! probe_batch_chunk "$chunk_file" "$chunk_no"; then
                rm -rf "$BATCH_DIR"
                return 1
            fi
            BATCH_ALIVE=$((BATCH_ALIVE + BATCH_CHUNK_ALIVE))
            chunk_no=$((chunk_no + 1))
            chunk_file="$BATCH_DIR/chunk-$chunk_no.tsv"
            : > "$chunk_file"
            chunk_count=0
        fi
    done < "$input_file"

    if [ "$chunk_count" -gt 0 ]; then
        BATCH_CHUNKS=$((BATCH_CHUNKS + 1))
        if ! probe_batch_chunk "$chunk_file" "$chunk_no"; then
            rm -rf "$BATCH_DIR"
            return 1
        fi
        BATCH_ALIVE=$((BATCH_ALIVE + BATCH_CHUNK_ALIVE))
    fi

    finished="$(now_ts)"
    duration=$((finished - started))
    log_msg "batch-проверка завершена: alive=$BATCH_ALIVE total=$BATCH_TOTAL chunks=$BATCH_CHUNKS batch_size=$BATCH_CHECK_BATCH_SIZE concurrency=$BATCH_CHECK_CONCURRENCY duration=${duration}s"
    rm -rf "$BATCH_DIR"
    return 0
}
