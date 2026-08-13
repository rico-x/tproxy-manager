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
    protocol="${5:-vless}"
    batch_template="$(batch_template_for_protocol "$protocol")"

    if [ ! -f "$batch_template" ]; then
        log_msg "ошибка: не найден batch-шаблон $batch_template"
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
    done < "$batch_template"
}

build_batch_config() {
    chunk_file="$1"
    config_file="$2"
    probe_map="$3"
    protocol="${4:-vless}"

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

        render_template="$(outbound_template_for_link "$link")"
        if ! "$VLESS2JSON" -r "$single_link_file" -t "$render_template" --one-outbound --tag "$tag" > "$outbound_file" 2>"$TEST_DIR/render-$tag.err"; then
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
    render_batch_test_config "$inbounds_json" "$outbounds_json" "$rules_json" "$config_file" "$protocol"
}

# The converter builds the whole chunk config: one listener per link, each pinned
# to its own outbound. Mihomo and sing-box both do this in a single process, so
# batch mode is no longer something only Xray gets.
build_batch_config_converter() {
    chunk_file="$1"
    config_file="$2"
    probe_map="$3"
    converter="$4"
    template="$5"
    label="$6"

    ports_file="$TEST_DIR/ports.tsv"
    : > "$ports_file"
    : > "$probe_map"
    idx=0
    while IFS="$(printf '\t')" read -r hash link comment lineno; do
        [ -n "$hash" ] || continue
        port=$((BATCH_CHECK_PORT_START + idx))
        idx=$((idx + 1))
        if [ "$port" -gt 65535 ]; then
            mark_link_dead "$hash" "000" "0" "port-overflow"
            continue
        fi
        printf '%s\t%s\n' "$port" "$link" >> "$ports_file"
        printf '%s\t%s\t%s\n' "$hash" "$port" "probe-$port" >> "$probe_map"
    done < "$chunk_file"

    if [ ! -s "$ports_file" ]; then
        log_msg "batch: нет ссылок в пачке"
        return 1
    fi

    set -- --batch --ports "$ports_file"
    if [ -n "$template" ] && [ -f "$template" ]; then
        set -- "$@" --template "$template"
    fi
    case "$PROBE_KIND" in
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
    err_file="$TEST_DIR/converter.err"
    "$converter" "$@" > "$config_file" 2>"$err_file"
    rc=$?
    [ -s "$err_file" ] && cat "$err_file" >> "$LOG_FILE"

    # Links the engine cannot run are named by port. They are reported as
    # unsupported and dropped from the map, so the rest of the chunk still gets
    # measured -- one XHTTP link used to be enough to fail a whole chunk.
    if [ -s "$err_file" ]; then
        while IFS= read -r line; do
            case "$line" in
                "unsupported-port: "*)
                    rest="${line#unsupported-port: }"
                    bad_port="${rest%% *}"
                    reason="${rest#* }"
                    bad_hash="$(awk -F '\t' -v p="$bad_port" '$2 == p { print $1; exit }' "$probe_map")"
                    if [ -n "$bad_hash" ]; then
                        mark_link_unsupported "$bad_hash" "$reason"
                        grep -v "^$bad_hash	" "$probe_map" > "$probe_map.keep" 2>/dev/null
                        mv "$probe_map.keep" "$probe_map"
                    fi
                    ;;
            esac
        done < "$err_file"
    fi

    if [ "$rc" -eq 3 ]; then
        # Every link in the chunk was already reported unsupported above; there is
        # nothing left to probe, and that is not a failure of the batch run.
        : > "$probe_map"
        return 0
    fi
    if [ "$rc" -ne 0 ]; then
        log_msg "batch: не удалось сгенерировать конфиг $label"
        return 1
    fi
    [ -s "$config_file" ] || return 1
    return 0
}

probe_batch_chunk() {
    chunk_file="$1"
    chunk_no="$2"
    protocol="${3:-vless}"

    TEST_DIR="$BATCH_DIR/run-$chunk_no"
    mkdir -p "$TEST_DIR" || return 1

    config_file="$TEST_DIR/batch-test-config.${PROBE_CONFIG_EXT:-json}"
    probe_map="$TEST_DIR/probe-map.tsv"
    log_file="$TEST_DIR/${PROBE_LOG_NAME:-batch-test.log}"
    result_dir="$TEST_DIR/results"
    mkdir -p "$result_dir" || return 1

    case "$PROBE_KIND" in
        mihomo)
            build_batch_config_converter "$chunk_file" "$config_file" "$probe_map" \
                "$PROXY2MIHOMO" "$(probe_template_for mihomo batch)" "Mihomo" || return 1
            ;;
        singbox)
            build_batch_config_converter "$chunk_file" "$config_file" "$probe_map" \
                "$PROXY2SINGBOX" "$(probe_template_for singbox batch)" "sing-box" || return 1
            ;;
        template)
            build_batch_config "$chunk_file" "$config_file" "$probe_map" "$protocol" || return 1
            ;;
        *)
            log_msg "batch: неизвестный способ проверки '$PROBE_KIND'"
            return 1
            ;;
    esac
    # Every link in the chunk turned out to be unsupported by this engine. They are
    # already recorded as such, so starting an engine with nothing to probe would
    # only waste a process.
    if [ ! -s "$probe_map" ]; then
        BATCH_CHUNK_ALIVE=0
        return 0
    fi
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

probe_links_batch_protocol_runtime() {
    protocol="$1"
    input_file="$2"
    [ -s "$input_file" ] || return 0

    chunk_file="$BATCH_DIR/chunk-$protocol-1.tsv"
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
            if ! probe_batch_chunk "$chunk_file" "$protocol-$chunk_no" "$protocol"; then
                return 1
            fi
            BATCH_ALIVE=$((BATCH_ALIVE + BATCH_CHUNK_ALIVE))
            chunk_no=$((chunk_no + 1))
            chunk_file="$BATCH_DIR/chunk-$protocol-$chunk_no.tsv"
            : > "$chunk_file"
            chunk_count=0
        fi
    done < "$input_file"

    if [ "$chunk_count" -gt 0 ]; then
        BATCH_CHUNKS=$((BATCH_CHUNKS + 1))
        if ! probe_batch_chunk "$chunk_file" "$protocol-$chunk_no" "$protocol"; then
            return 1
        fi
        BATCH_ALIVE=$((BATCH_ALIVE + BATCH_CHUNK_ALIVE))
    fi
    return 0
}

probe_links_batch_runtime() {
    input_file="$1"
    BATCH_ALIVE=0
    BATCH_TOTAL=0
    BATCH_CHUNKS=0

    [ "$BATCH_CHECK_ENABLED" = "1" ] || return 1
    # Whether one process can probe many links at once is a property of the engine,
    # not a privilege of Xray. Every engine that says it can, does; the sequential
    # fallback is for one that says it cannot.
    if [ "$PROBE_BATCH" != "1" ]; then
        log_msg "batch: ядро $PROBE_LABEL не поддерживает пакетную проверку, используется индивидуальная"
        return 1
    fi
    case "$PROBE_KIND" in
        template)
            [ -x "$VLESS2JSON" ] || return 1
            [ -f "$BATCH_TEST_TEMPLATE_FILE" ] || return 1
            ;;
        mihomo) [ -x "$PROXY2MIHOMO" ] || return 1 ;;
        singbox) [ -x "$PROXY2SINGBOX" ] || return 1 ;;
        *) return 1 ;;
    esac

    BATCH_DIR="$(mktemp -d /tmp/tproxy-manager-watchdog-batch.XXXXXX 2>/dev/null || printf '')"
    if [ -z "$BATCH_DIR" ] || [ ! -d "$BATCH_DIR" ]; then
        log_msg "batch: не удалось создать временный каталог"
        return 1
    fi

    # Splitting by protocol is an Xray requirement, not a general one: there
    # Hysteria 2 is a stream transport and needs its own template, so the two
    # protocols cannot share a config. Mihomo and sing-box take both as ordinary
    # outbounds and probe them together -- splitting would just double the number
    # of engine processes for no reason.
    started="$(now_ts)"
    if [ "$PROBE_KIND" = "template" ]; then
        vless_input="$BATCH_DIR/input-vless.tsv"
        hy2_input="$BATCH_DIR/input-hy2.tsv"
        : > "$vless_input"
        : > "$hy2_input"

        while IFS="$(printf '\t')" read -r hash link comment lineno; do
            [ -n "$hash" ] || continue
            case "$(link_protocol "$link")" in
                hy2) printf '%s\t%s\t%s\t%s\n' "$hash" "$link" "$comment" "$lineno" >> "$hy2_input" ;;
                *) printf '%s\t%s\t%s\t%s\n' "$hash" "$link" "$comment" "$lineno" >> "$vless_input" ;;
            esac
        done < "$input_file"

        for protocol in vless hy2; do
            protocol_input="$BATCH_DIR/input-$protocol.tsv"
            if ! probe_links_batch_protocol_runtime "$protocol" "$protocol_input"; then
                rm -rf "$BATCH_DIR"
                return 1
            fi
        done
    else
        if ! probe_links_batch_protocol_runtime "mixed" "$input_file"; then
            rm -rf "$BATCH_DIR"
            return 1
        fi
    fi

    finished="$(now_ts)"
    duration=$((finished - started))
    log_msg "batch-проверка завершена: alive=$BATCH_ALIVE total=$BATCH_TOTAL chunks=$BATCH_CHUNKS batch_size=$BATCH_CHECK_BATCH_SIZE concurrency=$BATCH_CHECK_CONCURRENCY duration=${duration}s"
    rm -rf "$BATCH_DIR"
    return 0
}
