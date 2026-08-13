# shellcheck shell=sh

link_hash() {
    printf '%s' "$1" | md5sum 2>/dev/null | awk '{print $1}'
}

split_link_comment() {
    raw="$1"
    SPLIT_LINK=""
    SPLIT_COMMENT=""
    case "$raw" in
        *" # "*)
            SPLIT_LINK="${raw%%" # "*}"
            SPLIT_COMMENT="${raw#*" # "}"
            ;;
        *)
            SPLIT_LINK="$raw"
            SPLIT_COMMENT=""
            ;;
    esac
    SPLIT_LINK="$(trim_text "$SPLIT_LINK")"
    SPLIT_COMMENT="$(trim_text "$SPLIT_COMMENT")"
}

valid_link() {
    case "$1" in
        vless://*) return 0 ;;
        hysteria2://*) return 0 ;;
        hy2://*) return 0 ;;
        *) return 1 ;;
    esac
}

link_protocol() {
    case "$1" in
        hysteria2://*|hy2://*) printf '%s\n' "hy2" ;;
        vless://*) printf '%s\n' "vless" ;;
        *) printf '%s\n' "unknown" ;;
    esac
}

# The Xray templates below are per PROTOCOL because Xray carries Hysteria 2 as a
# stream transport, so its outbound looks nothing like a VLESS one. Mihomo and
# sing-box take both protocols as ordinary outbounds and need one template each,
# which is what probe_template_for answers.
outbound_template_for_link() {
    case "$(link_protocol "$1")" in
        hy2) printf '%s\n' "$XRAY_HY2_TEMPLATE_FILE" ;;
        *) printf '%s\n' "$TEMPLATE_FILE" ;;
    esac
}

test_template_for_link() {
    case "$(link_protocol "$1")" in
        hy2) printf '%s\n' "$XRAY_HY2_TEST_TEMPLATE_FILE" ;;
        *) printf '%s\n' "$TEST_TEMPLATE_FILE" ;;
    esac
}

batch_template_for_protocol() {
    case "$1" in
        hy2) printf '%s\n' "$XRAY_HY2_BATCH_TEST_TEMPLATE_FILE" ;;
        *) printf '%s\n' "$BATCH_TEST_TEMPLATE_FILE" ;;
    esac
}

# probe_template_for <engine> <single|batch>
#
# The override a user can edit for the engines whose probe config is generated.
# Empty means "no override": the converter's built-in layout is used.
probe_template_for() {
    case "$1:$2" in
        mihomo:single) printf '%s\n' "$MIHOMO_TEST_TEMPLATE_FILE" ;;
        mihomo:batch) printf '%s\n' "$MIHOMO_BATCH_TEST_TEMPLATE_FILE" ;;
        singbox:single) printf '%s\n' "$SINGBOX_TEST_TEMPLATE_FILE" ;;
        singbox:batch) printf '%s\n' "$SINGBOX_BATCH_TEST_TEMPLATE_FILE" ;;
        *) printf '%s\n' "" ;;
    esac
}

build_links_index() {
    [ -f "$LINKS_FILE" ] || return 0
    lineno=0
    while IFS= read -r raw || [ -n "$raw" ]; do
        lineno=$((lineno + 1))
        line="$(trim_text "$raw")"
        [ -n "$line" ] || continue
        case "$line" in
            \#*) continue ;;
        esac
        split_link_comment "$line"
        valid_link "$SPLIT_LINK" || continue
        # Табы вырезаем из ОБОИХ полей ДО хеширования: иначе таб внутри самой
        # ссылки сдвигает колонки TSV-строки и ломает hash/comment/lineno у
        # всех потребителей build_links_index (batch.sh, loop_status.sh и т.п.),
        # а хеш перестаёт соответствовать фактически используемой ссылке.
        link="$(printf '%s' "$SPLIT_LINK" | tr '\t' ' ')"
        comment="$(printf '%s' "$SPLIT_COMMENT" | tr '\t' ' ')"
        hash="$(link_hash "$link")"
        printf '%s\t%s\t%s\t%s\n' "$hash" "$link" "$comment" "$lineno"
    done < "$LINKS_FILE"
}

find_link_by_hash() {
    want="$1"
    build_links_index | awk -F '\t' -v target="$want" '$1 == target { print; exit }'
}

reorder_random() {
    awk 'BEGIN{srand()} {printf "%.12f\t%s\n", rand(), $0}' "$1" | sort -n | cut -f2-
}

reorder_ordered() {
    input_file="$1"
    last_hash="$(read_last_success_hash)"
    last_line=""
    if [ -n "$last_hash" ]; then
        last_line="$(build_links_index | awk -F '\t' -v target="$last_hash" '$1 == target { print $4; exit }')"
    fi
    if [ -n "$last_hash" ] && awk -F '\t' -v target="$last_hash" '$1 == target { found = 1 } END { exit(found ? 0 : 1) }' "$input_file"; then
        awk -F '\t' -v target="$last_hash" '
            { lines[NR] = $0; if ($1 == target) idx = NR; n = NR }
            END {
                if (n == 0) exit
                start = 1
                if (idx > 0) {
                    start = idx + 1
                    if (start > n) start = 1
                }
                for (i = start; i <= n; i++) print lines[i]
                for (i = 1; i < start; i++) print lines[i]
            }
        ' "$input_file"
        return 0
    fi

    if validate_number "$last_line"; then
        awk -F '\t' -v target_line="$last_line" '
            { lines[NR] = $0; if (($4 + 0) > target_line && start == 0) start = NR; n = NR }
            END {
                if (n == 0) exit
                if (start == 0) start = 1
                for (i = start; i <= n; i++) print lines[i]
                for (i = 1; i < start; i++) print lines[i]
            }
        ' "$input_file"
        return 0
    fi

    cat "$input_file"
}

reorder_fastest() {
    input_file="$1"
    fastest_file="${input_file}.fastest"
    rest_file="${input_file}.fastest-rest"
    : > "$fastest_file"
    : > "$rest_file"

    while IFS="$(printf '\t')" read -r hash link comment lineno; do
        [ -n "$hash" ] || continue
        status="$(link_state_get "$hash" LAST_STATUS)"
        request_ms="$(link_state_get "$hash" LAST_REQUEST_TIME_MS)"
        if [ "$status" = "alive" ] && validate_number "$request_ms" && [ "$request_ms" -gt 0 ]; then
            printf '%s\t%s\t%s\t%s\t%s\n' "$request_ms" "$hash" "$link" "$comment" "$lineno" >> "$fastest_file"
        else
            printf '%s\t%s\t%s\t%s\n' "$hash" "$link" "$comment" "$lineno" >> "$rest_file"
        fi
    done < "$input_file"

    if [ -s "$fastest_file" ]; then
        sort -n "$fastest_file" | cut -f2-
        cat "$rest_file"
    else
        log_msg "режим fastest: нет alive-ссылок с временем проверки, fallback на ordered"
        reorder_ordered "$input_file"
    fi

    rm -f "$fastest_file" "$rest_file"
}

build_candidate_file() {
    temp_file="$1"
    build_links_index > "$temp_file"
    filtered_file="${temp_file}.filtered"
    : > "$filtered_file"
    while IFS="$(printf '\t')" read -r hash link comment lineno; do
        [ -n "$hash" ] || continue
        # Unconditional, unlike the cooldown filter: a protocol the running engine
        # cannot build is never a candidate, whatever EXCLUDE_DEAD says.
        if ! engine_supports_protocol "$(link_protocol "$link")"; then
            continue
        fi
        if [ "$EXCLUDE_DEAD" = "1" ] && cooldown_active "$hash"; then
            continue
        fi
        printf '%s\t%s\t%s\t%s\n' "$hash" "$link" "$comment" "$lineno" >> "$filtered_file"
    done < "$temp_file"
    mv "$filtered_file" "$temp_file"
}

rotate_candidates() {
    temp_file="$(mktemp /tmp/tproxy-manager-watchdog-candidates.XXXXXX 2>/dev/null || printf '')"
    if [ -z "$temp_file" ]; then
        log_msg "ошибка: не удалось создать временный список кандидатов"
        return 1
    fi

    build_candidate_file "$temp_file"
    if [ ! -s "$temp_file" ]; then
        rm -f "$temp_file"
        log_msg "живые кандидаты для ротации отсутствуют"
        return 1
    fi

    ordered_file="${temp_file}.ordered"
    log_msg "режим выбора ссылок: $SELECTION_MODE"
    case "$SELECTION_MODE" in
        ordered)
            reorder_ordered "$temp_file" > "$ordered_file"
            ;;
        fastest)
            reorder_fastest "$temp_file" > "$ordered_file"
            ;;
        *)
            reorder_random "$temp_file" > "$ordered_file"
            ;;
    esac

    while IFS="$(printf '\t')" read -r hash link comment lineno; do
        [ -n "$hash" ] || continue
        if apply_link_runtime "$hash" "$link"; then
            rm -f "$temp_file" "$ordered_file"
            log_msg "выбрана и применена ссылка $hash"
            return 0
        fi
        cleanup_test_instance
    done < "$ordered_file"

    rm -f "$temp_file" "$ordered_file"
    log_msg "не удалось найти рабочую ссылку для ротации"
    return 1
}
