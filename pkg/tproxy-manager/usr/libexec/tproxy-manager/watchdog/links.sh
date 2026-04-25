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
        *) return 1 ;;
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
        hash="$(link_hash "$SPLIT_LINK")"
        comment="$(printf '%s' "$SPLIT_COMMENT" | tr '\t' ' ')"
        printf '%s\t%s\t%s\t%s\n' "$hash" "$SPLIT_LINK" "$comment" "$lineno"
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

build_candidate_file() {
    temp_file="$1"
    build_links_index > "$temp_file"
    if [ "$EXCLUDE_DEAD" = "1" ]; then
        filtered_file="${temp_file}.filtered"
        : > "$filtered_file"
        while IFS="$(printf '\t')" read -r hash link comment lineno; do
            [ -n "$hash" ] || continue
            if cooldown_active "$hash"; then
                continue
            fi
            printf '%s\t%s\t%s\t%s\n' "$hash" "$link" "$comment" "$lineno" >> "$filtered_file"
        done < "$temp_file"
        mv "$filtered_file" "$temp_file"
    fi
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
    case "$SELECTION_MODE" in
        ordered)
            reorder_ordered "$temp_file" > "$ordered_file"
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
