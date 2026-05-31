#!/bin/bash
# =============================================
# Global Unique Parameter Extractor + Tracking Filter
# =============================================

usage() {
    echo "Usage: $0 -f <input_file> -o <output_file>"
    echo "Example: $0 -f urls.txt -o clean_urls.txt"
    exit 1
}

while getopts "f:o:" opt; do
    case $opt in
        f) input_file="$OPTARG" ;;
        o) output_file="$OPTARG" ;;
        *) usage ;;
    esac
done

if [[ -z "$input_file" || -z "$output_file" ]]; then
    usage
fi

if [[ ! -f "$input_file" ]]; then
    echo "Error: Input file '$input_file' not found!"
    exit 1
fi

temp_file=$(mktemp)
count=0

# ================== IGNORE LIST ==================
declare -A ignore_params
ignore_list=(
    "gclid" "fbclid" "msclkid" "ttclid" "twclid" "dclid" "li_fat_id" "scid"
    "embed" "theme" "autoplay" "controls" "mute" "loop" "rel"
    "size" "width" "height" "ratio" "scale" "limit" "offset"
    "page" "per_page" "sort" "view" "mode"
)

for p in "${ignore_list[@]}"; do
    ignore_params["$p"]=1
done

echo "Processing URLs..."

# Global seen parameters (across all URLs)
seen_params_file=$(mktemp)

while IFS= read -r line || [[ -n "$line" ]]; do
    # Trim whitespace
    url="${line#"${line%%[![:space:]]*}"}"
    url="${url%"${url##*[![:space:]]}"}"

    [[ -z "$url" || "$url" != *'?'* || "$url" != http* ]] && continue

    path="${url%%'?'*}"
    query="${url#*'?'}"

    IFS='&' read -ra param_pairs <<< "$query"

    new_params=()
    has_non_ignore=false

    for pair in "${param_pairs[@]}"; do
        [[ -z "$pair" ]] && continue
        key="${pair%%=*}"

        # If this parameter key is completely new globally
        if ! grep -qxF "$key" "$seen_params_file" 2>/dev/null; then
            new_params+=("$pair")
            echo "$key" >> "$seen_params_file"

            # Check if it's a useful (non-tracking) parameter
            if [[ ! -v ignore_params["$key"] && ! "$key" =~ ^utm_ && ! "$key" =~ ^embed_ ]]; then
                has_non_ignore=true
            fi
        fi
    done

    # Save URL only if it introduced at least one new non-tracking parameter
    if [[ ${#new_params[@]} -gt 0 && "$has_non_ignore" == true ]]; then
        new_query=$(IFS='&'; echo "${new_params[*]}")
        echo "${path}?${new_query}" >> "$temp_file"
        ((count++))
    fi

done < "$input_file"

mv "$temp_file" "$output_file" 2>/dev/null
rm -f "$seen_params_file"

echo "Done! Extracted $count URLs with globally unique parameters to '$output_file'"
