#!/bin/bash

# =============================================
# XSS Reflection Tester - Simple Webhook (Form Data)
# Payload: testtt<a>t"e'st
# =============================================

PAYLOAD="testtt<a>t\"e'st"
OUTPUT_FILE="xss_vulnerable.txt"
WEBHOOK="https://discord.com/api/webhooks/1508123239732350987/Q-oc7dcydk07KJwnsAJSbTpaVeNxHR6HnVkkpf5Q8kkJqMfQYpbu9ZGEaHx80IKm1oZw"

usage() {
    echo "Usage:"
    echo "  $0 -u <URL> [-o output.txt]"
    echo "  $0 -l <urls.txt> [-o output.txt]"
    echo ""
    echo "Options:"
    echo "  -u    Single URL"
    echo "  -l    URL list file"
    echo "  -o    Output file (default: xss_vulnerable.txt)"
    exit 1
}

while getopts "u:l:o:h" opt; do
    case $opt in
        u) SINGLE_URL="$OPTARG" ;;
        l) URL_LIST="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$SINGLE_URL" ] && [ -z "$URL_LIST" ]; then
    echo "Error: Use -u or -l"
    usage
fi

echo "[+] XSS Reflection Tester started"
echo "[+] Payload: $PAYLOAD"
echo "[+] Using simple form data for webhook"
echo "============================================================="

> "$OUTPUT_FILE"

send_to_discord() {
    local vuln_url="$1"
    local param="$2"
    
    echo "     [WEBHOOK] Sending notification..."
    
    curl -s -X POST \
         -H "Content-Type: application/x-www-form-urlencoded" \
         --data-urlencode "content=**🔴 REFLECTION FOUND!**, **URL:** ${vuln_url}  **Parameter:** ${param}" \
         "$WEBHOOK" > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo "     ✅ Webhook Sent Successfully!"
    else
        echo "     ❌ Webhook Failed"
    fi
}

test_url() {
    local base_url="$1"
    echo -e "\n[+] Testing: $base_url"
    
    if ! echo "$base_url" | grep -q "?"; then
        echo "   No parameters found."
        return
    fi

    local base=$(echo "$base_url" | cut -d'?' -f1)
    local query=$(echo "$base_url" | cut -d'?' -f2)

    IFS='&' read -ra params <<< "$query"
    
    for param in "${params[@]}"; do
        local key=$(echo "$param" | cut -d'=' -f1)
        
        local encoded_payload=$(echo -n "$PAYLOAD" | sed 's/ /%20/g; s/</%3C/g; s/>/%3E/g; s/"/%22/g; s/'"'"'/%27/g')
        local test_url="${base}?$(echo "$query" | sed "s|$key=[^&]*|$key=$encoded_payload|g")"
        
        echo "   → Testing: $key"
        
        response=$(curl -s -L -A "Mozilla/5.0" --max-time 15 "$test_url" 2>/dev/null)
        
        if echo "$response" | grep -q "testtt<a>t\"e'st"; then
            echo "     ✅ REFLECTED!"
            echo "     URL: $test_url"
            
            if echo "$response" | grep -oE '<[^>]*testtt' >/dev/null; then
                echo "     📍 Inside HTML tag"
            else
                echo "     📍 In response body"
            fi
            
            # Save to file
            {
                echo "URL: $test_url"
                echo "✅ REFLECTED!"
                echo "Parameter: $key"
                echo "Payload: $PAYLOAD"
                echo "--------------------------------------------------"
            } >> "$OUTPUT_FILE"
            
            # Send webhook
            send_to_discord "$test_url" "$key"
            
        else
            echo "     Not reflected"
        fi
    done
}

# Run tests
if [ -n "$SINGLE_URL" ]; then
    test_url "$SINGLE_URL"
fi

if [ -n "$URL_LIST" ]; then
    if [ ! -f "$URL_LIST" ]; then
        echo "Error: File $URL_LIST not found!"
        exit 1
    fi
    while IFS= read -r url || [ -n "$url" ]; do
        url=$(echo "$url" | tr -d '\r')
        [ -z "$url" ] && continue
        test_url "$url"
    done < "$URL_LIST"
fi

echo -e "\n[+] Testing completed!"
echo "[+] Results saved to: $OUTPUT_FILE"
