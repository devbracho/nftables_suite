#!/bin/bash
# Alert Script - Send firewall alerts via Alertmanager or direct SMTP
# Usage: ./send-alert-email.sh "Subject" "Body text"
# Or via SSH: ssh server "/usr/local/bin/send-alert-email.sh 'Subject' 'Body'"
#
# Transport priority:
#   1. Alertmanager API  (set ALERTMANAGER_URL)
#   2. Direct SMTP       (set SMTP_HOST + SMTP_USER + SMTP_PASS)

# --- Recipients ---
EMAIL_FROM="${EMAIL_FROM:-noreply@example.com}"
EMAIL_TO="${EMAIL_TO:-mailexample@gmail.com}"

# --- Alertmanager (preferred) ---
ALERTMANAGER_URL="${ALERTMANAGER_URL:-http://localhost:9093}"

# --- Direct SMTP fallback (curl) ---
SMTP_HOST="${SMTP_HOST:-smtp.example.com}"
SMTP_PORT="${SMTP_PORT:-587}"
SMTP_USER="${SMTP_USER:-}"
SMTP_PASS="${SMTP_PASS:-}"

# -------------------------------------------------------

if [ $# -lt 2 ]; then
    echo "Usage: $0 <subject> <body>"
    echo "Example: $0 'NFT alert' 'User blocked egress to 1.2.3.4'"
    exit 1
fi

SUBJECT="$1"
BODY="$2"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(hostname -s)

send_via_alertmanager() {
    # POST a firing alert to Alertmanager; Alertmanager handles email routing.
    # Requires an Alertmanager receiver with an email route configured.
    local payload
    payload=$(printf '[{
  "labels":   { "alertname": "FirewallAlert", "host": "%s", "severity": "warning" },
  "annotations": { "summary": "%s", "description": "%s" },
  "startsAt": "%s"
}]' "$HOSTNAME" "$SUBJECT" "$BODY" "$TIMESTAMP")

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${ALERTMANAGER_URL}/api/v2/alerts" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        --connect-timeout 5 --max-time 10)

    [ "$http_code" = "200" ]
}

send_via_smtp() {
    # Send directly over SMTP using curl (supports STARTTLS on port 587).
    # Requires SMTP_USER and SMTP_PASS to be set.
    if [ -z "$SMTP_USER" ] || [ -z "$SMTP_PASS" ]; then
        echo "ERROR: SMTP_USER and SMTP_PASS must be set for direct SMTP delivery" >&2
        return 1
    fi

    local message
    message=$(printf "From: %s\r\nTo: %s\r\nSubject: [nftables] %s\r\nDate: %s\r\n\r\n%s\r\n" \
        "$EMAIL_FROM" "$EMAIL_TO" "$SUBJECT" "$(date -R)" "$BODY")

    curl -s \
        --url "smtp://${SMTP_HOST}:${SMTP_PORT}" \
        --ssl-reqd \
        --mail-from "$EMAIL_FROM" \
        --mail-rcpt "$EMAIL_TO" \
        --user "${SMTP_USER}:${SMTP_PASS}" \
        --upload-file - \
        --connect-timeout 10 --max-time 30 \
        <<< "$message"
}

# --- Transport selection ---
if send_via_alertmanager; then
    echo "SUCCESS: Alert posted to Alertmanager (${ALERTMANAGER_URL})"
    logger -t nft-alert "Alert sent via Alertmanager: $SUBJECT"
    exit 0
fi

echo "WARNING: Alertmanager unavailable, trying direct SMTP..." >&2

if send_via_smtp; then
    echo "SUCCESS: Email sent to $EMAIL_TO via ${SMTP_HOST}"
    logger -t nft-alert "Email sent via SMTP to $EMAIL_TO: $SUBJECT"
    exit 0
fi

echo "ERROR: All transports failed — subject: $SUBJECT" >&2
logger -t nft-alert -p mail.err "Failed to send alert: $SUBJECT"
exit 1
