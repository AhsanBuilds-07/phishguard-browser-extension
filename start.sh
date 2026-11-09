#!/usr/bin/env bash
# Starts the SentinelAI API with SMS gateway settings loaded from .env
set -euo pipefail
cd "$(dirname "$0")"

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# Empty values would look "configured" to nothing, but unset them for clarity.
for var in FAST2SMS_API_KEY TWILIO_ACCOUNT_SID TWILIO_AUTH_TOKEN TWILIO_PHONE_NUMBER TWILIO_MESSAGING_SERVICE_SID; do
  if [ -z "${!var:-}" ]; then unset "$var"; fi
done

if [ -n "${FAST2SMS_API_KEY:-}" ]; then
  echo "SMS: Fast2SMS enabled for +91 numbers${TWILIO_PHONE_NUMBER:+ (Twilio fallback on)}"
elif [ -n "${TWILIO_ACCOUNT_SID:-}" ] && [ -n "${TWILIO_AUTH_TOKEN:-}" ] && [ -n "${TWILIO_PHONE_NUMBER:-${TWILIO_MESSAGING_SERVICE_SID:-}}" ]; then
  echo "SMS: Twilio enabled (sender ${TWILIO_PHONE_NUMBER:-messaging service})"
else
  echo "SMS: no gateway configured in .env - OTP codes will show on screen (sandbox mode)"
fi

exec venv/bin/uvicorn ml.platform_api:app --host 127.0.0.1 --port 8000
