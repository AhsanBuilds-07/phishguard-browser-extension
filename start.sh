#!/bin/sh
# Starts the SentinelAI API with SMS gateway settings loaded from .env
# Fully compatible with both /bin/sh (dash) and /bin/bash

set -e
[ -n "${BASH_VERSION:-}" ] && set -o pipefail 2>/dev/null || true

cd "$(dirname "$0")"

# Load environment variables from .env if present
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

# Clean up empty variables so they don't count as configured
[ -z "${FAST2SMS_API_KEY:-}" ] && unset FAST2SMS_API_KEY || true
[ -z "${TWILIO_ACCOUNT_SID:-}" ] && unset TWILIO_ACCOUNT_SID || true
[ -z "${TWILIO_AUTH_TOKEN:-}" ] && unset TWILIO_AUTH_TOKEN || true
[ -z "${TWILIO_PHONE_NUMBER:-}" ] && unset TWILIO_PHONE_NUMBER || true
[ -z "${TWILIO_MESSAGING_SERVICE_SID:-}" ] && unset TWILIO_MESSAGING_SERVICE_SID || true

# Display gateway status
if [ -n "${FAST2SMS_API_KEY:-}" ]; then
  echo "📱 SMS Gateway: Fast2SMS ACTIVE for +91 carrier SMS dispatch"
elif [ -n "${TWILIO_ACCOUNT_SID:-}" ] && [ -n "${TWILIO_AUTH_TOKEN:-}" ]; then
  echo "📱 SMS Gateway: Twilio ACTIVE for carrier SMS dispatch"
else
  echo "🛡️  SMS Gateway: Sandbox Mode (OTP codes displayed on screen & in Admin Console)"
fi

# Detect virtualenv uvicorn executable
if [ -x "venv/bin/uvicorn" ]; then
  UVICORN="venv/bin/uvicorn"
elif [ -x ".venv/bin/uvicorn" ]; then
  UVICORN=".venv/bin/uvicorn"
elif command -v uvicorn >/dev/null 2>&1; then
  UVICORN="uvicorn"
else
  echo "Error: uvicorn not found. Run: python3 -m venv venv && ./venv/bin/pip install -r requirements-platform.txt"
  exit 1
fi

# Ensure port 8000 is free before binding
if command -v fuser >/dev/null 2>&1 && fuser 8000/tcp >/dev/null 2>&1; then
  echo "⚠️  Port 8000 is already in use by a running instance. Freeing port 8000..."
  fuser -k 8000/tcp 2>/dev/null || true
  sleep 1
fi

echo "🚀 Starting SentinelAI Platform at http://127.0.0.1:8000 ..."
exec "$UVICORN" ml.platform_api:app --host 127.0.0.1 --port 8000
