#!/usr/bin/env bash
# ./run.sh [fuji|mainnet]     default fuji
set -e
PROFILE="${1:-fuji}"
set -a
. "./profiles/${PROFILE}.env"
[ -f .env ] && . ./.env      # secrets last, so they win
set +a
echo "profile: ${PROFILE}  network: ${X402_NETWORK}  settle: ${SETTLE_MODE}  card: ${CARD_MODE}"
pkill -f "uvicorn pg" 2>/dev/null || true
pkill -f "uvicorn merchants" 2>/dev/null || true
sleep 1
uvicorn pg.policy_server:app --port 4020 --log-level warning &
env -u AGENT_PRIVATE_KEY -u POLICY_SECRET uvicorn merchants.server:app --port 4030 --log-level warning &
sleep 2
echo "policy :4020   merchants :4030   (the merchant process holds no keys)"
wait
