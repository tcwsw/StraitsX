#!/usr/bin/env bash
# ./run.sh [fuji|mainnet]        normal demo. Policy tier loads its own .env.policy
#                                (AGENT_PRIVATE_KEY, POLICY_SECRET); the merchant process
#                                never sees any of AGENT_PRIVATE_KEY / POLICY_SECRET /
#                                RELAYER_PRIVATE_KEY. Default fuji.
# ./run.sh live-self-transfer    INTERACTIVE ONLY. Real Avalanche mainnet self-transfer
#                                demo (payer wallet == merchant recipient) — see
#                                tools/live_self_transfer.py. Refuses to run unattended;
#                                never invoke this from CI or a script.
set -e

if [ "${1:-}" = "live-self-transfer" ]; then
    if [ ! -t 0 ]; then
        echo "live-self-transfer refuses to run without an interactive terminal (stdin is not a tty)." >&2
        exit 1
    fi
    set -a
    . "./profiles/mainnet.env"
    [ -f .env.policy ] && . ./.env.policy      # secrets last, so they win
    set +a
    echo "profile: mainnet  network: ${X402_NETWORK}  settle: ${SETTLE_MODE}  card: ${CARD_MODE}"
    pkill -f "uvicorn pg" 2>/dev/null || true
    pkill -f "uvicorn merchants" 2>/dev/null || true
    sleep 1
    uvicorn pg.policy_server:app --port 4020 --log-level warning &
    # This flow's whole point is a REAL on-chain settlement, so the merchant process
    # (which alone calls merchants/facilitator.settle()) needs RELAYER_PRIVATE_KEY here.
    # It still never sees AGENT_PRIVATE_KEY or POLICY_SECRET — those stay exclusive to
    # pg/policy_server.py.
    env -u AGENT_PRIVATE_KEY -u POLICY_SECRET uvicorn merchants.server:app --port 4030 --log-level warning &
    sleep 2
    echo "policy :4020   merchants :4030   (merchant process holds only its own RELAYER_PRIVATE_KEY)"
    set +e
    python -m tools.live_self_transfer
    status=$?
    set -e
    kill %1 %2 2>/dev/null || true
    exit $status
fi

PROFILE="${1:-fuji}"
set -a
. "./profiles/${PROFILE}.env"
[ -f .env.policy ] && . ./.env.policy      # secrets last, so they win
set +a
echo "profile: ${PROFILE}  network: ${X402_NETWORK}  settle: ${SETTLE_MODE}  card: ${CARD_MODE}"
pkill -f "uvicorn pg" 2>/dev/null || true
pkill -f "uvicorn merchants" 2>/dev/null || true
sleep 1
uvicorn pg.policy_server:app --port 4020 --log-level warning &
env -u AGENT_PRIVATE_KEY -u POLICY_SECRET -u RELAYER_PRIVATE_KEY uvicorn merchants.server:app --port 4030 --log-level warning &
sleep 2
echo "policy :4020   merchants :4030   (the merchant process holds no keys)"
wait

