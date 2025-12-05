#!/bin/bash
# HA Failover Test Script for TLSGate NG Poolgen

POOLGEN="./build/tlsgateNG-poolgen"
LOG_PRIMARY="/tmp/poolgen-primary.log"
LOG_BACKUP="/tmp/poolgen-backup.log"

echo "═══════════════════════════════════════════════════════════════"
echo "  TLSGate NG - HA Failover Test"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Cleanup
cleanup() {
    echo "[CLEANUP] Stopping poolgen processes..."
    pkill -f "tlsgateNG-poolgen.*--ha-role" 2>/dev/null || true
    sleep 1
    rm -f /dev/shm/tlsgateNG_keypool 2>/dev/null || true
    rm -f /var/run/tlsgateNG/tlsgateNG-poolgen.lock 2>/dev/null || true
}

show_status() {
    echo ""
    $POOLGEN --shm-status 2>/dev/null | grep -E "Total:|PID:|Heartbeat:" || echo "  (no SHM)"
    echo ""
}

cleanup

# Initialize (creates config etc.)
echo "[INIT] Initializing..."
$POOLGEN --help >/dev/null 2>&1
mkdir -p /var/run/tlsgateNG

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 1: Start PRIMARY"
echo "═══════════════════════════════════════════════════════════════"

$POOLGEN --poolkeygen --shm --ha-role primary > "$LOG_PRIMARY" 2>&1 &
PRIMARY_PID=$!
echo "[PRIMARY] PID $PRIMARY_PID"
sleep 8
show_status

echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 2: Start BACKUP (should wait)"
echo "═══════════════════════════════════════════════════════════════"

$POOLGEN --poolkeygen --shm --ha-role backup > "$LOG_BACKUP" 2>&1 &
BACKUP_PID=$!
echo "[BACKUP] PID $BACKUP_PID"
sleep 5

echo "[CHECK] Backup status:"
grep -E "STANDBY|waiting" "$LOG_BACKUP" | head -2 || tail -3 "$LOG_BACKUP"
show_status

echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 3: KILL PRIMARY"
echo "═══════════════════════════════════════════════════════════════"

echo "[KILL] SIGKILL to PRIMARY (PID $PRIMARY_PID)..."
kill -9 $PRIMARY_PID 2>/dev/null || true

echo "[WAIT] Waiting for failover (15s)..."
for i in {1..15}; do sleep 1; echo -n "."; done
echo ""

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 4: Verify FAILOVER"
echo "═══════════════════════════════════════════════════════════════"

show_status

echo "[CHECK] Backup takeover log:"
grep -E "Acquired|ACTIVE|leadership" "$LOG_BACKUP" | tail -3 || echo "  (none)"

OWNER=$($POOLGEN --shm-status 2>/dev/null | grep "PID:" | awk '{print $2}')
echo ""
if [ "$OWNER" = "$BACKUP_PID" ]; then
    echo "✅ SUCCESS: Backup (PID $BACKUP_PID) is now keygen owner!"
else
    echo "⚠️  Owner is $OWNER (expected $BACKUP_PID)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 5: Check Heartbeat"
echo "═══════════════════════════════════════════════════════════════"

sleep 5
$POOLGEN --shm-status 2>/dev/null | grep "Heartbeat:" || echo "(no heartbeat info)"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  CLEANUP"
echo "═══════════════════════════════════════════════════════════════"

kill $BACKUP_PID 2>/dev/null || true
echo "Logs: $LOG_PRIMARY, $LOG_BACKUP"
echo ""
echo "To check refill debug:"
echo "  grep REFILL $LOG_PRIMARY $LOG_BACKUP"
