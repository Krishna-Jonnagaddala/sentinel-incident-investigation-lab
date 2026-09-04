#!/usr/bin/env bash
#
# 03-ssh-pivot.sh
# Simulates a lateral-movement attempt from the compromised workstation to the Linux
# host: a handful of failed SSH logons that generate "Failed password" Syslog entries on
# WEB-SRV-02. This is the pivot the case shows failing.
#
# LAB ONLY. Run this FROM FIN-WKS-04 (10.10.20.45) against a Linux host you own. It makes
# real SSH connection attempts with wrong passwords - nothing is exploited, and by design
# none of the attempts succeed.
#
# Requires: sshpass (to feed wrong passwords non-interactively).
#   Ubuntu:  sudo apt-get install -y sshpass

set -u

TARGET="${1:-10.10.20.60}"      # WEB-SRV-02
USER="${2:-a.patel}"
ATTEMPTS="${3:-8}"

echo "[*] SSH pivot simulation: ${USER}@${TARGET}, ${ATTEMPTS} attempts (all will fail)."
echo "[*] Lab use only."

for i in $(seq 1 "${ATTEMPTS}"); do
    WRONG_PW="Autumn2024!$((RANDOM % 9000 + 1000))"
    # -o BatchMode=no and a wrong password => a genuine 'Failed password' on the target.
    sshpass -p "${WRONG_PW}" \
        ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=5 \
            -o PreferredAuthentications=password \
            -o PubkeyAuthentication=no \
            "${USER}@${TARGET}" "true" 2>/dev/null
    echo "    attempt ${i}/${ATTEMPTS} (failed, as intended)"
    sleep "$(awk "BEGIN{print 0.5 + rand()}")"
done

echo "[*] Pivot simulation complete. Check Syslog on ${TARGET} for 'Failed password from 10.10.20.45'."
