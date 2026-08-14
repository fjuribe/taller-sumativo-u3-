#!/bin/bash
#-------------------------------------------------------------------------------
# invoke-ir.sh
# Respuesta ante incidentes automatizada en Linux (SecOps)
# Recolección volátil -> integridad -> contención -> sello de evidencia
#-------------------------------------------------------------------------------
set -euo pipefail

# Constantes (inmutables)
readonly EVIDENCE_DIR="/var/log/ir_evidence_$(date +%Y%m%d_%H%M%S)"
readonly IP_SOSPECHOSA="203.0.113.50"
readonly BINARIOS_CRITICOS=("/usr/bin/ssh" "/usr/bin/sudo" "/bin/bash" "/usr/sbin/sshd")
readonly CPU_THRESHOLD="10.0"

# Logging: consola + bitácora de auditoría
log() {
    local nivel="${1:-INFO}"
    local mensaje="${2:-}"
    printf "[%s] [%-8s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$nivel" "$mensaje" \
        | tee -a "${EVIDENCE_DIR}/ir_execution.log"
}

#--- 1. Validación de privilegios y directorio de evidencia --------------------
if [[ "${EUID}" -ne 0 ]]; then
    echo "CRITICAL: Este script debe ejecutarse como root." >&2
    exit 1
fi

mkdir -p "${EVIDENCE_DIR}"
chmod 700 "${EVIDENCE_DIR}"
chown root:root "${EVIDENCE_DIR}"
: > "${EVIDENCE_DIR}/ir_execution.log"
chmod 600 "${EVIDENCE_DIR}/ir_execution.log"

log "INFO" "Iniciando protocolo IR. Evidencia: ${EVIDENCE_DIR}"
log "INFO" "IP sospechosa: ${IP_SOSPECHOSA}"
log "INFO" "Host: $(hostname) | Kernel: $(uname -r)"

#--- 2. Evidencia volátil: procesos (antes de cualquier contención) ------------
log "INFO" "Capturando procesos (ps aux --forest)"

if ! ps aux --forest > "${EVIDENCE_DIR}/01_procesos_forest.txt" 2>&1; then
    log "WARNING" "ps --forest no disponible; usando ps aux"
    ps aux > "${EVIDENCE_DIR}/01_procesos_forest.txt" 2>&1
fi
ps aux > "${EVIDENCE_DIR}/01_procesos_aux.txt" 2>&1

# Sospechosos: sin TTY y CPU elevada
awk -v thr="${CPU_THRESHOLD}" '
    NR == 1 { next }
    {
        tty = $7
        cpu = $3 + 0
        if ((tty == "?" || tty == "-") && cpu >= thr) print
    }
' "${EVIDENCE_DIR}/01_procesos_aux.txt" > "${EVIDENCE_DIR}/01_procesos_sospechosos.txt" || true

sospechosos="$(wc -l < "${EVIDENCE_DIR}/01_procesos_sospechosos.txt" | tr -d ' ')"
if [[ "${sospechosos}" -gt 0 ]]; then
    log "WARNING" "Procesos sin TTY con CPU >= ${CPU_THRESHOLD}%: ${sospechosos}"
else
    log "INFO" "Sin procesos sin TTY con CPU elevada"
fi

#--- 3. Evidencia de red -------------------------------------------------------
log "INFO" "Capturando conexiones (ss -tunap)"
ss -tunap > "${EVIDENCE_DIR}/02_conexiones_ss.txt" 2>&1 || log "ERROR" "Fallo al ejecutar ss"

# ESTAB hacia/desde externos (excluye loopback)
awk '
    /ESTAB/ {
        if ($0 ~ /127\.0\.0\.1/ || $0 ~ /\[::1\]/ || $0 ~ /::1:/) next
        print
    }
' "${EVIDENCE_DIR}/02_conexiones_ss.txt" > "${EVIDENCE_DIR}/02_conexiones_externas_estab.txt" || true

ext_count="$(wc -l < "${EVIDENCE_DIR}/02_conexiones_externas_estab.txt" | tr -d ' ')"
log "INFO" "Conexiones ESTAB externas: ${ext_count}"

if grep -F "${IP_SOSPECHOSA}" "${EVIDENCE_DIR}/02_conexiones_ss.txt" \
    > "${EVIDENCE_DIR}/02_conexiones_ip_sospechosa.txt" 2>/dev/null; then
    hits="$(wc -l < "${EVIDENCE_DIR}/02_conexiones_ip_sospechosa.txt" | tr -d ' ')"
    log "WARNING" "Coincidencias con ${IP_SOSPECHOSA}: ${hits}"
else
    : > "${EVIDENCE_DIR}/02_conexiones_ip_sospechosa.txt"
    log "INFO" "Sin conexiones activas con ${IP_SOSPECHOSA}"
fi

#--- 4. Integridad de binarios críticos (SHA-256) ------------------------------
log "INFO" "Calculando SHA-256 de binarios críticos"
integrity_file="${EVIDENCE_DIR}/03_integridad_binarios.sha256"
: > "${integrity_file}"

for binario in "${BINARIOS_CRITICOS[@]}"; do
    if [[ -e "${binario}" && -r "${binario}" ]]; then
        sha256sum "${binario}" >> "${integrity_file}"
        log "INFO" "Hash OK: ${binario}"
    elif [[ ! -e "${binario}" ]]; then
        echo "MISSING  ${binario}" >> "${integrity_file}"
        log "CRITICAL" "Binario ausente: ${binario}"
    else
        echo "UNREADABLE  ${binario}" >> "${integrity_file}"
        log "CRITICAL" "Binario no legible: ${binario}"
    fi
done

#--- 5. Contención inicial (iptables, idempotente) -----------------------------
# Se aplica DESPUÉS de recolectar evidencia volátil
log "INFO" "Respaldo iptables (antes de contención)"
iptables-save > "${EVIDENCE_DIR}/04_iptables_before.rules" 2>&1 || \
    log "WARNING" "iptables-save (before) con errores"

aplicar_drop() {
    local chain="$1"
    local flag="$2"   # -s o -d
    local ip="$3"
    if iptables -C "${chain}" "${flag}" "${ip}" -j DROP 2>/dev/null; then
        log "INFO" "Regla ya existe: ${chain} ${flag} ${ip} -j DROP"
    else
        iptables -A "${chain}" "${flag}" "${ip}" -j DROP
        log "WARNING" "Regla aplicada: ${chain} ${flag} ${ip} -j DROP"
    fi
}

log "INFO" "Bloqueando ${IP_SOSPECHOSA} (INPUT origen / OUTPUT destino)"
aplicar_drop "INPUT"  "-s" "${IP_SOSPECHOSA}"
aplicar_drop "OUTPUT" "-d" "${IP_SOSPECHOSA}"

{
    echo "=== INPUT ==="
    iptables -L INPUT -n -v --line-numbers 2>&1 || true
    echo
    echo "=== OUTPUT ==="
    iptables -L OUTPUT -n -v --line-numbers 2>&1 || true
    echo
    echo "=== Reglas con IP sospechosa ==="
    iptables-save 2>/dev/null | grep -F "${IP_SOSPECHOSA}" || echo "(sin coincidencias)"
} > "${EVIDENCE_DIR}/04_iptables_verificacion.txt"

iptables-save > "${EVIDENCE_DIR}/04_iptables_after.rules" 2>&1 || true

if iptables-save 2>/dev/null | grep -qF "${IP_SOSPECHOSA}"; then
    log "INFO" "Contención verificada para ${IP_SOSPECHOSA}"
else
    log "CRITICAL" "No se verificó la regla para ${IP_SOSPECHOSA}"
fi

log "INFO" "Nota: DROP total solo sobre esa IP; no se modificó la política por defecto"

#--- 6. Cierre: inventario y sello criptográfico -------------------------------
log "INFO" "Generando manifiesto SHA-256 de la evidencia"

find "${EVIDENCE_DIR}" -type f ! -name '05_MANIFEST.sha256' | sort \
    > "${EVIDENCE_DIR}/05_inventario_archivos.txt"

(
    cd "${EVIDENCE_DIR}"
    find . -type f ! -name '05_MANIFEST.sha256' -print0 | sort -z | xargs -0 sha256sum
) > "${EVIDENCE_DIR}/05_MANIFEST.sha256"
chmod 400 "${EVIDENCE_DIR}/05_MANIFEST.sha256"

log "INFO" "Manifiesto: ${EVIDENCE_DIR}/05_MANIFEST.sha256"
log "INFO" "Protocolo IR finalizado"

echo
echo "================================================================"
echo " IR COMPLETADO"
echo " Evidencia : ${EVIDENCE_DIR}"
echo " Manifiesto: ${EVIDENCE_DIR}/05_MANIFEST.sha256"
echo " Log       : ${EVIDENCE_DIR}/ir_execution.log"
echo "================================================================"

exit 0
