# Protocolo de Respuesta a Incidentes (IR) — Linux

Script de automatización para **recolección de evidencia forense**, **verificación de integridad** y **contención de red** en hosts Linux comprometidos o bajo sospecha.

Diseñado como entregable académico de ciberseguridad / respuesta a incidentes: documenta el flujo completo desde la detección hasta el bloqueo de una IP maliciosa, dejando rastro auditable (logs + hashes SHA-256).

---

## En qué consiste

Ante un indicador de compromiso (IoC) —por ejemplo, tráfico hacia una IP externa sospechosa— el operador ejecuta un único script que:

1. **Identifica** procesos y conexiones de red en el momento del incidente.
2. **Verifica** que binarios críticos del sistema no hayan sido alterados (SSH, sudo, bash, sshd).
3. **Contiene** el IoC bloqueando la IP en `iptables` (entrada y salida), de forma idempotente.
4. **Preserva** toda la evidencia en disco con un manifiesto de integridad (`SHA-256`).

El flujo sigue buenas prácticas de IR: **primero recolectar y documentar, después contener**, para no destruir pruebas.

---

## Características

| Capacidad | Descripción |
|-----------|-------------|
| Inventario de procesos | `ps aux` y árbol (`--forest`); filtro heurístico de comandos sospechosos |
| Conexiones de red | `ss -tunap`; conexiones establecidas externas; cruce con la IP IoC |
| Integridad de binarios | SHA-256 de `/usr/bin/ssh`, `/usr/bin/sudo`, `/bin/bash`, `/usr/sbin/sshd` |
| Contención | Reglas `iptables` DROP en INPUT/OUTPUT (requiere root); comprobación previa (`-C`) para no duplicar |
| Cadena de custodia | Log con timestamps + `05_MANIFEST.sha256` de todos los artefactos |
| Idempotencia | Puede reejecutarse sin duplicar reglas de firewall |
| Modo sin root | Recolecta evidencia y documenta el bloqueo esperado si no hay privilegios |

---

## Estructura del repositorio

```text
entregables/
├── README.md                 # Este documento
├── LEEME.txt                 # Instrucciones rápidas (ES)
├── INFORME_TECNICO.md        # Análisis, hallazgos y justificación técnica
├── invoke-ir.sh              # Script principal del protocolo IR
└── evidencia_ejecucion/      # Artefactos generados en una corrida de ejemplo
    ├── ir_execution.log
    ├── 01_procesos_*.txt
    ├── 02_conexiones_*.txt
    ├── 03_integridad_binarios.sha256
    ├── 04_iptables_*.rules / 04_iptables_verificacion.txt
    ├── 05_inventario_archivos.txt
    └── 05_MANIFEST.sha256
```

---

## Requisitos

- **SO:** Linux (utilidades estándar GNU/Linux)
- **Shell:** Bash
- **Herramientas:** `ps`, `ss` (iproute2), `sha256sum`, `date`, `find`
- **Contención:** `iptables` / `iptables-save` (requiere root o `sudo`)
- **Privilegios:**
  - Usuario normal → fases 1–3 y 5 (recolección e integridad)
  - `root` / `sudo` → fase 4 (bloqueo de IP)

---

## Uso rápido

```bash
cd entregables
chmod +x invoke-ir.sh

# Ejecución completa (laboratorio / host de prueba)
sudo ./invoke-ir.sh

# Solo recolección de evidencia (sin modificar firewall)
./invoke-ir.sh
```

### Variables de entorno opcionales

| Variable | Por defecto | Uso |
|----------|-------------|-----|
| `SUSPICIOUS_IP` | `203.0.113.50` | IoC de red a buscar y bloquear (RFC 5737) |
| `EVIDENCE_DIR` | `./evidencia_ejecucion` | Directorio de salida de artefactos |

```bash
sudo SUSPICIOUS_IP=198.51.100.10 ./invoke-ir.sh
sudo EVIDENCE_DIR=/tmp/ir_caso_001 ./invoke-ir.sh
```

---

## Fases del protocolo

| Fase | Acción | Artefactos |
|------|--------|------------|
| **1** | Captura de procesos (`ps aux`, árbol, heurística de sospechosos) | `01_procesos_*.txt` |
| **2** | Captura de sockets y cruce con la IP IoC | `02_conexiones_*.txt` |
| **3** | Hash SHA-256 de binarios críticos | `03_integridad_binarios.sha256` |
| **4** | Snapshot de `iptables` antes/después + DROP de la IP IoC | `04_iptables_*` |
| **5** | Inventario de archivos y manifiesto de integridad | `05_*` |

Todas las operaciones quedan en `ir_execution.log` con marca de tiempo.

---

## Cómo probarlo

### 1. Recolección sin root

```bash
./invoke-ir.sh
ls -la evidencia_ejecucion/
cat evidencia_ejecucion/ir_execution.log
```

**Esperado:** archivos `01_*`, `02_*`, `03_*` y `05_*`; el log indica si la contención quedó pendiente por falta de privilegios.

### 2. Contención completa (root)

```bash
sudo ./invoke-ir.sh
sudo iptables -L INPUT  -n -v | grep -- 203.0.113.50
sudo iptables -L OUTPUT -n -v | grep -- 203.0.113.50
```

**Esperado:** reglas `DROP` en INPUT (origen) y OUTPUT (destino); `04_iptables_after.rules` refleja el cambio.

### 3. Idempotencia

```bash
sudo ./invoke-ir.sh
sudo ./invoke-ir.sh
```

**Esperado:** no se duplican reglas (`iptables -C` antes de `-A`).

### 4. Cadena de custodia

```bash
cd evidencia_ejecucion
sha256sum -c 05_MANIFEST.sha256
```

**Esperado:** todos los archivos del manifiesto en estado `OK` (si no se modificaron tras la corrida).

### 5. IoC personalizado

```bash
sudo SUSPICIOUS_IP=198.51.100.25 ./invoke-ir.sh
grep -R "198.51.100.25" evidencia_ejecucion/
```

---

## Evidencia incluida

La carpeta `evidencia_ejecucion/` incluye una **corrida de referencia**:

- Listados reales de procesos y conexiones (`ps` / `ss`)
- Hashes SHA-256 reales de binarios del sistema
- Capturas / plantillas de reglas `iptables` (el bloqueo efectivo requiere `sudo` en el host destino)
- Manifiesto `05_MANIFEST.sha256` para validar integridad de los artefactos

Análisis detallado: **[INFORME_TECNICO.md](./INFORME_TECNICO.md)**.

---

## Notas de seguridad y alcance

- Con root, el script **modifica el firewall**. Úselo solo en hosts autorizados (laboratorio, VM o incidente bajo mandato).
- La IP por defecto (`203.0.113.50`) es del rango de documentación **RFC 5737**; no enruta tráfico real en Internet.
- No sustituye un EDR/SIEM ni un playbook completo de CSIRT: es un **protocolo mínimo automatizable** de contención y preservación de evidencia en Linux.
- En un incidente real, preserve la evidencia y continúe con análisis forense (memoria, disco, timeline).

---

## Documentación relacionada

| Documento | Contenido |
|-----------|-----------|
| [LEEME.txt](./LEEME.txt) | Guía breve de uso en español |
| [INFORME_TECNICO.md](./INFORME_TECNICO.md) | Metodología, resultados y conclusiones |
| `invoke-ir.sh` | Implementación del protocolo |

---

## Licencia y uso académico

Material elaborado como **entregable académico** de programación / ciberseguridad. Uso educativo y de laboratorio. Adapte variables, rutas y políticas de contención antes de emplearlo en producción.
