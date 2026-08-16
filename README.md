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
| Requisito de root | El script corta al inicio si no se ejecuta como root, antes de tocar nada |

---

## Estructura del repositorio

```text
README.md                   # Este documento
LEEME.txt                   # Instrucciones rápidas (ES)
INFORME_TECNICO.md          # Análisis, hallazgos y justificación técnica
invoke-ir.sh                # Script principal del protocolo IR
evidencia_ejecucion/        # Artefactos generados en una corrida de ejemplo
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
- **Privilegios:** el script exige `root` desde el inicio (`EUID = 0`); si no hay privilegios, corta la ejecución antes de tocar nada.

---

## Uso rápido

```bash
chmod +x invoke-ir.sh
sudo ./invoke-ir.sh
```

La IP a bloquear (`203.0.113.50`, rango de documentación RFC 5737) y el directorio de evidencia (`/var/log/ir_evidence_<fecha>_<hora>`) están fijos como `readonly` dentro del script. Para usar otra IP u otra ruta hay que editar esas constantes al principio de `invoke-ir.sh`.

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

### 1. Sin privilegios de root

```bash
./invoke-ir.sh
```

**Esperado:** el script corta de inmediato con `CRITICAL: Este script debe ejecutarse como root.` (sale antes de tocar nada).

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
cd /var/log/ir_evidence_<fecha_hora>
sha256sum -c 05_MANIFEST.sha256
```

**Esperado:** todos los archivos del manifiesto en estado `OK` (si no se modificaron tras la corrida).

---

## Evidencia incluida

La carpeta `evidencia_ejecucion/` es una copia de una corrida real de `sudo ./invoke-ir.sh` (hecha en un contenedor Linux con permisos de root), tal cual la generó el script en `/var/log/ir_evidence_<fecha_hora>/`:

- Listados reales de procesos y conexiones (`ps` / `ss`)
- Hashes SHA-256 reales de binarios del sistema
- Reglas `iptables` antes/después con el bloqueo de `203.0.113.50` ya aplicado
- Manifiesto `05_MANIFEST.sha256`, verificado con `sha256sum -c` (todo `OK`, incluido el propio log)

Análisis detallado: **[INFORME_TECNICO.md](./INFORME_TECNICO.md)**.

### Reproducir la evidencia con Docker

No hace falta una VM Linux: el repo trae un `Dockerfile` que arma una imagen mínima (Ubuntu + `iptables`/`iproute2`/`procps`) y corre `invoke-ir.sh` como root dentro del contenedor.

```bash
docker build -t ir-lab .
mkdir -p var_log
docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW -v "$(pwd)/var_log:/var/log" ir-lab
ls var_log/ir_evidence_*
```

Al montar `/var/log` como volumen, la carpeta `ir_evidence_<fecha_hora>` queda directo en `var_log/` del host, igual que en un servidor real.

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
