# Informe técnico
## Script de respuesta ante incidentes en Linux — `invoke-ir.sh`

**Módulo:** Programación para la ciberseguridad  
**Unidad:** Scripting con Linux Shell (Bash)  
**Entregable:** script + evidencia de ejecución + este informe

---

## 1. Resumen ejecutivo

Se desarrolló el script Bash `invoke-ir.sh` para automatizar una respuesta inicial ante una alerta del SIEM en un servidor web Linux con sospecha de intrusión activa. El script:

- crea un directorio de evidencia con marca temporal y permisos restrictivos;
- recolecta evidencia volátil de procesos y red;
- calcula hashes SHA-256 de binarios críticos;
- contiene la IP sospechosa `203.0.113.50` con `iptables` (sin duplicar reglas);
- registra cada acción en un log y sella la evidencia con un manifiesto SHA-256.

Todo se hace con herramientas nativas del sistema (`ps`, `ss`, `awk`, `sha256sum`, `iptables`, `find`, `tee`), sin instalar paquetes durante la emergencia.

---

## 2. Descripción del escenario

| Elemento | Valor |
|----------|--------|
| Evento | Alerta SIEM por comportamiento anómalo / posible C2 |
| Activo | Servidor web de producción (Linux) |
| IoC de red | IP `203.0.113.50` |
| Objetivo | Preservar volatilidad, dejar rastro auditable y aislar la IP |

El orden de trabajo sigue el criterio de volatilidad (primero lo que más rápido se pierde: procesos y conexiones; después disco e integridad; al final la contención que cambia el estado del firewall).

---

## 3. Desarrollo del script

### 3.1 Estructura general

- Shebang `#!/bin/bash` y `set -euo pipefail` para fallar ante errores, variables no definidas o fallos en tuberías.
- Constantes con `readonly`: directorio de evidencia, IP sospechosa y lista de binarios críticos.
- Directorio `/var/log/ir_evidence_YYYYMMDD_HHMMSS` con `chmod 700` y dueño `root:root`.
- Función `log` que escribe en pantalla y en `ir_execution.log`.
- Salida inmediata si `EUID != 0` (el script exige root).

### 3.2 Evidencia volátil de procesos

- `ps aux --forest` → `01_procesos_forest.txt`
- `ps aux` → `01_procesos_aux.txt`
- Filtro con `awk`: procesos sin TTY (`?` o `-`) y `%CPU >= 10` → `01_procesos_sospechosos.txt`
- Si hay hallazgos, se deja un `WARNING` en el log.

Así se conserva una foto del estado en memoria al momento del incidente y un primer triaje de procesos raros.

### 3.3 Evidencia de red

- `ss -tunap` → `02_conexiones_ss.txt` (conexiones con proceso asociado).
- Filtro de sesiones `ESTAB` excluyendo `127.0.0.1` / `::1` → `02_conexiones_externas_estab.txt`.
- Búsqueda de la IP del IoC → `02_conexiones_ip_sospechosa.txt`.

### 3.4 Verificación de integridad

Binarios revisados: `/usr/bin/ssh`, `/usr/bin/sudo`, `/bin/bash`, `/usr/sbin/sshd`.

Por cada uno se calcula `sha256sum` y se guarda en `03_integridad_binarios.sha256`. Si falta o no se puede leer, se registra `MISSING` / `UNREADABLE` y un `CRITICAL` en el log.

### 3.5 Contención inicial

Después de recolectar lo volátil:

1. Se guarda el firewall actual (`04_iptables_before.rules`).
2. Se bloquea la IP en `INPUT` (origen) y `OUTPUT` (destino) con `DROP`.
3. Antes de agregar, se comprueba con `iptables -C` para no duplicar reglas.
4. Se verifica y se guarda el estado final (`04_iptables_verificacion.txt`, `04_iptables_after.rules`).

No se hace `iptables -F` ni se cambia la política por defecto: solo se aísla esa IP, para no tumbar el resto del servicio.

### 3.6 Cierre operativo

- Inventario de archivos generados.
- Manifiesto global `05_MANIFEST.sha256` con el hash de toda la evidencia.
- Mensaje final con la ruta del directorio para el operador.

Verificación posterior:

```bash
cd /var/log/ir_evidence_<timestamp>
sha256sum -c 05_MANIFEST.sha256
```

---

## 4. Evidencia recolectada

En este paquete, la carpeta `evidencia_ejecucion/` muestra el tipo de salida del script (procesos, red, hashes, log y manifiesto). En un servidor real, con:

```bash
sudo ./invoke-ir.sh
```

la evidencia queda en `/var/log/ir_evidence_<timestamp>/` con los mismos nombres de archivo.

| Archivo | Contenido |
|---------|-----------|
| `ir_execution.log` | Bitácora de lo ejecutado |
| `01_procesos_*.txt` | Estado y filtro de procesos |
| `02_conexiones_*.txt` | Sockets y foco en IP externa / IoC |
| `03_integridad_binarios.sha256` | Hashes de binarios críticos |
| `04_iptables_*.rules` / `*_verificacion.txt` | Firewall antes, después y comprobación |
| `05_MANIFEST.sha256` | Sello de integridad del paquete |

---

## 5. Medidas de contención aplicadas

| Regla | Efecto |
|-------|--------|
| `INPUT -s 203.0.113.50 -j DROP` | Corta tráfico entrante desde la IP |
| `OUTPUT -d 203.0.113.50 -j DROP` | Corta tráfico saliente hacia la IP |

La comprobación previa con `iptables -C` hace la acción **idempotente** (se puede volver a correr el script sin ensuciar la tabla). El respaldo before/after deja prueba de qué cambió.

---

## 6. Explicación técnica

**a) Preservar evidencia en una intrusión activa**  
Se capturan procesos y conexiones *antes* de tocar el firewall. Son lecturas (`ps`, `ss`); no se matan procesos ni se reinicia el host en esta fase.

**b) Trazabilidad**  
Cada paso pasa por `log` (fecha, nivel, mensaje) y el cierre genera un manifiesto SHA-256. Un tercero puede reconstruir qué se hizo y comprobar que los archivos no se alteraron después.

**c) Menos errores operativos**  
`set -euo pipefail`, chequeo de root, reglas de firewall sin duplicar y solo herramientas del sistema reducen fallos típicos bajo presión (olvidar el log, aplicar dos veces la misma regla, depender de un binario que no está instalado).

**d) Flujo IR básico alineado a SecOps**  
El script materializa un playbook corto y repetible: recolectar → señalar hallazgos → contener el IoC → sellar evidencia. Sirve como primera respuesta automatizable desde un operador o un orquestador.

---

## 7. Cómo ejecutar

```bash
chmod +x invoke-ir.sh
sudo ./invoke-ir.sh
```

Al terminar, el script imprime la ruta del directorio de evidencia.  
Si en laboratorio hay que deshacer el bloqueo:

```bash
sudo iptables -D INPUT  -s 203.0.113.50 -j DROP
sudo iptables -D OUTPUT -d 203.0.113.50 -j DROP
```

---

## 8. Conclusiones

1. `invoke-ir.sh` cubre el flujo pedido: estructura segura, procesos, red, integridad, contención y cierre con sello.
2. Respeta la volatilidad: primero memoria/red, después cambios de estado.
3. Deja evidencia legible y verificable para continuar la investigación.
4. Es suficiente como respuesta inicial; un análisis forense profundo (volcado de RAM, disco, correlación SIEM) queda como paso siguiente fuera de este script.

---

## Referencias breves

- Buenas prácticas de recolección de evidencia y orden de volatilidad (RFC 3227).
- Manuales: `ps(1)`, `ss(8)`, `iptables(8)`, `sha256sum(1)`.
