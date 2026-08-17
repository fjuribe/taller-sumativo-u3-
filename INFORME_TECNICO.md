# Informe técnico
## Script de respuesta ante incidentes en Linux — `invoke-ir.sh`

**Módulo:** Programación para la ciberseguridad

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

**Supuestos del escenario:**

- El host sigue en pie y accesible por consola/SSH; no es un caso de "apagar y clonar disco".
- El equipo de respuesta tiene acceso `root` (o `sudo`), condición mínima para leer procesos de todos los usuarios, calcular hashes de binarios del sistema y tocar `iptables`.
- La IP `203.0.113.50` corresponde al rango de documentación **RFC 5737**; se usa como IoC de ejemplo porque no enruta tráfico real, lo que permite ejecutar y mostrar el bloqueo sin riesgo.
- No se asume la existencia de EDR, SIEM centralizado ni acceso a la red fuera del propio host: el script solo depende de utilidades ya instaladas en cualquier distribución Linux estándar.

---

## 3. Desarrollo del script

### 3.1 Estructura general

- Shebang `#!/bin/bash` y `set -euo pipefail` para fallar ante errores, variables no definidas o fallos en tuberías.
- Constantes con `readonly`: directorio de evidencia, IP sospechosa y lista de binarios críticos.
- Directorio `/var/log/ir_evidence_YYYYMMDD_HHMMSS` con `chmod 700` y dueño `root:root`.
- Función `log` que escribe en pantalla y en `ir_execution.log`.
- Salida inmediata si `EUID != 0` (el script exige root).

La combinación `set -e` (corta ante cualquier comando que falle), `-u` (corta si se usa una variable no definida) y `-o pipefail` (propaga el error de cualquier comando dentro de una tubería, no solo el último) evita que el script siga corriendo "a ciegas" tras un fallo silencioso — algo especialmente importante cuando el paso siguiente puede ser modificar el firewall. Declarar las constantes como `readonly` cierra la puerta a que un error de tipeo más adelante en el script sobrescriba, por ejemplo, la IP objetivo a mitad de la contención.

### 3.2 Evidencia volátil de procesos

- `ps aux --forest` → `01_procesos_forest.txt`
- `ps aux` → `01_procesos_aux.txt`
- Filtro con `awk`: procesos sin TTY (`?` o `-`) y `%CPU >= 10` → `01_procesos_sospechosos.txt`
- Si hay hallazgos, se deja un `WARNING` en el log.

Así se conserva una foto del estado en memoria al momento del incidente y un primer triaje de procesos raros. El umbral de `%CPU >= 10` es una heurística simple y deliberadamente conservadora: no reemplaza un análisis con EDR, pero como primer filtro manual sirve para no tener que leer a ojo cientos de líneas de `ps aux` bajo presión. Un proceso sin TTY (`?` o `-`) suele corresponder a un demonio o a algo lanzado por `cron`/`systemd`; si además consume CPU de forma sostenida, es candidato razonable a revisión prioritaria.

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

### 3.7 Pruebas y verificación

El script se probó de punta a punta en un contenedor Linux real (Ubuntu 22.04, con `iptables`, `iproute2` y `procps` instalados) usando el `Dockerfile` incluido en el repositorio, corriendo como `root` y con las capacidades `NET_ADMIN`/`NET_RAW` habilitadas para que `iptables` funcione de verdad y no solo se simule. Esto permitió validar, con ejecuciones reales y no solo revisión de código:

- que el script corta con `CRITICAL` si no se ejecuta como root, antes de tocar nada;
- que la regla `DROP` se aplica y aparece en `iptables -L`;
- que una segunda ejecución detecta la regla existente (`iptables -C`) y no la duplica — la idempotencia funciona en la práctica, no solo en la lectura del código;
- que `sha256sum -c 05_MANIFEST.sha256` valida el paquete completo.

Este último punto reveló un defecto real: la primera versión del script seguía escribiendo en `ir_execution.log` (los mensajes "Manifiesto generado" y "Protocolo IR finalizado") **después** de calcular el manifiesto, por lo que el hash del log guardado en `05_MANIFEST.sha256` nunca coincidía con el archivo final — justo el artefacto que debía demostrar la cadena de custodia quedaba marcado `FAILED`. Se corrigió dejando de escribir en el log una vez que el manifiesto se generó (el mensaje de cierre pasa a imprimirse solo por consola, igual que el resumen final). Tras el cambio, las doce entradas del manifiesto verifican en `OK`, incluido el propio log. Este hallazgo confirma el valor de no limitarse a una revisión estática: encontrar el problema requirió ejecutar el script y correr la verificación completa, tal como lo haría el operador que reciba esta evidencia.

Un contenedor recién creado no tiene procesos ruidosos ni conexiones activas, así que una primera corrida "limpia" deja `01_procesos_sospechosos.txt` y `02_conexiones_ip_sospechosa.txt` vacíos — lo cual es correcto, pero no demuestra que los filtros realmente detecten algo. Para dejar evidencia que muestre los tres mecanismos en acción, antes de la corrida final se generaron condiciones de prueba reales dentro del contenedor (no se editó ningún archivo de salida a mano):

- un proceso `yes` en segundo plano, sin TTY y con ~90% de CPU, para activar el filtro de procesos sospechosos;
- una conexión TCP real y sostenida hacia un host externo (`1.1.1.1:80`), para poblar las conexiones `ESTAB` externas;
- un alias de loopback con la propia IP del IoC (`ip addr add 203.0.113.50/32 dev lo`) y una conexión real contra ese alias, para que `ss` mostrara una coincidencia genuina con `203.0.113.50`.

Con esas condiciones activas, la corrida quedó registrada como corresponde: `WARNING Procesos sin TTY con CPU >= 10.0%: 1`, `Conexiones ESTAB externas: 1` y `WARNING Coincidencias con 203.0.113.50: 1`. Es la evidencia que está en `evidencia_ejecucion/` en este entregable.

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
Se capturan procesos y conexiones *antes* de tocar el firewall. Son lecturas (`ps`, `ss`); no se matan procesos ni se reinicia el host en esta fase. Esto sigue el orden de volatilidad descrito en RFC 3227: la memoria y el estado de red se pierden apenas se reinicia un proceso, se cierra una conexión o se reinicia el host, mientras que los binarios en disco y las reglas de firewall son mucho más estables. Contener primero (por ejemplo, cortando la IP antes de fotografiar procesos) arriesgaría perder justo la evidencia más frágil, sin ninguna ganancia real de seguridad si el atacante no está reaccionando en tiempo real al bloqueo.

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

## 8. Limitaciones y trabajo futuro

- El script asume una lista fija de binarios críticos y una sola IP de contención; ambos valores están en `readonly` y requieren editar el script para un caso distinto, en vez de parametrizarse por línea de comandos. Para un solo IoC puntual es suficiente y evita errores de invocación; para un CSIRT que lo use a diario, valdría la pena agregar argumentos (`--ip`, `--binarios`).
- La verificación de integridad compara contra un hash calculado en el momento, no contra una línea base previa (por ejemplo, un manifiesto de binarios "limpios" guardado antes del incidente). Sin esa línea base, un binario ya troyanizado desde antes del despliegue pasaría sin marcarse.
- No hay captura de memoria RAM ni de disco (imagen forense); el script cubre la primera respuesta, no una investigación forense completa.
- La lista de binarios y el umbral de CPU están pensados para un servidor web genérico; en otros roles (base de datos, balanceador) convendría revisar ambos valores.

## 9. Conclusiones

1. `invoke-ir.sh` cubre el flujo pedido: estructura segura, procesos, red, integridad, contención y cierre con sello.
2. Respeta la volatilidad: primero memoria/red, después cambios de estado.
3. Deja evidencia legible y verificable para continuar la investigación; esto se comprobó ejecutando el script de punta a punta, no solo leyendo el código, lo que además permitió detectar y corregir un defecto real en el sellado del log.
4. Es suficiente como respuesta inicial; un análisis forense profundo (volcado de RAM, disco, correlación SIEM) queda como paso siguiente fuera de este script.

---

## Referencias breves

- Buenas prácticas de recolección de evidencia y orden de volatilidad (RFC 3227).
- Manuales: `ps(1)`, `ss(8)`, `iptables(8)`, `sha256sum(1)`.
