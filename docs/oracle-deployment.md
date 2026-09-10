# Desplegar FEE en Oracle Cloud

Guía revisada el 10 de septiembre de 2026. Configuración desplegada desde `deploy/oracle-auth-scan`, basada en `feature/auth-scan-modules` (`b97534a`), y transferida por rsync. Los cambios de configuración siguen sin commit/push: un `git clone` del remoto todavía no los incluye. Consulta también [el README](../README.md).

**FEE está desplegado en [https://backosisnt.ici-labs.com](https://backosisnt.ici-labs.com/api/v1/health)**; su health público devuelve 200. La VM `RanchoPuebloViejo` usa Ubuntu 22.04 ARM64 e IP `163.192.148.22`, en Querétaro. SSH fue recuperado y verificado con la clave del host contrastada por consola serie. La API construida en ARM nativo y PostgreSQL están healthy, con migración `823459897ec8`. El túnel Cloudflare está conectado y healthy, hacia `http://api:8000`, sin puertos de FEE publicados en el host.

El registro `/home/ubuntu/fee-server/DEPLOYMENT.json` conserva revisión base, URL, túnel, migración e imágenes utilizadas, sin credenciales.

El inventario por SSH confirmó ARM64, 23 GiB de RAM y Docker Compose v5.1.0. Por petición del usuario se eliminó el servicio Rancho completo: sus tres contenedores, volumen SQL, red, imágenes propias/API/PostgreSQL 15, código, respaldos y cron de `ubuntu`. La VM conserva su nombre. Los tres contenedores de MADTEC conservaron sus identificadores y horas de arranque. UFW está inactivo, lo que no descarta reglas iptables; `172.30.80.0/28` no se solapó con las rutas observadas. Repite el inventario antes de otros cambios y conserva MADTEC. Esto no acredita gratuidad ni facturación.

Se ejecutó `git fetch origin --prune` y se verificó el pull con fast-forward de `feature/auth-scan-modules`: estaba al día. La rama remota más reciente por fecha es `feature/engineer-1-passkey-auth` (`9858bba`), pero parte de `main` por separado: sustituye autenticación y esquema, y no incluye scans. No hay una migración entre ambas bases de datos. Este despliegue conserva `auth-scan-modules`; integrar passkeys requiere resolver esa diferencia antes de sustituirlo. Los archivos nuevos se transfirieron con el procedimiento del paso 4 y siguen sin commit/push.

## 1. Comprobar si tu instancia sigue dentro de lo gratuito

**Observado en la consola OCI el 10 de septiembre:** agosto de 2026 registró 2,976 OCPU-h y 17,856 GB-h A1, con precio, importe y excedente en cero. La consulta del 1 al 10 de septiembre, con datos disponibles del 1 al 9, mostró 880 OCPU-h y 5,280 GB-h A1 a cero. Cost Analysis, incluyendo todos los servicios, mostró **MX$0.00** para agosto y para septiembre consultado. El boot volume de 47 GB figuró como Always Free.

La suscripción aparece como **Universal Credits / Active / Infrastructure**; no se confirmó una etiqueta PAYG o Always Free para la cuenta. Los importes observados describen los períodos disponibles, no garantizan coste futuro ni sustituyen una factura final. Revisa retrasos de contabilización y estimaciones antes de redimensionar recursos. Para repetir la comprobación:

1. En **Billing & Cost Management → Billing → Subscriptions** abre la suscripción de infraestructura y confirma si la cuenta es Always Free o de pago/PAYG. La columna Type distingue Infrastructure/Applications; por sí sola no identifica PAYG. El aviso de cambio de límites no confirma un cargo. [Suscripciones](https://docs.oracle.com/en-us/iaas/Content/Billing/Concepts/subscriptions.htm).
2. En **Compute → Instances → RanchoPuebloViejo → Details**, busca **Shape**, OCPU y memoria. Para A1 debe ser `VM.Standard.A1.Flex`. Suma el consumo de todas tus instancias A1; la franquicia es compartida.
3. La documentación Always Free indica **1,500 OCPU-h y 9,000 GB-h al mes**, equivalentes a **2 OCPU/12 GB**. La lista de precios distingue cuentas de pago: **3,000 OCPU-h y 18,000 GB-h**, aproximadamente **4 OCPU/24 GB** continuos. Confirma tu suscripción antes de usar la segunda cifra. Fuentes: [Always Free](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm) y [precios de OCI](https://www.oracle.com/cloud/price-list/#pricing-compute).
4. Confirma que Querétaro sea tu **home region** y suma boot volumes + block volumes: la franquicia publicada es **200 GB combinados y cinco backups de volumen**. Revisa también otros recursos y tráfico; que Compute sea gratuito no garantiza factura cero. [Límites de almacenamiento](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm).
5. En **Billing & Cost Management → Cost Management → Cost Analysis**, elige mes actual y anterior, **Show: Cost**, agrupa por servicio/SKU y revisa toda la tenancy, incluidos los subcompartimentos. Revisa Compute, almacenamiento y red; después consulta **Invoices**. Cost Analysis puede tardar hasta 48 horas en reflejar datos, por lo que un cero reciente no garantiza ausencia de cargos. [Cost Analysis](https://docs.oracle.com/en-us/iaas/Content/Billing/Concepts/costanalysisoverview.htm).
6. Crea en **Budgets** un presupuesto mensual bajo con alertas de gasto real y previsto. Las alertas avisan; no son un corte automático del gasto. Si hay exceso o dudas, resuélvelos antes de redimensionar o crear recursos; conserva un respaldo del servicio existente. [Budgets](https://docs.oracle.com/en-us/iaas/Content/Billing/Concepts/budgetsoverview.htm).

## 2. Revisar acceso, red y convivencia con MADTEC

En **Instances → RanchoPuebloViejo → Networking → Primary VNIC**, confirma IP pública y subred. Conserva la conectividad existente para SSH y la salida a Internet. En esta VM pública se usa la ruta `0.0.0.0/0 → Internet Gateway`. El túnel necesita conexiones de salida, no acceso web entrante a la VM. [Red pública de OCI](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingIGs.htm), [Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/).

En el NSG asociado a la VNIC o en las Security Lists de su subred, conserva entrada **stateful TCP 22** desde tu IP pública de administración `/32`, con puerto de origen cualquiera. FEE no requiere abrir 80, 443, 8000 ni 5432 en la VM. Mantén las reglas necesarias para MADTEC y revisa las anteriores antes de restringirlas.

Las reglas permisivas de distintas listas/NSG se acumulan: una nueva regla SSH `/32` no elimina una regla anterior abierta al mundo. Mantén salida para DNS y descargas HTTPS, y **TCP/UDP 7844 hacia los destinos oficiales de Cloudflare Tunnel**; QUIC usa UDP y HTTP/2 usa TCP. La salida stateful existente puede cubrirlo. [Security Lists](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securitylists.htm), [destinos del túnel](https://developers.cloudflare.com/tunnel/configuration/).

Desde **esta computadora**, usa el alias ya configurado, con privada local y clave del host verificada. En otro equipo configura primero su propia credencial autorizada y verifica la huella por consola; no copies privadas al servidor ni al repo.

```bash
ssh oracle-fee
```

En **la VM**, inventaría recursos, servicios y firewall antes de instalar:

```bash
uname -m
cat /etc/os-release
free -h
df -h
sudo ss -lntup
command -v docker
sudo docker ps
sudo docker compose version
sudo ufw status verbose
sudo iptables -S
sudo iptables -S DOCKER-USER
```

Docker ya está activo en esta VM. FEE usa el proyecto independiente `fee-prod`, y su túnel se conecta directamente a la API en la red Docker. No reemplaces contenedores, redes, volúmenes, rutas ni túneles de MADTEC.

El firewall de Ubuntu es independiente del de OCI: verifica también forwarding/`DOCKER-USER` para la salida del contenedor. Si una regla bloquea el túnel, añade una excepción específica con el gestor existente. No ejecutes `iptables -F`, no desactives el firewall y no reemplaces todo el ruleset. Docker puede saltarse reglas UFW en puertos publicados por otros proyectos. [Limitaciones de Docker](https://docs.docker.com/engine/install/ubuntu/#firewall-limitations).

### Recuperación de SSH completada: procedimiento de referencia

La recuperación ya terminó; no repitas la instalación de la pública ni el arranque de emergencia. La conexión SSH confirmó `ubuntu` (UID 1001), host `ranchopuebloviejo`, PID 1 `systemd`, `sudo -n true` y `sshd -t` correctos, y servicios SSH/Docker activos. Puedes usar directamente el comando de conexión que aparece al final de esta sección y continuar con el inventario del paso 2.

Para una futura recuperación mediante consola serie, `init=/bin/bash` debe ser temporal en GRUB. En la realizada se remontó `/dev/sda1` en escritura y se conservó `/home/ubuntu/.ssh/authorized_keys.before-recovery-20260910` con modo 600. La cuenta `ubuntu` tiene UID/GID 1001, home 750, `.ssh` 700 y `authorized_keys` 600. Conserva el respaldo y las claves anteriores. El usuario instaló personalmente **solo la pública** `/home/peterpad/.ssh/oracle-fee-recovery.pub`; la privada permanece local. El siguiente bloque sirve de referencia para esa shell: después de `read`, pegar la pública completa y pulsar Enter; `>>` la añade sin sustituir las existentes. [Claves de OpenSSH en Ubuntu](https://ubuntu.com/server/docs/how-to/security/openssh-server/).

```bash
read -r fee_recovery_pub
printf '\n%s\n' "$fee_recovery_pub" >> /home/ubuntu/.ssh/authorized_keys
chown ubuntu:ubuntu /home/ubuntu/.ssh /home/ubuntu/.ssh/authorized_keys
chmod 700 /home/ubuntu/.ssh
chmod 600 /home/ubuntu/.ssh/authorized_keys
ssh-keygen -l -E sha256 -f /home/ubuntu/.ssh/authorized_keys
ssh-keygen -l -E sha256 -f /etc/ssh/ssh_host_ed25519_key.pub
echo $$
```

Compara la huella de la pública instalada con `ssh-keygen -l -E sha256 -f ~/.ssh/oracle-fee-recovery.pub` en tu computadora. La segunda huella de la consola identifica al **servidor**. Ya se contrastó y se guardó su clave pública en `/home/peterpad/.ssh/oracle-fee-known_hosts`. Si `echo $$` muestra **1**, ejecuta `sync` y después `exec /sbin/init` para continuar el arranque con systemd. No uses `exit`/Ctrl-D ni `systemctl` mientras bash sea PID 1. [systemd e init](https://manpages.ubuntu.com/manpages/jammy/man1/systemd.1.html).

El arranque normal y esta conexión ya se verificaron. **En esta computadora** está configurado el alias `ssh oracle-fee`, que usa la clave y el archivo de hosts verificados; no se presupone que exista en otros equipos. Su comando explícito equivalente es:

```bash
ssh -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 \
  -o UserKnownHostsFile=/home/peterpad/.ssh/oracle-fee-known_hosts \
  -i /home/peterpad/.ssh/oracle-fee-recovery ubuntu@163.192.148.22
```

Dentro de SSH comprueba `id`, `ps -p 1 -o pid=,comm=` (debe mostrar systemd), `sudo -n true` y `sudo /usr/sbin/sshd -t`. Mantén abierta la consola OCI hasta confirmar otra conexión SSH. Si la clave del host no coincide, vuelve a comprobarla por la consola; no desactives esa validación. Después retoma el inventario del paso 2 antes de desplegar.

## 3. Instalar Docker solo si falta

**En esta VM Docker y Compose ya funcionan: omite la instalación.** Ubuntu 22.04 y ARM64 están soportados. El siguiente bloque es únicamente para otra VM sin Docker ni paquetes de contenedores conflictivos; no reinstales ni elimines paquetes de servicios activos.

```bash
sudo apt update
sudo apt install -y ca-certificates curl rsync python3
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker run --rm hello-world
sudo docker compose version
```

Este procedimiento usa [el repositorio oficial de Docker](https://docs.docker.com/engine/install/ubuntu/#install-using-the-apt-repository). El contenedor incluye Python 3.12: Ubuntu no necesita reemplazar su Python del sistema.

## 4. Copiar el código y configurar secretos y ruta de Cloudflare

El túnel desplegado es **`backosisnt`**, ID `025fb3d3-a84b-472e-8e2e-cd5e6ab89c05`, con hostname **`backosisnt.ici-labs.com`** y origen **`http://api:8000`**. Para revisar la configuración, en Cloudflare abre **Networking → Tunnels → backosisnt → Routes → Published application**. La ruta pública debe cubrir `/api/v1/...`; `api` es el servicio de Compose y `localhost` dentro de cloudflared no es la API. El DNS asocia el hostname con el túnel, no con la IP de Oracle. HTTPS público termina en Cloudflare. [Publicar una aplicación](https://developers.cloudflare.com/tunnel/setup/), [protocolos admitidos](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/protocols/).

La regla **`FEE backosisnt HTTPS`** aplica únicamente a `http://backosisnt.ici-labs.com/*` y redirige a `https://backosisnt.ici-labs.com/${1}` con **308**, preservando la query. Se comprobaron el código y el destino. Mantén su alcance limitado a este hostname para conservar el comportamiento de MADTEC.

En **tu computadora**, copia el árbol local incluyendo los archivos nuevos. `rsync` debe estar instalado en ambos equipos. Esta copia no usa `--delete` y excluye datos, secretos e instalaciones locales:

```bash
cd /home/peterpad/Hackaton-FEE/server
git status --short --branch
ssh oracle-fee 'mkdir -p /home/ubuntu/fee-server'
rsync -av --exclude='.git/' --exclude='.env*' --exclude='.venv/' \
  --exclude='.tooling/' --exclude='__pycache__/' --exclude='.pytest_cache/' \
  --exclude='.ruff_cache/' --exclude='*.db' --exclude='*.db-*' \
  --exclude='backups/' --exclude='*.dump' \
  -e ssh ./ oracle-fee:/home/ubuntu/fee-server/
```

En **la VM** `.env.production` ya se creó con secretos SQL/autenticación aleatorios: consérvalo. El siguiente generador es solo para un despliegue nuevo. Su dominio es una referencia de configuración; no crea DNS ni la ruta del túnel:

```bash
cd /home/ubuntu/fee-server
python3 deploy/oracle/init-env.py api.tu-dominio.com
# Solo para Flutter web, usa en su lugar:
# python3 deploy/oracle/init-env.py api.tu-dominio.com --web-origin https://app.tu-dominio.com
stat -c '%a %n' .env.production
```

Debe mostrar `600`. El script rechaza sobrescribir un archivo existente. Guarda una copia cifrada fuera de la VM; no publiques su contenido. No regeneres secretos al actualizar: cambiar la clave invalida access tokens; cambiar solo `POSTGRES_PASSWORD` no modifica una base ya inicializada. Para Flutter web configura `FEE_CORS_ORIGINS` con orígenes HTTPS exactos en JSON; está cerrado por defecto y móvil nativo no necesita CORS.

El token entregado para el túnel se almacena **solo en `.env.cloudflared.token`**, modo **0400**, propietario **10001:10001**, para que cloudflared lo lea como UID 10001. Compose lo monta como secreto y usa `TUNNEL_TOKEN_FILE`; no lo pongas en argumentos, código ni capturas. `.env.*` está excluido de Git, del build y de la transferencia anterior. Verifica únicamente metadatos con `sudo stat -c '%a %u:%g %n' .env.cloudflared.token`. El token debe corresponder al túnel elegido; no reutilices credenciales de MADTEC. [Token desde archivo](https://developers.cloudflare.com/tunnel/advanced/run-parameters/#token-file).

En la VM `FEE_TUNNEL_IMAGE` fija por digest verificado cloudflared **2026.9.0**. Conserva esa referencia hasta revisar una actualización; el valor por defecto del Compose es `latest`. Los logs del conector se limitan a nivel `fatal`, por lo que su ausencia no demuestra que el túnel esté saludable.

Usa **solo** `compose.production.yaml`; no lo combines con `compose.yaml`, que contiene credenciales de desarrollo. Conserva siempre el nombre de proyecto `fee-prod`, para reutilizar sus volúmenes. Define este atajo de terminal de nuevo en cada sesión:

```bash
dc() { sudo docker compose --env-file .env.production -f compose.production.yaml -p fee-prod "$@"; }
dc config --quiet
sudo docker network ls
ip route
```

La red usa `172.30.80.0/28`, cloudflared `172.30.80.2` y API `172.30.80.3`. Si hay un conflicto con VCN/VPN/Docker, configura `FEE_PROXY_SUBNET`, `FEE_PROXY_IP` y `FEE_API_IP` en `.env.production` antes del arranque, con dos IP utilizables distintas en una subred libre. Uvicorn confía en cabeceras reenviadas **solo desde la IP de cloudflared**. Mantén esta red dedicada y verifica el límite por IP mediante la URL pública; no configures confianza `*`.

## 5. Migrar, arrancar y validar

Ejecuta cada comando solamente si el anterior terminó correctamente:

```bash
dc build api migrate
dc up -d --wait db
dc run --rm migrate
dc up -d --wait api cloudflared
dc ps
dc exec -T api python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=5).read().decode())"
dc exec -T cloudflared cloudflared tunnel --metrics 127.0.0.1:2000 ready
```

Si una migración falla, **detén la secuencia** antes de arrancar/recrear la API. PostgreSQL 17 queda en una red privada, con volumen `postgres_data`. **Ningún servicio de FEE publica puertos del host**. Los servicios persistentes usan `unless-stopped`; una parada manual necesita arranque manual. El healthcheck de cloudflared comprueba su conexión con Cloudflare; no acredita que el hostname apunte a esta API.

Comprueba el endpoint **desde tu computadora** con `curl --fail --show-error https://backosisnt.ici-labs.com/api/v1/health`. Debe devolver 200; la URL HTTP equivalente debe redirigir con 308 a HTTPS conservando ruta y query. El estado Healthy del túnel por sí solo no valida el origen ni la ruta pública; estas comprobaciones externas también se completaron. [Diagnóstico de rutas](https://developers.cloudflare.com/tunnel/troubleshooting/https-origins/).

Health debe devolver `{"status":"ok","service":"fee-server","version":"0.1.0"}`; solo acredita respuesta del proceso. `/docs` y `/openapi.json` deben devolver 404. Para comprobar SQL/sesiones, realiza registro → login → `/auth/me` → refresh → logout con una cuenta ficticia y contraseña aleatoria, siguiendo [el contrato](api-contract.md); tras logout el access debe devolver 401. No imprimas tokens en logs compartidos. El registro crea una cuenta persistente y no hay endpoint público de borrado: la cuenta usada en esta validación se eliminó exactamente después, verificando que no quedaran su usuario, sesiones ni tokens.

Si falla el acceso público, revisa túnel, salida 7844, token, DNS y Service URL `http://api:8000`. Un 502 puede indicar que el túnel no alcanza la API. Usa `dc ps` y `dc logs --tail=50 api db cloudflared` sin compartir secretos. Se observó **403 de Cloudflare con `User-Agent: Python-urllib/3.12`**, mientras curl, Dart y `fee-deploy-check` recibieron 200; los scripts de comprobación usaron User-Agent explícito y **no se cambió WAF**. Distingue respuestas de Cloudflare de errores de FEE y revisa Access/WAF para el cliente previsto. No uses `curl -k` como validación TLS. [Diagnóstico de Cloudflare](https://developers.cloudflare.com/tunnel/troubleshooting/).

## 6. Respaldos y prueba de restauración

Antes de una actualización, en la VM y desde `/home/ubuntu/fee-server`, con `dc` definido:

```bash
umask 077
mkdir -p /home/ubuntu/backups
chmod 700 /home/ubuntu/backups
fee_backup="/home/ubuntu/backups/fee-$(date -u +%Y%m%dT%H%M%SZ).dump"
if dc exec -T db pg_dump -U fee -d fee --format=custom > "$fee_backup"; then
  chmod 600 "$fee_backup"
else
  rm -f "$fee_backup"
  exit 1
fi
```

El respaldo contiene datos de cuentas y sesiones. Cópialo por SSH a almacenamiento seguro **fuera de la VM**; un volumen Docker o un dump en el mismo disco no protegen frente a perder la instancia. Desde tu computadora, por ejemplo, a una carpeta privada que luego respaldes cifrada:

```bash
umask 077
mkdir -p ~/fee-backups
rsync -av -e ssh oracle-fee:/home/ubuntu/backups/ ~/fee-backups/
```

En la VM prueba el dump en **otra base**, nunca sobre `fee`. Usa la variable `fee_backup` anterior o asígnale la ruta exacta del archivo que quieres verificar:

```bash
fee_restore_db="fee_restore_$(date -u +%Y%m%d%H%M%S)"
dc exec -T db createdb -U fee "$fee_restore_db"
dc exec -T db pg_restore --exit-on-error --no-owner -U fee -d "$fee_restore_db" < "$fee_backup"
dc exec -T db psql -U fee -d "$fee_restore_db" -c 'SELECT version_num FROM alembic_version;'
```

Solo continúa si cada paso termina con éxito. Prueba después la aplicación contra esa base aislada. Conserva `.env.production` en un respaldo cifrado separado y controla espacio/retención. Gestiona el token del túnel en almacenamiento seguro o mediante su rotación en Cloudflare; no lo incluyas en dumps SQL ni carpetas de código. El nombre del túnel y su hostname confirmado deben constar en el registro de despliegue, sin credenciales.

## 7. Actualizaciones y mantenimiento

1. Revisa la rama/commit que se desplegará y sus migraciones; ejecuta las validaciones del README localmente. `git pull` solo actualiza la rama actual. `feature/engineer-1-passkey-auth` es una alternativa que requiere decidir integración y compatibilidad de esquema; no se debe mezclar ni sustituir por ser más reciente.
2. Haz el respaldo anterior **antes de Alembic**. Conserva el código y la imagen anteriores para recuperación, por ejemplo `sudo docker image tag fee-server:oracle-local fee-server:rollback-FECHA`, sustituyendo `FECHA` por un identificador único. Anota la revisión desplegada.
3. Transfiere el código revisado con las exclusiones anteriores. Revisa archivos eliminados/renombrados entre versiones: `rsync` sin `--delete` deja los antiguos. Retira solo los archivos obsoletos de código confirmados; conserva secretos y datos.
4. En `/home/ubuntu/fee-server`, repite `dc build api migrate`. Si la migración rompe compatibilidad con la versión en ejecución, detén antes `dc stop api` durante una ventana de mantenimiento.
5. Ejecuta `dc up -d --wait db`, después `dc run --rm migrate`; **si falla, aborta el despliegue**. Solo tras éxito ejecuta `dc up -d --wait api cloudflared` y repite las comprobaciones HTTP/autenticación. Una imagen anterior solo sirve de rollback si admite el esquema actual; no ejecutes downgrades Alembic a ciegas.

Nunca uses `docker compose down -v` ni borres `postgres_data`. Mantén `-p fee-prod` incluso si cambia el directorio. Revisa aparte actualizaciones de imágenes base y sus compatibilidades; no subas PostgreSQL de versión mayor cambiando únicamente el tag.

La limpieza de sesiones vencidas es explícita:

```bash
dc exec -T api python -m fee_server.maintenance cleanup-auth
```

Opcionalmente, después de probarla, añade esta línea con `sudo crontab -e` para ejecutarla diariamente a las 03:15 de la **zona horaria del servidor**. No reemplaces otras entradas. El comando imprime cantidades agregadas; configura rotación del archivo de log.

```cron
15 3 * * * cd /home/ubuntu/fee-server && /usr/bin/docker compose --env-file .env.production -f compose.production.yaml -p fee-prod exec -T api python -m fee_server.maintenance cleanup-auth >> /var/log/fee-auth-maintenance.log 2>&1
```

El backend ofrece autenticación por contraseña y catálogo de proveedores; aún no ejecuta escaneos externos. La app Flutter sigue siendo una demo local: subir el backend no conecta automáticamente la app. La selección de URL HTTPS, almacenamiento seguro de tokens y flujo de autenticación del cliente requieren su integración correspondiente.

## Verificación local y del despliegue público

- `uv lock --check`, instalación congelada, Ruff y formato: correctos.
- Suite general: 115 pruebas correctas; las tres de PostgreSQL se ejecutaron después contra una instancia temporal de PostgreSQL 17 y también pasaron.
- API y PostgreSQL healthy en ARM nativo; migración `823459897ec8` correcta. Cloudflared 2026.9.0 conectado y healthy. Health público 200, HTTP 308 al destino HTTPS esperado, Swagger/OpenAPI 404 y ruta protegida sin autenticación 401.
- Registro, login, perfil, refresh, logout, rechazo de replay y persistencia tras un único reinicio de API comprobados mediante la URL pública, con TLS verificado y User-Agent `FEE-deployment-validation/1.0`. Se eliminó la cuenta ficticia exacta y se verificó ausencia de su usuario, sesiones y tokens. Los identificadores y horas de arranque de MADTEC permanecieron intactos.
- Cuarenta solicitudes con `X-Forwarded-For` falsificado produjeron 30 respuestas 422 y 10 respuestas 429 con `rate_limited` de FEE: la falsificación no evitó el límite. Generador de secretos 0600/sin sobrescritura e imagen ARM64 emulada también verificados; los recursos locales de prueba se retiraron.

El endpoint público, la autenticación y la persistencia quedaron comprobados al finalizar. Estas pruebas no miden capacidad bajo carga ni garantizan disponibilidad futura. Los costes se revisaron por separado en OCI, con los períodos y límites de contabilización descritos en el paso 1. La configuración desplegada está pendiente de commit/push.
