# Proxy residencial Decodo

`FEE_OSINT_RESIDENTIAL_PROXY_URL` (o `FEE_OSINT_PROXY_URL` por retrocompatibilidad)
se configura únicamente en `.env.production` (modo 0600), nunca en Flutter, Git,
argumentos de diagnóstico ni capturas. Compose la pasa a la API. El transporte
común comprobado para los motores es un proxy `http://` con puerto explícito; los
destinos HTTPS usan CONNECT y conservan TLS. Una URL no soportada impide arrancar,
para evitar configuraciones erróneas.

### Asignación diferenciada y economía de cuota

Para no agotar la cuota del proxy residencial:
- **Holehe e Ignorant (account-recovery):** Usan el proxy residencial (`FEE_OSINT_RESIDENTIAL_PROXY_URL`
  o `FEE_OSINT_PROXY_URL`). Consultan endpoints de restablecimiento de contraseña en
  servicios que bloquean activamente IPs de centros de datos. Su consumo es mínimo
  (< 2 MB por escaneo).
- **Blackbird y Maigret (búsqueda de usernames):** Usan `FEE_OSINT_NORMAL_PROXY_URL`
  o salida directa (conexión normal del servidor) si dicha variable está vacía.
  Consultan perfiles públicos abiertos, ahorrando más del 95% del tráfico residencial.

Ejemplo ficticio: `http://USUARIO:CLAVE@gate.decodo.com:7000`. Codifica los caracteres
especiales del usuario y contraseña como componentes URL. El puerto 7000 rota
por solicitud; 10001 mantiene una sesión sticky. Véanse [puertos](https://help.decodo.com/docs/residential-proxy-endpoints-and-ports)
y [sesiones](https://help.decodo.com/docs/residential-proxy-session-types).

Blackbird recibe `--proxy` si hay proxy normal configurado. Holehe e Ignorant usan HTTPX
y las variables `HTTP_PROXY`/`HTTPS_PROXY` con el proxy residencial. Maigret 0.6.5 usa su
cliente con `trust_env=True` sobre el proxy normal; no debe recibir además `--proxy`.
Los subprocesos reciben un entorno acotado sin heredar `NO_PROXY` ni credenciales del servidor.
La configuración oculta las URLs en representaciones y errores de validación.

Un proxy operativo no garantiza acceso a todas las fuentes ni evita límites o
CAPTCHA. Decodo requiere plan pagado y verificación de identidad para ciertos
[grupos de destinos](https://help.decodo.com/docs/accessing-target-groups-after-id-verification);
el desbloqueo no está disponible durante la prueba. El panel observado el
10 de septiembre de 2026 mostraba 100 MB de prueba. No ejecutar auditorías masivas
como comprobación de conectividad: basta el endpoint HTTPS `ip.decodo.com/json`.

## Actualizar sin recrear el túnel

1. Conservar `.env*` y la imagen anterior. Transferir solo código revisado, sin
   `--delete`, excluyendo `.git`, `.venv`, cachés y herramientas locales.
2. Construir `api migrate` mientras la API existente sirve solicitudes.
3. Respaldar PostgreSQL en formato custom, modo 0600, y probar la restauración
   en una base temporal separada. No restaurar sobre `fee`.
4. Consultar el número de escaneos `QUEUED`/`RUNNING` antes del reinicio; viven en
   el proceso y deben terminar antes de recrear la API.
5. Desde `/home/ubuntu/fee-server`, definir y ejecutar:

   ```sh
   dc() { sudo docker compose --env-file .env.production -f compose.production.yaml -p fee-prod "$@"; }
   dc config --quiet
   dc run --rm --no-deps -e PGOPTIONS='-c lock_timeout=5s -c statement_timeout=60s' migrate
   dc up -d --no-deps --wait api
   ```

   Si falla la migración, detener la secuencia. `0003` añade `correlation` JSON
   nullable y es compatible con la imagen anterior; ALTER TABLE sí requiere un
   bloqueo breve. Los límites evitan esperas indefinidas. No ejecutar downgrade.
6. Comprobar salud pública, revisión 0003, proxy configurado y solicitud HTTPS
   autenticada desde el contenedor. Comparar ID, hora de arranque y reinicios de
   `cloudflared` y `db` con el inventario previo.

No usar `compose down`, recrear `cloudflared` ni modificar su token. La API puede
tener una breve interrupción al recrearse aunque el túnel permanezca conectado.
Conservar el respaldo y la referencia de imagen anterior para recuperación.

## Evidencia

Las pruebas automatizadas usan dobles y un proxy autenticado en loopback,
incluyendo respuesta 407. No realizan escaneos reales de personas. Las pruebas
de conectividad a Decodo acreditan transporte y rotación, no resultados de redes
sociales. Registrar por separado el resultado del despliegue y sus imágenes en
`DEPLOYMENT.json`, sin secretos ni identificadores de personas.
