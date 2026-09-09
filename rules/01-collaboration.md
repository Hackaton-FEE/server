# Colaboración y ramas

- Mantén cada cambio dentro del objetivo autorizado. Preserva cambios ajenos y coordina archivos compartidos antes de editarlos en paralelo.
- `main` es la base estable. Tras el bootstrap, usa PR con squash; solicita una aprobación de la otra persona y espera checks aplicables correctos antes de fusionar.
- `work/engineer-1` pertenece al ingeniero 1 y `work/engineer-2` al ingeniero 2. No reescribas la rama ajena. Se prefieren ramas breves por tarea desde `main` actualizado.
- Tras un squash, crea una rama nueva desde `main`. Si se reutiliza la rama de trabajo, primero conserva cualquier trabajo pendiente y un respaldo; recrear o resetear es una decisión explícita de su propietario, nunca un paso destructivo automático.
- Revisión y CI son convención del equipo, no restricciones técnicas: GitHub Free no protege estas ramas privadas. Antes del merge comprueba el estado real del PR.
- No vuelvas a pedir autorización para acciones ya incluidas en la tarea. Si falta una decisión material, prepara primero el resultado revisable que no dependa de ella.
