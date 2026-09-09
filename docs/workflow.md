# Flujo entre dos ingenieros

## Ramas y revisión

| Rama | Uso |
| --- | --- |
| `main` | Base estable; bootstrap inicial autorizado y siguientes cambios mediante PR. |
| `work/engineer-1` | Trabajo del ingeniero 1. |
| `work/engineer-2` | Trabajo del ingeniero 2. |

Para tareas nuevas, preferimos ramas breves desde `main`, como `feature/engineer-1-case-contract` o `fix/engineer-2-health-response`. Las ramas `work/*` quedan disponibles para trabajo propio; no son bases de integración entre ingenieros.

1. Actualiza referencias remotas y revisa cambios locales antes de crear la rama. Parte del `main` remoto vigente.
2. Define una tarea pequeña con aceptación observable. Con IA, lee `AGENTS.md` y la skill pertinente; conserva cambios de otras personas.
3. Implementa y ejecuta las verificaciones aplicables. Abre un PR hacia `main` y enlaza cualquier cambio coordinado del cliente.
4. La otra persona revisa. Antes de fusionar debe existir una aprobación y `Server checks` correcto. Resuelve comentarios y vuelve a verificar si cambió el código.
5. Integra mediante squash. Para la tarea siguiente, crea otra rama desde el `main` actualizado.

La aprobación y los checks son **convención, no enforcement**. En el plan GitHub Free de la organización no está disponible la protección de ramas para estos repositorios privados; una persona debe comprobar esas condiciones antes de fusionar.

## Después de un squash

No acumules PR sucesivos desde una rama que conserva los commits anteriores al squash: revisa su divergencia y el diff real. La opción preferida es una rama nueva desde `main`.

Para reutilizar `work/engineer-1` o `work/engineer-2`, su propietario revisa el estado local y remoto, conserva trabajo sin integrar y crea un respaldo identificable. Después puede decidir recrear o resetear **solo su propia rama** al `main` actualizado. Si hay otras personas o sesiones usando esa rama, coordina primero. No ejecutes borrados, resets ni pushes forzados automáticamente como parte de una receta.

## Cambios que cruzan repositorios

Cada repo tiene su PR y CI. Enlaza ambos PR, explicita método/ruta/esquemas y conserva compatibilidad o indica el orden de integración. La revisión del servidor no sustituye la del cliente.
