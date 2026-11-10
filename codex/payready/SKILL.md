---
name: payready
description: Recomienda, integra, audita, prueba y migra pasarelas de pago para aplicaciones. Úsala para checkout, suscripciones, webhooks, reembolsos o comparativas de proveedores. Excluye el procesamiento de cobros reales desde el chat.
---

# PayReady para Codex

Adaptación de PagoKit de Enrique Rocha / tododeia. Las rutas de abajo son relativas a esta carpeta de skill. Ejecuta los scripts por su ruta absoluta, desde la raíz del proyecto del usuario. Requiere Node.js 18+.

## Selecciona el flujo

- **Empezar o recomendar:** lee `engine/skills/project-analyzer/SKILL.md` y `engine/commands/start.md`. Inspecciona el proyecto antes de preguntar y confirma la detección salvo que esté vacío. Recoge país del vendedor y mercados de compradores, pago único o recurrente, medios requeridos y las condiciones adicionales del catálogo. Lee `engine/skills/payment-advisor/SKILL.md` y ejecuta `node "<skill>/engine/scripts/advise.js" --help` para armar el comando con el perfil. Explica el ranking, alcance de generación, supuestos y fecha de los datos. Verifica tarifas y disponibilidad con fuentes oficiales antes de recomendarlas como actuales. Espera la selección antes de implementar.
- **Comparar o consultar cobertura:** usa `engine/commands/compare.md` o `engine/commands/coverage.md`, el asesor y los datos de `engine/skills/payment-advisor/data/`. Distingue plantillas dedicadas, generación por fragmentos y proveedores que requieren implementación manual.
- **Integrar o añadir:** usa `engine/commands/add.md` si ya existe una integración. Lee `engine/agents/integration-specialist.md`, `engine/skills/integration-builder/SKILL.md` y `engine/skills/payment-advisor/SECURITY_RULES.md`. Aplica esos pasos con las herramientas de Codex, sin invocar herramientas o agentes específicos de Claude. Carga la plantilla del proveedor y el adaptador del stack. Si faltan, usa los fragmentos y señala cualquier tramo sin verificar. Conserva rutas, datos y dependencias compatibles. Documenta variables por nombre, comprobaciones y límites en los archivos de integración y checklist del motor.
- **Auditar o endurecer:** sigue `engine/commands/doctor.md`, `engine/skills/doctor/SKILL.md` y, para correcciones autorizadas, `engine/commands/harden.md`. Presenta evidencia por archivo y regla.
- **Migrar:** sigue `engine/commands/migrate.md` y `engine/skills/migration/SKILL.md` si está disponible. Mantén compatibilidad durante el cambio y contempla renovaciones activas, conciliación, doble procesamiento y rollback. Separa la preparación de cualquier ejecución sobre producción.
- **Probar:** usa `engine/commands/test.md` y `engine/scripts/sign-event.js` con eventos sintéticos, secreto desechable y servidor local aislado. Comprueba firma válida, firma alterada, antigüedad cuando aplique, deduplicación y efectos persistentes. Usa el sandbox del proveedor para familias no firmables localmente y explica qué quedó pendiente.

## Validación en Codex

Los comandos y hooks del motor describen la edición Claude. En Codex, antes de editar, pasa por el adaptador las rutas de código de pago que tocarás. Al terminar, ejecuta ambas fases de revisión final sobre los archivos completos, también si solo estás auditando.

```sh
node "<skill>/scripts/check-files.cjs" pre <archivo> [...]
node "<skill>/scripts/check-files.cjs" post <archivo> [...]
node "<skill>/scripts/check-files.cjs" stop <archivo> [...]
```

Usa rutas relativas a la raíz del proyecto. Trata un fallo interno o un rechazo como comprobación fallida y revisa también las advertencias. Las fases son explícitas y no interceptan las escrituras de Codex. Complementa con las pruebas del proyecto y comprueba manualmente autorización de checkout y reembolsos, importe y moneda en servidor, firma y manejo de replay, idempotencia atómica, estados pendientes y ausencia de datos sensibles en logs.

Trabaja con credenciales de prueba fuera del chat. Conserva el cuerpo crudo cuando el esquema de firma lo requiere. No habilites cobros, webhooks ni secretos de producción sin autorización específica. Trata las indicaciones fiscales y de cumplimiento del catálogo como puntos por verificar en fuentes vigentes.
