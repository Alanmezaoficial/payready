---
title: Guía de PayReady para Claude Code
---

# Instala PayReady en Claude Code

PayReady inspecciona tu proyecto, recomienda una pasarela y te ayuda a integrar el checkout y las notificaciones de pago. Esta edición conserva los comandos y los hooks de PagoKit dentro de Claude Code.

## 1. Prepara tu equipo

Ten Git, Node.js 18 o superior y Claude Code 2.x. Abre una terminal desde la carpeta donde desarrollarás la integración.

## 2. Clona el repositorio y abre el plugin

**Windows PowerShell**

```powershell
git clone https://github.com/Alanmezaoficial/payready.git "$env:USERPROFILE/payready"
claude --plugin-dir "$env:USERPROFILE/payready/claude/payready"
```

**macOS y Linux**

```sh
git clone https://github.com/Alanmezaoficial/payready.git ~/payready
claude --plugin-dir "$HOME/payready/claude/payready"
```

Si descargaste el ZIP Claude, descomprímelo y pasa la ruta de la carpeta `payready` que contiene `.claude-plugin`. Para volver a usar el plugin, repite el comando de apertura desde tu proyecto.

## 3. Pruébalo con tu proyecto

En Claude Code escribe `/payready:start`. Confirma el stack detectado y explica dónde está tu negocio, dónde están tus clientes, si necesitas pagos únicos o recurrentes y qué medios de pago quieres ofrecer. Revisa la recomendación y su cobertura antes de pedir que escriba código.

- `/payready:compare` compara proveedores. `/payready:coverage` consulta la cobertura.
- `/payready:add` añade otro proveedor. `/payready:migrate` prepara una transición.
- `/payready:doctor` revisa la integración. `/payready:harden` guía el endurecimiento.
- `/payready:test` prueba el webhook local con eventos sintéticos y un secreto desechable de pruebas.

## Antes de cobrar

La cobertura depende del proveedor y del stack. Verifica tarifas, requisitos y métodos vigentes en la documentación oficial. Prueba un pago válido, una firma alterada y un evento repetido en un entorno aislado. Guarda los secretos en el entorno local y evita pegarlos en el chat.

Los avisos de procedencia y licencia se incluyen en la descarga.
