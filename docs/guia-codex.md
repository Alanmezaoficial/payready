---
title: Guía de PayReady para Codex
---

# Instala PayReady en Codex

Usa PayReady desde Codex con acceso al proyecto y a la terminal. Conserva el catálogo, el asesor de pasarelas, las plantillas y los validadores de PagoKit. Codex llama a los validadores de forma explícita durante el trabajo.

## 1. Prepara tu equipo

Ten Git, Node.js 18 o superior y Codex. Descarga el repositorio o el ZIP de esta edición. La carpeta que debes instalar es `codex/payready` en el repositorio, o `payready` en el ZIP.

## 2. Copia la carpeta completa

**Windows PowerShell**

```powershell
$repo = Join-Path $env:USERPROFILE 'payready'
$skills = Join-Path $env:USERPROFILE '.agents/skills'
git clone https://github.com/Alanmezaoficial/payready.git $repo
if ($LASTEXITCODE -ne 0) { throw 'Revisa el clon antes de continuar.' }
New-Item -ItemType Directory -Force $skills | Out-Null
if (Test-Path (Join-Path $skills 'payready')) { throw 'Ya hay una copia de PayReady. Revisa su versión.' }
Copy-Item (Join-Path $repo 'codex/payready') -Destination $skills -Recurse -ErrorAction Stop
```

**macOS y Linux**

```sh
git clone https://github.com/Alanmezaoficial/payready.git ~/payready &&
mkdir -p ~/.agents/skills &&
test ! -e ~/.agents/skills/payready &&
cp -R ~/payready/codex/payready ~/.agents/skills/payready
```

Si ya tienes el ZIP, puedes copiar la carpeta extraída a la misma ubicación. Comprueba que quede `~/.agents/skills/payready/SKILL.md`, junto con `engine` y `scripts`.

## 3. Abre el proyecto en Codex

Abre una sesión nueva en tu proyecto y escribe:

```text
Usa $payready para analizar este proyecto y recomendarme cómo integrar pagos de prueba.
```

Después puedes pedirle que compare proveedores, prepare un checkout, revise la seguridad del webhook o planifique una migración. Indica qué cambios autorizas y qué quieres probar primero.

## 4. Revisa lo que quedó validado

Pide que ejecute los chequeos de PayReady sobre los archivos de la integración y te muestre las pruebas realizadas. El adaptador de Codex conserva las reglas del motor, con ejecución explícita antes de editar y al revisar el resultado. Para un webhook, prueba eventos válidos, alterados y repetidos en local o en el sandbox del proveedor. Usa credenciales de prueba fuera del chat.

Los avisos de procedencia y licencia se incluyen en la descarga.
