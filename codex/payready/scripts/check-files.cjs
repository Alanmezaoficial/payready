const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const [phase, ...files] = process.argv.slice(2);
if (!['pre', 'post', 'stop'].includes(phase) || files.length === 0) {
  console.error('Uso: node check-files.cjs <pre|post|stop> <archivo> [...]');
  process.exit(1);
}

const projectDir = fs.realpathSync(process.cwd());
const dispatcher = path.join(__dirname, '../engine/hooks/pagokit-validate.js');
let status = 0;

for (const file of files) {
  try {
    const filePath = path.resolve(projectDir, file);
    const exists = fs.existsSync(filePath);
    const resolved = exists ? fs.realpathSync(filePath) : filePath;
    const relative = path.relative(projectDir, resolved);
    if (!relative || relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
      throw new Error('La ruta debe estar dentro del proyecto.');
    }
    if (phase === 'pre' && !exists && !path.basename(filePath).startsWith('.env')) {
      continue;
    }

    const toolInput = { file_path: resolved };
    if (phase !== 'pre') {
      toolInput.content = fs.readFileSync(resolved, 'utf8');
    }
    const result = spawnSync(process.execPath, [dispatcher, phase], {
      input: JSON.stringify({ tool_name: 'Write', tool_input: toolInput }),
      encoding: 'utf8',
      env: { ...process.env, CLAUDE_PROJECT_DIR: projectDir },
    });
    if (result.error || ![0, 2].includes(result.status)) {
      throw new Error('El motor de validación no terminó correctamente.');
    }

    for (const line of result.stderr.trim().split('\n').filter(Boolean)) {
      const { level, rule, code } = JSON.parse(line);
      console.error(`${relative}: ${level} ${rule ?? 'dispatcher'} ${code ?? ''}`);
      if (level === 'internal') status = Math.max(status, 1);
    }
    status = Math.max(status, result.status);
  } catch (error) {
    console.error(error.message);
    status = Math.max(status, 1);
  }
}

process.exitCode = status;
