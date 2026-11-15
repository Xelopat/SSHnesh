const esbuild = require('esbuild');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

async function build() {
  await Promise.all([
    esbuild.build({ entryPoints: ['src/ui/app.js'], bundle: true, minify: true, outfile: 'build/ui.js', target: 'chrome150' }),
    esbuild.build({ entryPoints: ['src/mcp.cjs'], bundle: true, platform: 'node', target: 'node22', outfile: 'build/sshash-mcp.cjs' }),
  ]);
  if (process.platform === 'win32' || process.argv.includes('--win')) {
    const result = spawnSync('dotnet', [
      'publish', 'bridge/Bridge.csproj', '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true',
      '-p:PublishSingleFile=true', '-p:DebugType=None', '-o', path.join('build', 'bridge'),
    ], { stdio: 'inherit' });
    if (result.error) throw result.error;
    if (result.status) process.exitCode = result.status;
  }
}

build().catch(error => { console.error(error); process.exitCode = 1; });
