const esbuild = require('esbuild');
const fs = require('node:fs/promises');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
async function syncAndroidIcons() {
  const res = path.join(__dirname, 'gen/android/app/src/main/res');
  const present = await fs.stat(res).catch(error => {
    if (error.code !== 'ENOENT') throw error;
  });
  if (!present?.isDirectory()) return;
  await fs.copyFile(path.join(__dirname, 'android/MainActivity.kt'),
    path.join(res, '../java/ru/xelopat/sshnesh/preview/MainActivity.kt'));
  await fs.copyFile(path.join(__dirname,'android/VaultPlugin.kt'),path.join(res,'../java/ru/xelopat/sshnesh/preview/VaultPlugin.kt'));
  for (const density of ['mdpi', 'hdpi', 'xhdpi', 'xxhdpi', 'xxxhdpi']) {
    const name = 'mipmap-' + density;
    const dir = path.join(res, name);
    await fs.mkdir(dir, { recursive: true });
    for (const image of ['ic_launcher.png', 'ic_launcher_round.png', 'ic_launcher_foreground.png']) {
      await fs.copyFile(path.join(__dirname, 'icons/android', name, image), path.join(dir, image));
    }
  }
}

async function build() {
  const outdir = path.join(__dirname, 'web');
  await fs.mkdir(outdir, { recursive: true });
  const html = await fs.readFile(path.join(root, 'src/ui/index.html'), 'utf8');
  await fs.writeFile(path.join(outdir, 'index.html'), html
    .replace(/<meta http-equiv="Content-Security-Policy"[^>]*>\r?\n/, '')
    .replace('<span class="brand-icon" aria-label="SSHnesh">›_</span>',
      '<img class="brand-icon terminal-brand" src="/terminal-brand.png" alt="SSHnesh">')
    .replace('<script defer src="/app.js"></script>', '<script defer src="/bridge.js"></script>\n<script defer src="/app.js"></script>'));
  await Promise.all([
    esbuild.build({ entryPoints: { app: path.join(root, 'src/ui/app.js'), bridge: path.join(__dirname, 'bridge.js') },
      bundle: true, minify: true, target: ['chrome105', 'safari16'], outdir }),
  ]);
  await fs.copyFile(path.join(root, 'assets/sshnesh-terminal-dark.png'), path.join(outdir, 'terminal-brand.png'));
  await fs.appendFile(path.join(outdir, 'app.css'), '\n' + await fs.readFile(path.join(__dirname, 'narrow.css'), 'utf8'));
  await fs.cp(path.join(__dirname,'icons/systems'),path.join(outdir,'systems'),{recursive:true});
  await syncAndroidIcons();
}
build().catch(error => { console.error(error); process.exitCode = 1; });
