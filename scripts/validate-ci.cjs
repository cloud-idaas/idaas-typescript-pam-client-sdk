const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { fetchUpstreams, verifyConsumer } = require('./release.cjs');
const { checkArchive, checkMetadata, json, npm, stage } = require('./release-tools.cjs');

async function main() {
  const root = path.resolve(__dirname, '..');
  const pkg = json(path.join(root, 'package.json'));
  checkMetadata(pkg);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'idaas-ci-'));
  try {
    const upstreams = path.join(temp, 'upstreams');
    const packages = path.join(temp, 'packages');
    fs.mkdirSync(upstreams);
    fs.mkdirSync(packages);
    await fetchUpstreams(pkg, upstreams, root);
    stage(root, upstreams);
    npm(
      [
        'ci',
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
        '--registry=https://registry.npmjs.org/',
      ],
      root,
    );
    npm(['run', 'verify'], root);
    const packed = JSON.parse(
      npm(['pack', '--ignore-scripts', '--json', '--pack-destination', packages], root, {
        capture: true,
      }),
    )[0];
    const file = path.join(packages, packed.filename);
    checkArchive(file);
    verifyConsumer(file, pkg, temp, upstreams);
    console.log('CI validation completed: ' + pkg.name + '@' + pkg.version);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
