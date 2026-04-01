#!/usr/bin/env node
'use strict';

/**
 * Standalone scanner for the March 2026 axios npm supply-chain compromise.
 *
 * Usage:
 *   node axios_compromise_scanner.js --root .
 *   node axios_compromise_scanner.js --root . --json
 *   node axios_compromise_scanner.js --self-test
 *
 * Exit codes:
 *   0 = no findings / successful self-test
 *   1 = findings detected
 *   2 = runtime error / failed self-test
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const MALICIOUS_AXIOS_VERSIONS = new Set(['1.14.1', '0.30.4']);
const MALICIOUS_DEPENDENCY = 'plain-crypto-js';
const SUSPICIOUS_PLAIN_CRYPTO_VERSIONS = new Set(['4.2.1']);

const MALICIOUS_SHA1 = {
  'axios@1.14.1': '2553649f2322049666871cea80a5d0d6adc700ca',
  'axios@0.30.4': 'd6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71',
  'plain-crypto-js@4.2.1': '07d889e2dadce6f3910dcbc253317d28ca61c766',
};

const NETWORK_IOCS = {
  domains: ['sfrclak.com'],
  ip_addresses: ['142.11.206.73'],
  urls: ['http://sfrclak.com:8000/6202033'],
  post_bodies: ['packages.npm.org/product0', 'packages.npm.org/product1', 'packages.npm.org/product2'],
  user_agent: 'mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)',
};

const FILE_IOCS = [
  '/Library/Caches/com.apple.act.mond',
  '%PROGRAMDATA%\\wt.exe',
  '%PROGRAMDATA%\\system.bat',
  '%TEMP%\\6202033.vbs',
  '%TEMP%\\6202033.ps1',
  '/tmp/ld.py',
];

const LOCKFILE_CANDIDATES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml']);
const SKIP_DIRS = new Set(['.git', '.hg', '.svn', '.next', '.turbo', '.cache', 'dist', 'build', 'coverage']);

function finding(severity, category, fpath, summary, details) {
  return { severity, category, path: fpath, summary, details };
}

function safeRead(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (_err) {
    return '';
  }
}

function* iterFiles(root) {
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_err) {
      continue;
    }

    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(full);
      } else if (entry.isFile()) {
        yield full;
      }
    }
  }
}

function addAxiosFinding(findings, fpath, version, category = 'dependency') {
  findings.push(
    finding(
      'critical',
      category,
      fpath,
      `Potential malicious axios version referenced: ${version}`,
      'Known malicious axios version from the March 2026 compromise detected. Treat host as potentially compromised and rotate credentials.'
    )
  );
}

function checkLockfileForVersions(filePath, findings) {
  const text = safeRead(filePath);
  if (!text) return;

  if (filePath.endsWith('.json')) {
    let parsed = null;
    try {
      parsed = JSON.parse(text);
    } catch (_err) {
      parsed = null;
    }

    const walk = (obj) => {
      if (!obj || typeof obj !== 'object') return;
      if (Array.isArray(obj)) {
        for (const item of obj) walk(item);
        return;
      }

      if (obj.name === 'axios' && MALICIOUS_AXIOS_VERSIONS.has(String(obj.version || '').trim())) {
        addAxiosFinding(findings, filePath, String(obj.version).trim());
      }

      for (const [k, v] of Object.entries(obj)) {
        if (k === 'axios' && v && typeof v === 'object' && MALICIOUS_AXIOS_VERSIONS.has(String(v.version || '').trim())) {
          addAxiosFinding(findings, filePath, String(v.version).trim());
        }
        walk(v);
      }
    };

    if (parsed && typeof parsed === 'object') walk(parsed);
  }

  for (const version of MALICIOUS_AXIOS_VERSIONS) {
    const rx = new RegExp(`axios(?:@|\\s|/)?${version.replace('.', '\\.').replace('.', '\\.')}`);
    if (rx.test(text)) addAxiosFinding(findings, filePath, version);
  }

  if (/plain-crypto-js/.test(text)) {
    const sev = /plain-crypto-js[^\n]*4\.2\.1/.test(text) ? 'critical' : 'high';
    findings.push(
      finding(
        sev,
        'dependency',
        filePath,
        'Suspicious plain-crypto-js dependency reference detected',
        'plain-crypto-js appeared in the axios compromise chain and should not be present in normal axios installs.'
      )
    );
  }
}

function checkGenericJsonForIndicators(filePath, findings) {
  const text = safeRead(filePath);
  if (!text) return;

  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (_err) {
    parsed = null;
  }

  const walk = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    if (Array.isArray(obj)) {
      for (const item of obj) walk(item);
      return;
    }

    if (obj.name === 'axios' && MALICIOUS_AXIOS_VERSIONS.has(String(obj.version || '').trim())) {
      findings.push(
        finding(
          'critical',
          'json-indicator',
          filePath,
          `JSON indicator references malicious axios version: ${String(obj.version).trim()}`,
          'Structured JSON parsing identified a malicious axios version field.'
        )
      );
    }

    for (const [k, v] of Object.entries(obj)) {
      if (k === 'axios' && v && typeof v === 'object' && MALICIOUS_AXIOS_VERSIONS.has(String(v.version || '').trim())) {
        findings.push(
          finding(
            'critical',
            'json-indicator',
            filePath,
            `JSON indicator references malicious axios version: ${String(v.version).trim()}`,
            'Structured JSON parsing identified axios object with malicious version.'
          )
        );
      }
      walk(v);
    }
  };

  if (parsed && typeof parsed === 'object') walk(parsed);

  for (const version of MALICIOUS_AXIOS_VERSIONS) {
    const rx1 = new RegExp(`axios(?:@|\\s|/)?${version.replace('.', '\\.').replace('.', '\\.')}`);
    const rx2 = new RegExp(`"axios"\\s*:\\s*\\{[^\\}]*"version"\\s*:\\s*"${version.replace('.', '\\.').replace('.', '\\.')}"`);
    if (rx1.test(text) || rx2.test(text)) {
      findings.push(
        finding(
          'critical',
          'json-indicator',
          filePath,
          `Regex indicator references malicious axios version: ${version}`,
          'Regex scanning of JSON text matched a malicious axios version pattern.'
        )
      );
    }
  }

  if (/plain-crypto-js/.test(text)) {
    findings.push(
      finding(
        'high',
        'json-indicator',
        filePath,
        'Regex indicator references plain-crypto-js in JSON file',
        'Regex scanning found plain-crypto-js token in JSON content; investigate dependency chain.'
      )
    );
  }
}

function checkInstalledNodeModules(root, findings) {
  // Recursively inspect all node_modules directories under root so scans work
  // for full home-directory scans and monorepos.
  for (const filePath of iterFiles(root)) {
    if (!filePath.endsWith(path.join('node_modules', 'axios', 'package.json'))) continue;
    let version = '';
    try {
      version = String(JSON.parse(safeRead(filePath) || '{}').version || '').trim();
    } catch (_err) {
      version = '';
    }
    if (MALICIOUS_AXIOS_VERSIONS.has(version)) {
      findings.push(
        finding('critical', 'installed-package', filePath, `Installed axios version is malicious: ${version}`, 'Known compromised version discovered directly in nested node_modules.')
      );
    }
  }

  for (const filePath of iterFiles(root)) {
    if (!filePath.endsWith(path.join('node_modules', MALICIOUS_DEPENDENCY, 'package.json'))) continue;
    const plainCryptoDir = path.dirname(filePath);
    let details = 'Directory exists. Huntress notes presence of node_modules/plain-crypto-js can indicate compromise, even if package contents look benign after self-cleanup.';
    let sev = 'high';
    try {
      const version = String(JSON.parse(safeRead(filePath) || '{}').version || '').trim();
      if (SUSPICIOUS_PLAIN_CRYPTO_VERSIONS.has(version)) {
        sev = 'critical';
        details += ` package.json reports suspicious version ${version}.`;
      } else if (version) {
        details += ` package.json reports version ${version}; this can be spoofed post-infection.`;
      }
    } catch (_err) {
      // noop
    }

    findings.push(
      finding(sev, 'installed-package', plainCryptoDir, 'Suspicious dependency directory detected: node_modules/plain-crypto-js', details)
    );
  }
}

function checkHostIocs(findings) {
  const expanded = ['/Library/Caches/com.apple.act.mond', '/tmp/ld.py'];

  if (process.platform === 'win32') {
    if (process.env.PROGRAMDATA) {
      expanded.push(path.join(process.env.PROGRAMDATA, 'wt.exe'));
      expanded.push(path.join(process.env.PROGRAMDATA, 'system.bat'));
    }
    if (process.env.TEMP) {
      expanded.push(path.join(process.env.TEMP, '6202033.vbs'));
      expanded.push(path.join(process.env.TEMP, '6202033.ps1'));
    }
  }

  for (const p of expanded) {
    if (fs.existsSync(p)) {
      findings.push(
        finding('critical', 'host-artifact', p, 'Known axios-compromise filesystem IOC detected', 'IOC path exists on disk and maps to published malware artifacts.')
      );
    }
  }
}

function runScan(root) {
  const findings = [];
  for (const filePath of iterFiles(root)) {
    const base = path.basename(filePath);
    if (LOCKFILE_CANDIDATES.has(base)) {
      checkLockfileForVersions(filePath, findings);
    } else if (filePath.endsWith('.json')) {
      checkGenericJsonForIndicators(filePath, findings);
    }
  }

  checkInstalledNodeModules(root, findings);
  checkHostIocs(findings);

  return {
    scanned_root: path.resolve(root),
    findings,
    compromised: findings.some((f) => f.severity === 'critical' || f.severity === 'high'),
    iocs: {
      malicious_versions: {
        axios: Array.from(MALICIOUS_AXIOS_VERSIONS).sort(),
        [MALICIOUS_DEPENDENCY]: Array.from(SUSPICIOUS_PLAIN_CRYPTO_VERSIONS).sort(),
      },
      malicious_sha1: MALICIOUS_SHA1,
      network: NETWORK_IOCS,
      filesystem: FILE_IOCS,
    },
  };
}

function printHumanReport(report) {
  console.log('==============================================================================');
  console.log('Axios 2026 Supply-Chain Compromise Scanner (Node.js)');
  console.log('==============================================================================');
  console.log(`Scanned root: ${report.scanned_root}`);
  console.log(`Findings: ${report.findings.length}`);
  console.log(`Compromised (heuristic): ${report.compromised ? 'YES' : 'NO'}`);

  if (report.findings.length) {
    console.log('\nFindings:');
    report.findings.forEach((f, idx) => {
      console.log(`  ${idx + 1}. [${String(f.severity || '').toUpperCase()}] ${f.summary}`);
      console.log(`     Category: ${f.category}`);
      console.log(`     Path:     ${f.path}`);
      console.log(`     Details:  ${f.details}`);
    });
  }

  console.log('\nRecommended response if findings are present:');
  console.log('  1) Assume credential exposure on affected hosts; rotate secrets immediately.');
  console.log('  2) Rebuild affected systems from known-good images (avoid in-place cleanup).');
  console.log('  3) Pin axios to safe versions (1.14.0 or 0.30.3) and reinstall with --ignore-scripts.');
  console.log('  4) Block network IOC: sfrclak.com / 142.11.206.73 / port 8000.');
}

function parseArgs(argv) {
  const args = { root: '.', json: false, selfTest: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a === '--self-test') args.selfTest = true;
    else if (a === '--root') {
      const v = argv[i + 1];
      if (!v) throw new Error('--root requires a path');
      args.root = v;
      i += 1;
    } else {
      throw new Error(`Unknown argument: ${a}`);
    }
  }
  return args;
}

function runSelfTest() {
  const results = [];
  const record = (name, passed, details = '') => results.push({ name, passed, details });

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'axios-scan-test-node-'));
  try {
    const clean = runScan(tmp);
    record('clean_workspace', clean.compromised === false && clean.findings.length === 0, `findings=${clean.findings.length}`);

    const lock = path.join(tmp, 'package-lock.json');
    fs.writeFileSync(lock, JSON.stringify({ dependencies: { axios: { version: '1.14.1' } } }), 'utf8');
    const compromised = runScan(tmp);
    record('lockfile_malicious_axios', compromised.compromised === true && compromised.findings.some((f) => /axios version/i.test(f.summary)), `findings=${compromised.findings.length}`);

    const plainDir = path.join(tmp, 'node_modules', 'plain-crypto-js');
    fs.mkdirSync(plainDir, { recursive: true });
    fs.writeFileSync(path.join(plainDir, 'package.json'), JSON.stringify({ name: 'plain-crypto-js', version: '4.2.1' }), 'utf8');
    const compromised2 = runScan(tmp);
    record('node_modules_plain_crypto', compromised2.compromised === true && compromised2.findings.some((f) => f.summary.includes('plain-crypto-js')), `findings=${compromised2.findings.length}`);

    const nestedAxiosDir = path.join(tmp, 'users', 'example', 'project', 'node_modules', 'axios');
    fs.mkdirSync(nestedAxiosDir, { recursive: true });
    fs.writeFileSync(path.join(nestedAxiosDir, 'package.json'), JSON.stringify({ name: 'axios', version: '0.30.4' }), 'utf8');
    const compromised3 = runScan(tmp);
    record(
      'nested_node_modules_recursive_scan',
      compromised3.compromised === true && compromised3.findings.some((f) => /installed axios version is malicious/i.test(f.summary)),
      `findings=${compromised3.findings.length}`
    );

    console.log('Self-test results:');
    let failures = 0;
    for (const r of results) {
      console.log(`  - ${r.name}: ${r.passed ? 'PASS' : 'FAIL'} ${r.details}`);
      if (!r.passed) failures += 1;
    }
    console.log(`Summary: ${results.length - failures}/${results.length} tests passed`);

    return failures === 0 ? 0 : 2;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function main(argv) {
  try {
    const args = parseArgs(argv);
    if (args.selfTest) return runSelfTest();

    const root = args.root;
    if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
      console.error(`[error] --root does not exist or is not a directory: ${root}`);
      return 2;
    }

    const report = runScan(root);
    if (args.json) {
      console.log(JSON.stringify({ ...report, finding_count: report.findings.length }, null, 2));
    } else {
      printHumanReport(report);
    }

    return report.compromised ? 1 : 0;
  } catch (err) {
    console.error(`[error] scanner failed: ${err.message}`);
    return 2;
  }
}

process.exitCode = main(process.argv.slice(2));
