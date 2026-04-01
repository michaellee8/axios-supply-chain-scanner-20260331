# Axios Supply-Chain Scanner (March 2026 Incident)

This repository contains two standalone scanners for investigating exposure to the March 2026 `axios` npm supply-chain compromise:

- `axios_compromise_scanner.py` (Python 3, standard library only)
- `axios_compromise_scanner.js` (Node.js, zero external dependencies)

## Purpose

These scripts help you quickly triage systems and source trees for known indicators reported in public incident write-ups, including:

- malicious `axios` versions
- suspicious `plain-crypto-js` dependency artifacts
- selected host and network IOCs
- nested `node_modules` evidence across recursive paths

They are intended to be portable and easy to run in incident response workflows, CI, and offline environments.

## Quick Start

### Python

```bash
python3 axios_compromise_scanner.py --root ~
python3 axios_compromise_scanner.py --root ~ --json
python3 axios_compromise_scanner.py --self-test
```

### Node.js

```bash
node axios_compromise_scanner.js --root ~
node axios_compromise_scanner.js --root ~ --json
node axios_compromise_scanner.js --self-test
```

## Output and Exit Codes

Both scripts support human-readable and JSON output.

Exit codes:

- `0` = no findings (or successful self-test)
- `1` = findings detected
- `2` = script/runtime error

## Documentation Sources

The `docs/` directory includes markdown notes for the two incident references requested by the user:

- `docs/stepsecurity-axios-compromise.md`
- `docs/huntress-axios-compromise.md`

These files contain source URLs and concise, practical extraction notes used for scanner heuristics.

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE).
