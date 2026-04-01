# Huntress: Supply chain compromise of axios npm package (reference notes)

- Source URL: <https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package>
- Publisher: Huntress
- Accessed: 2026-04-01

## Why this source is included

This page provides incident analysis and practical indicators that can be translated into scanner checks and SOC hunting logic.

## Key extraction notes used by the scanner

- Published IOC details were used to shape scanner constants and report context:
  - package/version indicators
  - hash indicators
  - selected network and filesystem artifacts
- The scanner reports these indicators and checks for artifact presence in recursive directory scans.

## Original article

Please review the original source directly for full context, exact language, and any updates:

<https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package>
