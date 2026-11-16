# Vulnerability Triage Report

Total unique findings: **229**

| Priority | Meaning | Count |
|---|---|---|
| P1 | Fix now: actively exploited or very likely to be | 0 |
| P2 | Fix this sprint | 11 |
| P3 | Schedule | 48 |
| P4 | Backlog | 170 |

## Top 15 findings

| # | Priority | Score | Severity | Tool | Finding | Location | EPSS | KEV |
|---|---|---|---|---|---|---|---|---|
| 1 | P2 | 55 | HIGH | gitleaks | Detected a Generic API Key | `...app/manage-passkeys/passkey-providers.ts:9` | - | - |
| 2 | P2 | 55 | HIGH | gitleaks | Detected a Generic API Key | `...pp/manage-passkeys/passkey-providers.ts:11` | - | - |
| 3 | P2 | 55 | HIGH | gitleaks | Detected a Generic API Key | `...pp/manage-passkeys/passkey-providers.ts:20` | - | - |
| 4 | P2 | 55 | HIGH | gitleaks | Identified a Private Key | `terraform/networking.tf:172` | - | - |
| 5 | P2 | 55 | HIGH | gitleaks | Identified a Private Key | `infrastructure/terraform/networking.tf:171` | - | - |
| 6 | P2 | 55 | HIGH | gitleaks | Detected a Generic API Key | `...end/src/app/faucet/faucet.component.ts:828` | - | - |
| 7 | P2 | 55 | HIGH | gitleaks | Detected a Generic API Key | `data/static/users.yml:18` | - | - |
| 8 | P2 | 55 | HIGH | gitleaks | Identified a Private Key | `lib/insecurity.js:12` | - | - |
| 9 | P2 | 55 | HIGH | gitleaks | Identified a Private Key | `.../machines/default/virtualbox/private_key:1` | - | - |
| 10 | P2 | 55 | HIGH | gitleaks | Detected a Generic API Key | `server.js:24` | - | - |
| 11 | P2 | 55 | HIGH | gitleaks | Detected a Generic API Key | `.travis.yml:8` | - | - |
| 12 | P3 | 43.3 | CRITICAL | trivy | jsonwebtoken 0.1.0: nodejs-jsonwebtoken: verification ste... | `Node.js` | 8.4% | - |
| 13 | P3 | 43.3 | CRITICAL | trivy | jsonwebtoken 0.4.0: nodejs-jsonwebtoken: verification ste... | `Node.js` | 8.4% | - |
| 14 | P3 | 42.0 | CRITICAL | trivy | lodash 2.4.2: nodejs-lodash: prototype pollution in defau... | `Node.js` | 5.0% | - |
| 15 | P3 | 40.3 | CRITICAL | trivy | crypto-js 3.3.0: crypto-js: PBKDF2 1,000 times weaker tha... | `Node.js` | 0.6% | - |
