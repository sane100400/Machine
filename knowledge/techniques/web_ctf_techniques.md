# Web CTF Techniques Reference

> Source: ~/tools/google-ctf/, PayloadsAllTheThings, practical CTF experience
> Last updated: 2026-02-24

## 1. XSS Patterns

### DOM XSS
- URL fragment injection: `https://target/#<img src=x onerror=alert(1)>`
- Common sinks: innerHTML, document.write, eval, setTimeout, jQuery.html()
- Common sources: location.hash, location.search, document.referrer, postMessage

### Mutation XSS (mXSS)
- Browser HTML parser re-interprets sanitized output
- DOMPurify bypass patterns use namespace confusion (math/svg elements)
- Test: nested elements that re-parse after sanitizer processes them

### CSP Bypass Techniques
| Technique | When | Notes |
|-----------|------|-------|
| Nonce leak | Nonce in DOM | Fetch page source, extract nonce, inject script |
| base-uri | No base-uri directive | Redirect all relative URLs to attacker |
| JSONP callback | Allowlisted domains with JSONP | Google, Facebook, CDN JSONP endpoints |
| object-src | No object-src | Embed attacker HTML via object tag |
| Dangling markup | Strict CSP | Exfiltrate via img src before quote closes |

## 2. SSRF Techniques

### Cloud Metadata Endpoints
- AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- GCP: `http://169.254.169.254/computeMetadata/v1/` (requires Metadata-Flavor header)
- Azure: `http://169.254.169.254/metadata/instance` (requires Metadata:true header)

### URL Parser Differentials
- Hex IP: `http://0x7f000001/`
- Octal IP: `http://0177.0.0.1/`
- Shortened: `http://127.1/`
- IPv6 mapped: `http://[::ffff:127.0.0.1]/`
- Backslash confusion: `http://127.0.0.1:80\@evil.com/`
- Fragment: `http://evil.com#@trusted.com`

### DNS Rebinding
1. Set up domain with TTL=0
2. First resolve returns attacker IP (passes allowlist)
3. Second resolve returns 127.0.0.1 (hits internal service)
4. Tool: `~/SSRFmap/` (18+ modules)

## 3. Deserialization

### PHP Unserialize
- POP chains: __destruct → __toString → file_write
- phar:// wrapper triggers deserialization without unserialize() call
- Tool: PHPGGC for gadget chain generation

### Java (ysoserial)
- Common chains: CommonsCollections1-7, CB1, Hibernate, Spring, JDK7u21
- Detection: rO0AB (base64), AC ED 00 05 (hex header)
- Bypass: custom ObjectInputStream filters → use lesser-known chains

### Python Pickle
- __reduce__ method controls unpickling behavior
- Can call arbitrary functions with arguments
- Detection: \x80\x04\x95 header bytes

### Node.js
- node-serialize: _$$ND_FUNC$$_ prefix enables function execution
- cryo: similar deserialization risks
- Template engines: devalue, superjson — check for prototype pollution

## 4. SSTI (Server-Side Template Injection)

### Detection Polyglot
```
${{<%[%'"}}%\
```
Check: {{7*7}}=49 (Jinja2/Twig), ${7*7}=49 (Freemarker), #{7*7}=49 (Pebble)

### Exploitation by Engine
| Engine | Key Payload Pattern |
|--------|-------------------|
| Jinja2 | Access __subclasses__ via MRO chain → Popen |
| Jinja2 (short) | lipsum.__globals__.os.popen() |
| Twig | registerUndefinedFilterCallback → system |
| Freemarker | Execute class instantiation |
| Pebble | Runtime.getRuntime().exec() via reflection |
| ERB (Ruby) | system() via template evaluation |

## 5. JWT Attacks

### Algorithm Confusion
- **none algorithm**: Remove signature, set alg to "none"
- **HS256 with RS256 public key**: Sign with public key as HMAC secret
- Requires: Public key accessible (/.well-known/jwks.json, /api/keys)

### JWK/JKU Injection
- Inject attacker JWK in header → server uses it for verification
- JKU: Point to attacker JWKS endpoint

### kid Injection
- Path traversal: kid = "../../dev/null" → sign with empty string
- SQL injection: kid = "1' UNION SELECT 'secret' -- "
- Command injection: kid = "key | whoami"

## 6. Prototype Pollution

### Detection Vectors
- URL: `?__proto__[polluted]=1`
- JSON body: `{"__proto__":{"polluted":true}}`
- constructor.prototype path

### PP to RCE Chains
| Framework | Gadget Target |
|-----------|--------------|
| Express + EJS | outputFunctionName property |
| Express + Pug | block.type = "Text" with code |
| Express + Handlebars | constructor template manipulation |
| Lodash merge | Shell/NODE_OPTIONS injection |

## 7. Race Conditions

### TOCTOU (Time-of-Check to Time-of-Use)
- Send parallel requests to exploit check-then-act gap
- Threading: 50+ concurrent requests to the same endpoint
- Targets: balance transfers, coupon redemption, vote counting

### HTTP/2 Single-Packet Attack
- Send N requests in single TCP packet (eliminates network jitter)
- Tools: turbo-intruder, custom HTTP/2 client
- Most effective for: limit bypass, double-spend, coupon reuse

### Techniques
- **Limit overrun**: Send 100 "use coupon" requests simultaneously
- **Double spend**: Transfer full balance to two accounts simultaneously
- **TOCTOU file**: Upload check → replace file → use uploaded file

## 8. Google CTF Challenge Index (~/tools/google-ctf/)

### 2025 Quals
| Challenge | Category |
|-----------|----------|
| web-postviewer5 | XSS / iframe sandbox escape |
| web-postviewer5-ff | Firefox-specific XSS variant |
| web-sourceless | Server-side vulnerability |
| web-js-safe-6 | JavaScript reverse engineering |
| web-inspector-gadget | Gadget chain exploitation |
| web-lost-in-transliteration | Encoding/parser differential |
| web-mythos-python | Python web exploitation |
| web-mythos-perl | Perl-specific web vulnerabilities |

### 2022 Quals
| Challenge | Category |
|-----------|----------|
| web-gpushop | Payment/logic bypass |
| web-postviewer | XSS / iframe communication |
| web-horkos | Deserialization / protobuf |
| web-log4j | Log4Shell exploitation |
| sandbox-treebox | Python sandbox escape |

## 9. Tool Quick Reference

| Tool | Path | Best For |
|------|------|----------|
| PayloadsAllTheThings | `~/PayloadsAllTheThings/` | All payload categories |
| SSRFmap | `~/SSRFmap/` | SSRF exploitation (18+ modules) |
| commix | `~/commix/` | Command injection automation |
| dalfox | `~/gopath/bin/dalfox` | XSS scanning |
| sqlmap | system | SQL injection automation |
| fuxploider | `~/fuxploider/` | File upload exploitation |
| arjun | system | HTTP parameter discovery |
| nuclei | system | Template-based vuln scanning |
