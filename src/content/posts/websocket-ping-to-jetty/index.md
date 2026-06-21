---
title: "From WebSocket PING to Jetty Backend: Reconnaissance of a Live Casino Platform"
published: 2026-06-21
description: "How a single intercepted WebSocket request led to information disclosure, directory listing, and backend fingerprinting of a live casino platform."
image: /images/coverpost1.png
tags: [BugBounty, WebSocket, Reconnaissance, Jetty, InformationDisclosure]
category: Security Research
draft: false
---

## 0x00 — Prologue: A Single Intercept

It all started with one simple request while I was browsing a live casino client portal. Burp Suite caught this:

```http
GET /ws HTTP/1.1
Host: dga.dkitrxmdwoqruvsi.net
Connection: Upgrade
Upgrade: websocket
Origin: https://client.dkitrxmdwoqruvsi.net
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: oRRH9vs2xQP9GEC6oioO4w==
Cookie: AWSALB=...; AWSALBCORS=...
```

A WebSocket handshake. But the interesting part wasn't the `Sec-WebSocket-Key` — that's just an RFC 6455 nonce. What caught my eye was the exposed endpoint with a full session cookie, and the fact that there were other subdomains pointing to a deeper infrastructure.

## 0x01 — Phase 1: WebSocket Reconnaissance

First attempts with `websocat` and `openssl` failed — the server required a valid `Origin` header and session cookie. After some trial and error, a Python script finally completed the handshake:

```python
import websocket, ssl

ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
ws.connect(
    "wss://dga.dkitrxmdwoqruvsi.net/ws",
    header=["Origin: https://client.dkitrxmdwoqruvsi.net"],
    cookie="JSESSIONID=..."
)
ws.send('{"type":"ping"}')
print(ws.recv())
# {"pongTime":1781999879654,"pingTime":0}
```

### Finding #1: WebSocket Information Disclosure

The server responded with an internal `pongTime` timestamp and `userId: "null"`, `role: "null"`. This indicated anonymous access to the heartbeat endpoint — valuable reconnaissance data.

I moved on to the `/chat` WebSocket endpoint:

```python
ws.connect("wss://chat.dkitrxmdwoqruvsi.net/chat", ...)
ws.send('{"action":"ping"}')
# {"action":"PONG","status":"SUCCESS","userId":"null","role":"null","pongtime":...}
```

### Finding #2: Protocol Structure Leak

Invalid payloads returned structured error messages, revealing the server expects an `action` field (not `type`). More importantly: no rate limiting and the server didn't aggressively drop connections, leaving room for enumeration.

## 0x02 — Phase 2: The URL Goldmine

Looking closer at the browser URL bar, I found something alarming. The client portal query parameters contained sensitive data that should never be in a URL:

```plain
https://games.dkitrxmdwoqruvsi.net/...&config_url=/cgibin/appconfig/xml/configs/urls.xml
&JSESSIONID=vWhhhigmpIj5tOA0Y3K8bjdbkr6eu3B3OikeOlkl0pkXe1B-5ByJ!...
&userId=ppc1735045641964
&socket_server=wss://games.dkitrxmdwoqruvsi.net/game
&token=...
&stats_collector_uuid=328e5abc-17f0-49f3-8eb0-0ed92fd9e1d1
```

### Finding #3: Sensitive Information in URL Parameters (P3)

`JSESSIONID`, session token, `userId`, internal paths (`cgibin/appconfig/xml/configs/urls.xml`), and internal WebSocket endpoints were all exposed in the URL. Impact: browser history, proxy logs, and referrer headers will carry these credentials.

## 0x03 — Phase 3: Unauthenticated Manifest & CORS

Following the `config_url` parameter, I tried direct access:

```bash
curl -s "https://client.dkitrxmdwoqruvsi.net/apps/feature-flags/1.0.0/lobby.manifest.json"
```

Response:

```json
{
  "game": [{"version": "3.83.0"}],
  "defaultFeaturedGames": [{"value": ["270", "292", "204"]}],
  "heroBannerVideo": [{"enabled": true}],
  "gameAssetsBaseUrl": [{"value": ""}],
  "newComms": [{"enabled": true}],
  "slotsCurrencyNewFormat": [{"enabled": true}]
}
```

### Finding #4: Feature Flags Manifest Exposure (P3)

Internal configuration files were accessible without authentication. This revealed version disclosure (`3.83.0`), internal game IDs (`270`, `292`, `204`), and active feature flags exposing business logic.

**Bonus:** CORS headers showed `access-control-allow-origin: *` on static files — limited impact since the files are public-by-design, but still worth noting.

## 0x04 — Phase 4: Directory Listing & Source Code Exposure

Reconnaissance continued to the `games.` subdomain — and that's where the door opened wider.

```bash
curl -s "https://games.dkitrxmdwoqruvsi.net/authentication/" | grep 'href="'
```

Output:

```plain
/authentication/../
/authentication/authenticate.jsp
/authentication/logout.jsp
/authentication/request.js
/authentication/xlg_BO_footer.png
/authentication/xlg_BO_footer_over.png
jetty-dir.css
```

### Finding #5: Directory Listing Enabled (P3)

The server exposed directory listing under `/authentication/`, revealing JSP files and internal JavaScript logic.

I grabbed `authenticate.jsp` and `request.js`. The contents were surprising:

`authenticate.jsp` revealed:

- Login API endpoint: `POST /api/security/portal/login`
- Internal casino IDs: `il9srgw4dna23p47`, `il9srgw4dna11111`, `il9srgw4dna22222`
- Session token passed via URL: `/portal?JSESSIONID=...`
- `withCredentials: true` on CORS requests

`request.js` revealed:

- CORS request handler with `xhr.withCredentials = true`
- Content-type: `application/json` on POST requests
- `extractDomain()` helper for URL parsing

## 0x05 — Phase 5: Backend Fingerprinting — The Jetty Revelation

I tried sending an invalid JSON payload to the login API:

```bash
curl -s -X POST "https://games.dkitrxmdwoqruvsi.net/api/security/portal/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"pass":{"$ne":null},"time":1234567890}'
```

The response was a goldmine:

```plain
Can not deserialize instance of java.lang.String out of START_OBJECT token
 at [Source: HttpInput@627799400 cs=HttpChannelState@4543fddc...
 cp=org.eclipse.jetty.ee8.nested.BlockingContentProducer@49b2d60f...
 (through reference chain: com.extremelivegaming.api.security.vo.LoginVO["username"])
```

### Finding #6: Java Backend & Package Name Disclosure (P3/P4)

From the stack trace error, I extracted:

- **Server:** Jetty EE8 (`org.eclipse.jetty.ee8.nested.BlockingContentProducer`)
- **Vendor Package:** `com.extremelivegaming.api.security.vo.LoginVO`
- **Deserialization:** Jackson strict type checking

This is critical information disclosure — internal package structure that can be used to build gadget chains or further reconnaissance.

## 0x06 — Phase 6: The Bigger Picture

From all findings, the target architecture became clear:

| Layer | Technology |
|-------|------------|
| Frontend | S3 + CloudFront (Static) |
| Reverse Proxy | nginx |
| Application Server | Jetty EE8 |
| Backend | Java (Extreme Live Gaming) |
| WebSocket | Custom protocol (action-based JSON) |
| Session | JSESSIONID (Java/Jetty style) |

## 0x07 — Impact Summary

| Finding | Severity | Issue |
|---------|----------|-------|
| Sensitive tokens in URL | P3 | JSESSIONID, userId, token leak via URL |
| Feature flags manifest | P3 | Unauthenticated internal config access |
| Directory listing | P3 | Source code & JSP exposure |
| Internal package leak | P4 | `com.extremelivegaming` package disclosure |
| WebSocket info leak | P4 | `pongTime`, `userId: null` exposure |
| CORS wildcard | P4 | `access-control-allow-origin: *` on static |

## 0x08 — Takeaways & Lessons Learned

- **WebSocket is not just "real-time chat"** — it's often a gateway to deeper backend logic. Never skip WS recon.
- **URL parameters are the enemy** — always inspect query strings in intercepts; credentials often "stick" there.
- **Directory listing is still alive in 2026** — `/authentication/` with `jetty-dir.css` is proof that classic misconfigs never die.
- **Error messages are gold** — one invalid JSON payload opened the entire backend stack (`org.eclipse.jetty.ee8`, `com.extremelivegaming`).
- **Don't chase CVEs blindly** — this target wasn't Next.js, wasn't Spring Boot (despite similar-looking errors), but Jetty EE8 + custom Java stack. Match the CVE to the stack.

## 0x09 — Responsible Disclosure

All findings were documented with:

- Screenshots of requests and responses
- cURL commands for reproducibility
- Testing timeline (June 2026)
- Per-finding impact assessment

> **Note:** No exploitation beyond proof-of-concept was performed. No game state manipulation, betting interference, or unauthorized data access was attempted. All testing stayed within the scope of security research.

Thanks for reading. If you have feedback or corrections, feel free to reach out. Happy hacking! 🎯
