# Rebrands the product name in web/apps/web/src/locales/*/messages.json (TASKS #211).
# Replaces "Bitwarden" with "Cloudwarden" in message strings, except where the text names a real
# Bitwarden product the user installs separately (browser extension, mobile and desktop apps,
# Authenticator, CLI, Secrets Manager) or a URL, address or company name.
import glob, re, sys
KEEP_AFTER = r'(?:authenticator|browser|extens|erweiterung|app|aplik|applik|applica|aplica|anwendung|mobil|desktop|cli\b|secrets|inc\b|till[aä]gg|sovellu|laajennu|roz[sš][ií]ř|rozszerz|uzant|eklenti|estension|расширен|приложен|додат|розшир|扩展|擴充|应用|應用|拡張|アプリ|확장|앱)'
KEEP_BEFORE = r'(?:extension|extensión|extensão|estensione|erweiterung|application|aplicación|aplicativo|applicazione|appli|app|aplikac|applicatie|rozšíření|rozszerzeni|uzantısı|расширени|приложени|розширен|додат|扩展|擴充|应用|應用|拡張機能|アプリ|확장|앱)[\w\u2019\x27\s]{0,12}$'
RX = re.compile(r'(?<![\w./@-])Bitwarden(?![\w.-]*\.(?:com|eu|net|io)\b)(?=([\s\-‑]*)(\S*))')
def repl(m, line):
    after = (m.group(2) or '').lower()
    if re.match(KEEP_AFTER, after, re.I):
        return m.group(0)
    before = line[max(0, m.start() - 30):m.start()]
    if re.search(KEEP_BEFORE, before, re.I):
        return m.group(0)
    if re.match(r'[\w]', line[m.end():m.end()+1] or ' '):
        return m.group(0)
    return 'Cloudwarden'
total = 0
for f in sorted(glob.glob(sys.argv[1] + '/*/messages.json')):
    raw = open(f, encoding='utf-8').read(); out = []; c = 0
    for line in raw.split('\n'):
        if line.lstrip().startswith('"message":'):
            new = RX.sub(lambda m: repl(m, line), line)
            c += new != line; line = new
        out.append(line)
    if c: open(f, 'w', encoding='utf-8').write('\n'.join(out))
    total += c
print('lines changed', total)
