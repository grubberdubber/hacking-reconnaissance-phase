**IMPORTANTE (legal / seguridad):** Ejecuta **solo** contra entornos que controlas o tienes autorización explícita. No automatices explotación; esto es descubrimiento y validación.

---

## Pipeline definitivo (lista de comandos — copia/pega)

### 1) OSINT / certificados / subdominios (múltiples fuentes)

```bash
# Subdominios básicos
subfinder -d ejemplo.test -o subfinder.txt -v
assetfinder --subs-only ejemplo.test | sort -u > assetfinder.txt

# theHarvester (emails, hosts, etc)
theHarvester -d ejemplo.test -b all -l 5000 -f theharvester_ejemplo.html

# crt.sh (certificados)
curl -s "https://crt.sh/?q=%25.ejemplo.test&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | tr ',' '\n' | sort -u > crtsh_subs.txt

# CertSpotter (requiere API token opcional)
# curl -H "Authorization: Bearer $CERTSPOTTER_TOKEN" "https://api.certspotter.com/v1/issuances?domain=ejemplo.test&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u > certspotter_subs.txt

# Findomain (rápido y fiable)
findomain -t ejemplo.test -q -u findomain_subs.txt

# ThreatCrowd (pasivo)
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=ejemplo.test" | jq -r '.subdomains[]' | sort -u > threatcrowd_subs.txt

# AlienVault OTX (opcional, necesita API key)
# curl -s "https://otx.alienvault.com/api/v1/indicators/domain/ejemplo.test/passive_dns" | jq -r '.passive_dns[].hostname' | sort -u > otx_subs.txt

# PublicWWW (opcional, requiere API key) -> buscar referencias y JS patterns
# curl -s "https://publicwww.com/websites/ejemplo.test/" > publicwww_raw.html
```

---

### 2) Consolidar fuentes iniciales

```bash
cat subfinder.txt assetfinder.txt crtsh_subs.txt findomain_subs.txt threatcrowd_subs.txt 2>/dev/null | sort -u > all_subs_initial.txt
```

---

### 3) Enumeración DNS completa (passive + brute)

```bash
dnsenum --enum ejemplo.test --threads 20 --retry 3 -v -o dnsenum_out.txt
dnsrecon -d ejemplo.test -t std -D /usr/share/seclists/Discovery/DNS/big.txt -a -v > dnsrecon_out.txt
amass enum -passive -d ejemplo.test -o amass_passive.txt -v
amass enum -brute -d ejemplo.test -o amass_bruteforce.txt -v
```

---

### 4) Resolución masiva (shuffledns, massdns, dnsx)

```bash
cat all_subs_initial.txt amass_passive.txt amass_bruteforce.txt dnsenum_out.txt dnsrecon_out.txt 2>/dev/null | sort -u > all_subs_raw.txt

# shuffledns (wordlist SecLists grande)
shuffledns -d ejemplo.test -w /usr/share/seclists/Discovery/DNS/subdomains-top1million.txt -r resolvers.txt -v -o shuffledns_resolved.txt

# massdns (fast bulk resolution)
massdns -r resolvers.txt -t A -o S -w /usr/share/seclists/Discovery/DNS/subdomains-top1million.txt -v > massdns_out.txt

# unir y filtrar names
cat shuffledns_resolved.txt massdns_out.txt all_subs_raw.txt | sort -u > all_subs_resolved_candidates.txt

# dnsx: A/AAAA/CNAME/resolve + reverse, salida detallada
cat all_subs_resolved_candidates.txt | dnsx -a -aaaa -cname -resp -v -o dnsx_resolved.txt

# limpiar hostnames (extraer hostnames desde dnsx)
awk '{print $1}' dnsx_resolved.txt | sed 's/:.*$//' | sort -u > all_subs_resolved.txt
```

---

### 5) Probing / fingerprinting (httpx)

```bash
cat all_subs_resolved.txt | httpx -threads 200 -timeout 15 -status-code -title -content-length -content-type -tech-detect -follow-redirects -v -o httpx_hosts.txt
# extraer lista de URLs/hosts en formato usable
awk '{print $1}' httpx_hosts.txt | sed 's/https\?:\/\///' | sort -u > hosts_up.txt
```

---

### 6) Recolección histórica y OSINT URLs (gau, waybackurls, CommonCrawl)

```bash
cat all_subs_resolved.txt | sort -u | while read host; do echo "$host"; done | gau > gau_all_urls.txt
cat all_subs_resolved.txt | sort -u | while read host; do echo "$host"; done | waybackurls > wayback_urls.txt

# CommonCrawl index queries (simple, may necesitar paginado/ratelimit)
cat all_subs_resolved.txt | while read host; do curl -s "https://index.commoncrawl.org/CC-MAIN-2023-50-index?url=*.$host/*&output=json"; done | jq -r '.url' | sort -u > commoncrawl_urls.txt

# combinar y filtrar
cat gau_all_urls.txt wayback_urls.txt commoncrawl_urls.txt | sort -u > historical_urls_raw.txt
grep -E '\?|=' historical_urls_raw.txt | sort -u > historical_urls_with_params.txt
```

---

### 7) Crawling (Katana) y extracción de URLs / sitemap

```bash
mkdir -p katana_out
for host in $(awk '{print $1}' httpx_hosts.txt | sed 's|https\?://||' | sort -u); do
  katana -u "https://$host" -d 4 -o "katana_out/katana_${host}.txt" -v &
done
wait
cat katana_out/katana_*.txt | sort -u > katana_combined.txt
```

---

### 8) Extracción de endpoints desde JS (LinkFinder / grep) y ParamSpider

```bash
# LinkFinder (extrae endpoints desde JS/reference)
python3 /opt/LinkFinder/linkfinder.py -i katana_combined.txt -o cli -d -v > linkfinder_out.txt

# JS files list
grep -E '\.js($|\?)' katana_combined.txt historical_urls_raw.txt | sort -u > js_files.txt

# descargar JS en paralelo (nombres hash)
mkdir -p js_dl
cat js_files.txt | xargs -n1 -P40 -I{} bash -c 'curl -L "{}" -s -v -o js_dl/$(echo "{}" | md5sum | cut -d" " -f1).js'

# extraer endpoints de JS
grep -Eo 'https?://[A-Za-z0-9._:/?&=%#-]+' js_dl/*.js | sed 's/\/$//' | sort -u > js_endpoints.txt

# ParamSpider (extrae parametros pasivos)
python3 ~/ParamSpider/paramspider.py -d ejemplo.test -o paramspider_out -l all_subs_resolved.txt -v
```

---

### 9) Consolidar todas las URLs y validar (httpx enriquecido)

```bash
cat katana_combined.txt historical_urls_raw.txt js_endpoints.txt linkfinder_out.txt paramspider_out/* | sort -u > combined_urls_all_raw.txt

# validar y enriquecer
cat combined_urls_all_raw.txt | httpx -threads 200 -timeout 20 -status-code -content-type -content-length -title -tech-detect -follow-redirects -v -o validated_urls.txt
```

---

### 10) Fuzzing de directorios (feroxbuster / ffuf / gobuster) — wordlists grandes

```bash
# feroxbuster por host (usa SecLists raft-large/commons)
for host in $(cat hosts_up.txt); do
  feroxbuster -u "https://$host" -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt --depth 4 --threads 50 --timeout 25 -v -o ferox_${host}.txt &
done
wait
cat ferox_*.txt | sort -u > ferox_combined.txt

# ffuf para hosts prioritarios
ffuf -u 'https://sub.example.test/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 60 -mc 200,301,302 -v -o ffuf_dirs.json -of json

# gobuster alternativa
gobuster dir -u https://sub.example.test -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 60 -v -o gobuster_sub.txt
```

---

### 11) Fuzzing de parámetros y pruebas XSS/SQLi (ffuf / dalfox / wfuzz)

```bash
# ffuf parametrizado
ffuf -u 'https://sub.example.test/page.php?param=FUZZ' -w /usr/share/seclists/Fuzzing/Parameters/params.txt -t 60 -mc 200,302 -v -o ffuf_params.json -of json

# dalfox scan (XSS)
cat validated_urls.txt | dalfox file - --skip-bav -v -o dalfox_results.txt

# wfuzz para pruebas SQLi (usa listas grandes)
wfuzz -c -w /usr/share/seclists/Fuzzing/SQLi/SQLi.txt --hc 404 "https://sub.example.test/page.php?id=FUZZ"
```

---

### 12) Detección por templates (nuclei) + takeovers

```bash
# nuclei full scan (usa templates oficiales)
cat validated_urls.txt | nuclei -t /path/to/nuclei-templates/ -c 100 -v -o nuclei_results_verbose.txt -json nuclei_results_verbose.json

# takeover specific (hosts up)
cat all_subs_raw.txt | dnsx -a -v -o tmp_hosts_ips.txt
cat tmp_hosts_ips.txt | httpx -v -o hosts_up_for_takeover.txt
cat hosts_up_for_takeover.txt | nuclei -t vulnerabilities/takeovers -v -o takeover_results.txt
```

---

### 13) Subdomain takeover / CNAME checks (subjack, subzy)

```bash
cat all_subs_raw.txt | subjack -w - -t 50 -v -ssl -o subjack_out_verbose.txt
cat all_subs_raw.txt | dnsx -cname -v -o cname_results.txt
```

---

### 14) Escaneo de puertos (masscan rápido + nmap profundo)

```bash
# masscan (requiere root)
sudo masscan -p1-65535 --rate 2500 target_ip -oG masscan_grep.txt

# extraer IPs de masscan y dnsx y hacer nmap detallado por IP
cat masscan_grep.txt | grep open | awk '{print $2}' | sort -u > ips_from_masscan.txt
awk '{print $2}' dnsx_resolved.txt | cut -d':' -f1 | sort -u >> ips_from_masscan.txt
sort -u ips_from_masscan.txt > ips_to_scan.txt

for ip in $(cat ips_to_scan.txt); do
  sudo nmap -Pn -sV -sC -p- -T4 -v -oA nmap_full_${ip} $ip &
done
wait
```

---

### 15) Screenshots / visual triage (aquatone / gowitness)

```bash
cat validated_urls.txt | awk '{print $1}' | sort -u > urls_for_screens.txt
cat urls_for_screens.txt | aquatone -out aquatone_out -v
cat urls_for_screens.txt | gowitness file - -o gowitness_out --debug
```

---

### 16) Secrets / repos / JS scanning (gitleaks / trufflehog / SecretFinder)

```bash
gitleaks detect --source . --report-path gitleaks_report.json -v
trufflehog filesystem --json . > trufflehog_report.json
python3 /opt/SecretFinder/SecretFinder.py -i js_dl/ -o cli -v > secretfinder_out.txt

# gf patterns (filtrar potenciales XSS/SQLi/LFI)
cat validated_urls.txt | gf xss > gf_xss.txt
cat validated_urls.txt | gf sqli > gf_sqli.txt
cat validated_urls.txt | gf lfi > gf_lfi.txt
```

---

### 17) Normalización + correlación (con script de ejemplo)

Guarda outputs JSON/CSV para triage: nuclei (JSON), dalfox, ffuf (JSON), httpx (plain) se combinan. Abajo tienes un script Python (listo para guardar como `merge_results.py`) que *lee* varios archivos y genera `final_results.jsonl` y `final_results.csv`.

**Crea `merge_results.py`** con este contenido:

```python
#!/usr/bin/env python3
# merge_results.py
# Lee varios outputs y genera JSONL y CSV para triage rápido.

import json, csv, sys, os, re
from pathlib import Path

def load_lines(path):
    if not Path(path).exists():
        return []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [l.strip() for l in f if l.strip()]

def parse_httpx(path):
    # httpx default output is "url status title ..." -> keep raw url/status
    lines = load_lines(path)
    entries = []
    for l in lines:
        parts = l.split()
        if not parts:
            continue
        url = parts[0]
        status = None
        for p in parts[1:5]:
            if p.isdigit():
                status = p
                break
        entries.append({'source':'httpx','url':url,'status':status,'raw':l})
    return entries

def parse_nuclei_json(path):
    entries = []
    if not Path(path).exists():
        return entries
    with open(path,'r',encoding='utf-8') as f:
        for line in f:
            try:
                obj = json.loads(line)
                entries.append({'source':'nuclei','url': obj.get('host') or obj.get('matched',''), 'template': obj.get('template',''), 'info': obj})
            except Exception:
                continue
    return entries

def parse_ffuf_json(path):
    entries=[]
    if not Path(path).exists():
        return entries
    try:
        obj=json.load(open(path,'r',encoding='utf-8'))
        # ffuf json can be dict with results
        for r in obj.get('results',[]):
            entries.append({'source':'ffuf','url': r.get('url') or r.get('input',''), 'status': r.get('status',None), 'length': r.get('length',None), 'raw': r})
    except Exception:
        pass
    return entries

def parse_dalfox(path):
    entries=[]
    for l in load_lines(path):
        entries.append({'source':'dalfox','url':l,'raw':l})
    return entries

def main():
    out=[]
    out.extend(parse_httpx('httpx_hosts.txt'))
    out.extend(parse_nuclei_json('nuclei_results_verbose.json'))
    out.extend(parse_ffuf_json('ffuf_dirs.json'))
    out.extend(parse_dalfox('dalfox_results.txt'))
    # dedupe by url
    seen=set()
    dedup=[]
    for e in out:
        u=e.get('url') or e.get('raw') or ''
        if not u: continue
        key=u
        if key in seen: continue
        seen.add(key)
        dedup.append(e)
    # write JSONL
    with open('final_results.jsonl','w',encoding='utf-8') as f:
        for e in dedup:
            f.write(json.dumps(e,ensure_ascii=False) + "\\n")
    # write CSV (flat)
    keys=set()
    for e in dedup:
        keys.update(e.keys())
    keys=sorted(keys)
    with open('final_results.csv','w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for e in dedup:
            writer.writerow({k: json.dumps(e.get(k,''), ensure_ascii=False) if isinstance(e.get(k), (dict,list)) else e.get(k,'') for k in keys})
    print('Wrote final_results.jsonl and final_results.csv with', len(dedup), 'entries.')

if __name__ == '__main__':
    main()
```

Ejecuta:

```bash
python3 merge_results.py
```

---

### 18) Resumen / reporting rápido (líneas finales)

```bash
echo "Subdominios detectados:" > resumen_recon.txt
wc -l all_subs_raw.txt >> resumen_recon.txt
echo "Hosts vivos:" >> resumen_recon.txt
wc -l hosts_up.txt >> resumen_recon.txt
echo "URLs validadas:" >> resumen_recon.txt
wc -l validated_urls.txt >> resumen_recon.txt
echo "Nuclei findings:" >> resumen_recon.txt
wc -l nuclei_results_verbose.json >> resumen_recon.txt
