# 1) OSINT / certificados / subdominios

```bash
subfinder -d ejemplo.test -v -o subfinder.txt
theHarvester -d ejemplo.test -b all -l 5000 -f theharvester_ejemplo.html
curl -s "https://crt.sh/?q=%25.ejemplo.test&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | tr ',' '\n' | sort -u > crtsh_subs.txt

# Opcional: CommonCrawl
cat subfinder.txt crtsh_subs.txt | while read host; do curl -s "https://index.commoncrawl.org/CC-MAIN-2023-50-index?url=*.$host/*&output=json" | jq -r '.url'; done | sort -u > commoncrawl_urls.txt
```

---

# 2) Enumeración DNS

```bash
dnsenum --enum ejemplo.test --threads 20 --retry 3 -v -o dnsenum_out.txt
dnsrecon -d ejemplo.test -t std -D /usr/share/seclists/Discovery/DNS/big.txt -a -v > dnsrecon_out.txt
amass enum -passive -d ejemplo.test -v -o amass_passive.txt
amass enum -active -brute -d ejemplo.test -v -o amass_active.txt
```

---

# 3) Resolución y filtrado de subdominios

```bash
cat subfinder.txt crtsh_subs.txt dnsenum_out.txt dnsrecon_out.txt amass_passive.txt amass_active.txt | sort -u > all_subs_raw.txt

shuffledns -d ejemplo.test -w /usr/share/seclists/Discovery/DNS/subdomains-top1million.txt -r resolvers.txt -v -o shuffledns_resolved.txt
massdns -r resolvers.txt -t A -v -o massdns_out.txt /usr/share/seclists/Discovery/DNS/subdomains-top1million.txt

cat shuffledns_resolved.txt massdns_out.txt | sort -u > all_subs_resolved.txt
cat all_subs_resolved.txt | dnsx -a -aaaa -cname -resp -v -o dnsx_resolved.txt
```

---

# 4) Probing / fingerprinting

```bash
cat dnsx_resolved.txt | sed 's/:.*$//' | sort -u | httpx -threads 200 -status-code -title -content-type -tech-detect -v -o httpx_hosts.txt
```

---

# 5) Recolección histórica de URLs

```bash
cat all_subs_resolved.txt | gau > gau_all_urls.txt
cat all_subs_resolved.txt | waybackurls > wayback_urls.txt
cat gau_all_urls.txt wayback_urls.txt commoncrawl_urls.txt | sort -u > historical_urls_raw.txt
grep -E '\?|=' historical_urls_raw.txt | sort -u > historical_urls_with_params.txt
```

---

# 6) Crawling y extracción JS/endpoints

```bash
cat httpx_hosts.txt | awk '{print $1}' | sed 's|https\?://||' | while read host; do katana -u "https://$host" -d 4 -o katana_${host}.txt -v; done
cat katana_*.txt | sort -u > katana_combined.txt

python3 /opt/LinkFinder/linkfinder.py -i katana_combined.txt -o cli -d -v > linkfinder_out.txt
python3 ~/ParamSpider/paramspider.py -d ejemplo.test -o paramspider_out -l all_subs_raw.txt -v
```

---

# 7) JS / endpoints dinámicos

```bash
cat katana_combined.txt historical_urls_raw.txt | grep -E '\.js($|\?)' | sort -u > js_files.txt
mkdir -p js_dl
cat js_files.txt | xargs -n1 -P40 -I{} bash -c 'curl -L "{}" -v -o js_dl/$(echo "{}" | md5sum | cut -d" " -f1).js'
cat js_dl/*.js | grep -Eo 'https?://[A-Za-z0-9._:/?&=%-]+' | sed 's/\/$//' | sort -u > js_endpoints.txt
```

---

# 8) Validación de URLs en vivo

```bash
cat katana_combined.txt historical_urls_raw.txt js_endpoints.txt linkfinder_out.txt paramspider_out/* | sort -u > combined_urls_all.txt
cat combined_urls_all.txt | httpx -threads 200 -status-code -content-type -title -tech-detect -v -o validated_urls.txt
```

---

# 9) Fuzzing / directorios

```bash
feroxbuster -u https://sub.example.test -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt --depth 4 --threads 80 --timeout 25 -v -o ferox_sub_example.txt
ffuf -u 'https://sub.example.test/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 60 -mc 200,301,302 -v -o ffuf_dirs.json -of json
gobuster dir -u https://sub.example.test -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 60 -v -o gobuster_sub.txt
```

---

# 10) Parámetros / XSS / SQLi

```bash
ffuf -u 'https://sub.example.test/page.php?param=FUZZ' -w /usr/share/seclists/Fuzzing/Parameters/params.txt -t 60 -mc 200,302 -v -o ffuf_params.json -of json
cat validated_urls.txt | dalfox file - --skip-bav -v -o dalfox_results.txt
wfuzz -c -w /usr/share/seclists/Fuzzing/SQLi/SQLi.txt --hc 404 "https://sub.example.test/page.php?id=FUZZ"
```

---

# 11) Detección por templates / takeovers

```bash
cat validated_urls.txt | nuclei -t /path/to/nuclei-templates/ -c 100 -v -o nuclei_results_verbose.txt
cat all_subs_raw.txt | dnsx -a -v -o tmp_hosts_ips.txt
cat tmp_hosts_ips.txt | httpx -v -o hosts_up_for_takeover.txt
cat hosts_up_for_takeover.txt | nuclei -t vulnerabilities/takeovers -v -o takeover_results.txt
```

---

# 12) Subdomain takeover / CNAME checks

```bash
cat all_subs_raw.txt | subjack -w - -t 50 -v -ssl -o subjack_out_verbose.txt
cat all_subs_raw.txt | dnsx -cname -v -o cname_results.txt
```

---

# 13) Puertos / servicios

```bash
masscan target_ip -p1-65535 --rate 2500 -oG masscan_grep.txt
nmap -Pn -sV -sC -p- -T4 -v -oA nmap_full_scan target_ip_or_hostname
```

---

# 14) Screenshots / visual recon

```bash
cat validated_urls.txt | cut -d' ' -f1 | aquatone -out aquatone_out -v
cat validated_urls.txt | cut -d' ' -f1 | gowitness file - -o gowitness_out --debug
```

---

# 15) Secrets / repos / code scanning

```bash
gitleaks detect --source . --report-path gitleaks_report.json -v
trufflehog filesystem --json . > trufflehog_report.json
python3 /opt/SecretFinder/SecretFinder.py -i js_dl/ -o cli -v > secretfinder_out.txt
cat validated_urls.txt | gf xss > gf_xss.txt
cat validated_urls.txt | gf sqli > gf_sqli.txt
cat validated_urls.txt | gf lfi > gf_lfi.txt
