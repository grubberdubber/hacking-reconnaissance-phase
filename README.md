fase de enumeracion web:
Wappalyzer

whatweb

masscan

masscan -p1-65535 10.10.10.1 --rate=1000

theHarvester

echo "[]" > theHarvester.txt; for d in $(cat subfinder.txt); do theHarvester -d $d -l 500 -b crtsh,duckduckgo,hackertarget,rapiddns,subdomaincenter,yahoo -q -f "temp"; if [ -f temp.json ]; then jq ". + [$(cat temp.json)]" theHarvester.txt > final.json && mv final.json theHarvester.txt; rm temp.json temp.xml; fi; done

https://shodan.io/

https://search.censys.io/

maltego

spiderfoot

FOCA

subfinder

subfinder -d DOMAIN.com -o subfinder.txt

katana

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

feroxbuster

feroxbuster -u https://cgi-lib.berkeley.edu/ \           
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt \
  -t 100 \
  -x php,html,js,txt,conf,bak,old,zip,sql,env \
  -C 404 \
  -r \
  --depth 3 \
  --no-state \
  --smart \
  --thorough \
  --collect-backups \
  --collect-words \
  --collect-extensions \
  -k \
  -A \

  dnsrecon

while IFS= read -r d; do d=$(echo "$d" | tr -d '\r'); echo "[*] Analizando: $d" | tee -a dnsrecon.txt; dnsrecon -d "$d" -t std,axfr,zonewalk,snoop,rvl -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -s --threads 50 --disable_check_bindversion -v 2>&1 | tee -a dnsrecon.txt; done < subfinder.txt

post explotacion
comando anti idle en una shell
while true; do echo -n " "; sleep 60; done &
