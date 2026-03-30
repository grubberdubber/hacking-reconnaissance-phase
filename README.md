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

  for d in $(cat subfindercl.txt); do 
    echo -e "\n[*] Analizando: $d" | tee -a dnsrecon.txt
    # Agregamos -z (zonewalk) y -s (SPF lookup) a los que ya teníamos
    dnsrecon -d "$d" -t std,axfr,rvl,zonewalk -s --threads 50 --disable_check_bindversion -v | grep -vE "Could not resolve|Error:" | tee -a dnsrecon.txt
done
  -o feroxbuster.txt

