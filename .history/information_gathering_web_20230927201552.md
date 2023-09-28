# Information gatering web edition

We want to get to know as much as possible about the host, virtual host, the technologies used etc.

`whois` can be considered white pagees for domain names. `TCP P43`

common commands are `nslookup` & `dig`

We can query specifically for PTR Records:
`nslookup -query=PTR 31.13.92.36`
`dig -x 31.13.92.36 @1.1.1.1`

### Any target:
`nslookup -query=ANY $TARGET`
`dig any google.com @8.8.8.8`

ANY is however somewhat depricated and may not produce any response

```bash
# TXT
nslookup -query=TXT $TARGET
dig txt facebook.com @1.1.1.1

# MX
nslookup -query=MX $TARGET
dig mx facebook.com @1.1.1.1
```

If the host has some sort of block, we can combine `whois` and `nslookup`:
```bash
export TARGET="facebook.com"
nslookup $TARGET

whois 157.240.199.35
```
We can get subdomains from PTR record:
`nslookup -query=PTR 173.0.87.51`

# Passive subdomain Enumeration
### VirusTotal
VirusTotal maintains its DNS replication service, which is developed by preserving DNS resolutions made when users visit URLs given by them. To receive information about a domain, type the domain name into the search bar and click on the "Relations" tab.

### Certificates
Another interesting source of information we can use to extract subdomains is SSL/TLS certificates. The main reason is Certificate Transpareency CT, a project that requires every SSL/TLS certificate issued by a Certificate Authority CA to be published in a publicly accessible log.

    https://censys.io

    https://crt.sh

### On Command line:
```bash
export TARGET="facebook.com"
curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt"

head -n20 facebook.com_crt.sh.txt
```

    curl -s 	Issue the request with minimal output.
    https://crt.sh/?q=<DOMAIN>&output=json 	Ask for the json output.
    jq -r '.[]' "\(.name_value)\n\(.common_name)"' 	Process the json output and print certificate's name value and common name one per line.
    sort -u 	Sort alphabetically the output provided and removes duplicates.

```bash
export TARGET="facebook.com"
export PORT="443"
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u
```

### TheHarvester
Is a powerful tool that collects emails, names, subdomains, IP addresses and URLs from various public data sources for passive information gatering. For now: 

    Baidu 	Baidu search engine.
    Bufferoverun 	Uses data from Rapid7's Project Sonar - www.rapid7.com/research/project-sonar/
    Crtsh 	Comodo Certificate search.
    Hackertarget 	Online vulnerability scanners and network intelligence to help organizations.
    Otx 	AlienVault Open Threat Exchange - https://otx.alienvault.com
    Rapiddns 	DNS query tool, which makes querying subdomains or sites using the same IP easy.
    Sublist3r 	Fast subdomains enumeration tool for penetration testers
    Threatcrowd 	Open source threat intelligence.
    Threatminer 	Data mining for threat intelligence.
    Trello 	Search Trello boards (Uses Google search)
    Urlscan 	A sandbox for the web that is a URL and website scanner.
    Vhost 	Bing virtual hosts search.
    Virustotal 	Domain search.
    Zoomeye 	A Chinese version of Shodan.

<b>To automate it, we'll create a document called sources.txt</b>
```bash
baidu
bufferoverun
crtsh
hackertarget
otx
projecdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye

# Then run:
export TARGET="facebook.com"
cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done

# Then extract all subdomains:
cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"

# Now merge all the passive reconnisance files via:
cat facebook.com_*.txt | sort -u > facebook.com_subdomains_passive.txt
cat facebook.com_subdomains_passive.txt | wc -l
```

Many more ways at: (https://academy.hackthebox.com/course/preview/osint-corporate-recon)[OSINT: Corporate Recon]

# Passive Infrastructure Identification
Netcraft can offer us information about the servers without even interacting with them, and this is something valuable from a passive information gathering point of view. We can use the service by visiting https://sitereport.netcraft.com and entering the target domain.

    Background 	General information about the domain, including the date it was first seen by Netcraft crawlers.
    Network 	Information about the netblock owner, hosting company, nameservers, etc.
    Hosting history 	Latest IPs used, webserver, and target OS.

We can access older versions of websites at:
(https://en.wikipedia.org/wiki/Internet_Archive)[Internet Archive]
&
(http://web.archive.org/)[Wayback Machine]

and (https://github.com/tomnomnom/waybackurls)[waybackurls]

Which is also available as a cli tool:
```bash
go install github.com/tomnomnom/waybackurls@latest
```
To get a list of crawled URLs from a domain with the date it was obtained, we can add the -dates switch to our command as follows:

```bash
waybackurls -dates https://facebook.com > waybackurls.txt
cat waybackurls.txt
```

If we want to access a specific resource, we need to place the URL in the search menu and navigate to the date when the snapshot was created. As stated previously, Wayback Machine can be a handy tool and should not be overlooked. It can very likely lead to us discovering forgotten assets, pages, etc., which can lead to discovering a flaw.