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

# Active Infrastructure Identification
How to get the http headers:
`curl -I "http://${TARGET}"`

There are also other characteristics to take into account while fingerprinting web servers in the response headers. These are:

X-Powered-By header: This header can tell us what the web app is using. We can see values like PHP, ASP.NET, JSP, etc.

Cookies: Cookies are another attractive value to look at as each technology by default has its cookies. Some of the default cookie values are:
        .NET: ASPSESSIONID<RANDOM>=<COOKIE_VALUE>
        PHP: PHPSESSID=<COOKIE_VALUE>
        JAVA: JSESSION=<COOKIE_VALUE>

`curl -I http://${TARGET}`

<b>We can also use WhatWeb</b>
`whatweb -a3 https://www.facebook.com -v`
Use -h for help to understand what it does

### Wappalyzer
We also want to install wappalyzer as a brower extantion. Same as `whatweb` but directly in the browser
(https://www.wappalyzer.com/)[Wappalyzer]


<b>WafW00f</b> is a web application firewall (WAF) fingerprinting tool that sends requests and analyses responses to determine if a security solution is in place. We can install it with the following command:
```bash
sudo apt install wafw00f -y

wafw00f -v https://www.tesla.com

[*] Checking https://www.tesla.com
[+] The site https://www.tesla.com is behind CacheWall (Varnish) WAF.
[~] Number of requests: 2


# Installing Aquatone
sudo apt install golang chromium-driver
go get github.com/michenriksen/aquatone
export PATH="$PATH":"$HOME/go/bin"
```
Now, it's time to use cat in our subdomain list and pipe the command to aquatone via:
```bash
cat facebook_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000
```

When it finishes, we will have a file called aquatone_report.html where we can see screenshots, technologies identified, server response headers, and HTML.

# Active Subdomain Enumeration 
### ZoneTransfeers
We can for one use ZoneTransfer to get further information about the website

[ZoneTransfer](https://hackertarget.com/zone-transfer/)

<b>1. identifying Nameservers:::</b>

```bash
# 1. identifying Nameservers
nslookup -type=NS zonetransfer.me

# 2. Testing for ANY and AXFR Zone Transfer
nslookup -type=any -query=AXFR zonetransfer.me nsztm1.digi.ninja
```
<b>Gobuster</b>
Common patterns (patterns.txt)
    lert-api-shv-{GOBUSTER}-sin6
    atlas-pp-shv-{GOBUSTER}-sin6

The next step will be to launch gobuster using the dns module, specifying the following options:

    dns: Launch the DNS module
    -q: Don't print the banner and other noise.
    -r: Use custom DNS server
    -d: A target domain name
    -p: Path to the patterns file
    -w: Path to the wordlist
    -o: Output file

<b>Gobuster - DNS</b>
```bash
export TARGET="facebook.com"
export NS="d.ns.facebook.com"
export WORDLIST="numbers.txt"
gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"
```

Keep in mind that if the DNS isn't available publicly, we might have to specify it manually:
```bash
dig any inlanefreight.htb @10.129.49.236

# And add hosts to /etc/hosts...
10.129.49.236

dig axfr inlanefreight.htb @10.129.49.236

inlanefreight.htb.
inlanefreight.htb.
admin.inlanefreight.htb.
ftp.admin.inlanefreight.htb.
careers.inlanefreight.htb.
dc1.inlanefreight.htb.
dc2.inlanefreight.htb.
internal.inlanefreight.htb.
admin.internal.inlanefreight.htb.
wsus.internal.inlanefreight.htb.
ir.inlanefreight.htb.
dev.ir.inlanefreight.htb.
ns.inlanefreight.htb.
resources.inlanefreight.htb.
securemessaging.inlanefreight.htb.
test1.inlanefreight.htb.
us.inlanefreight.htb.
cluster14.us.inlanefreight.htb.
messagecenter.us.inlanefreight.htb.
ww02.inlanefreight.htb.
www1.inlanefreight.htb.
inlanefreight.htb.

#!/bin/bash

# Your DNS server IP address
DNS_SERVER="10.129.49.236"

# Read the list of domains from output.txt as a single string
domains=$(cat modified_output.txt)

# Use a delimiter to split the string into an array of domains
IFS=$'\n' read -d '' -r -a domain_array <<< "$domains"

# Loop through the array and run dig commands for each domain
for domain in "${domain_array[@]}"; do
    # Remove leading and trailing spaces
    domain=$(echo "$domain" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    
    # Run the dig command for TXT records on the current domain
    dig txt "$domain" "@$DNS_SERVER"
done

# Can add +short to dig to remove empty responses

# Thereafter we can loop through the afrx domains and test if there are other zones. 
./txtrun.sh > zones.txt

nslookup -query=axfr internal.inlanefreight.htb 10.129.49.236

# To get all of the info: axfr, then 

# If there is an A-record and , there is a chance it 
```

# Virtual Hosts

A `vHost` serve for example both the web app and the mobile app at the same time

### IP-based Virtual Hosting

For this type, a host can have multiple network interfaces. Multiple IP addresses, or interface aliases, can be configured on each network interface of a host. The servers or virtual servers running on the host can bind to one or more IP addresses. This means that different servers can be addressed under different IP addresses on this host. From the client's point of view, the servers are independent of each other.

### Name-based Virtual Hosting

The distinction for which domain the service was requested is made at the application level. For example, several domain names, such as admin.inlanefreight.htb and backup.inlanefreight.htb, can refer to the same IP. Internally on the server, these are separated and distinguished using different folders. Using this example, on a Linux server, the vHost admin.inlanefreight.htb could point to the folder /var/www/admin. For backup.inlanefreight.htb the folder name would then be adapted and could look something like /var/www/backup.

During our subdomain discovering activities, we have seen some subdomains having the same IP address that can either be virtual hosts or, in some cases, different servers sitting behind a proxy.

Imagine we have identified a web server at 192.168.10.10 during an internal pentest, and it shows a default website using the following command. Are there any virtual hosts present?

Imagine we have identified a web server at 192.168.10.10 during an internal pentest, and it shows a default website using the following command. Are there any virtual hosts present?
```bash
curl -s http://192.168.10.10
```

Let's make a cURL request sending a domain previously identified during the information gathering in the HOST header. We can do that like so:

```bash
curl -s http://192.168.10.10 -H "Host: randomtarget.com"
```

We can iterate through a premade list
`/opt/useful/SecLists/Discovery/DNS/namelist.txt`

### vHost Fuzzing
```bash
at ./vhosts | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://192.168.10.10 -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done
```

Accessing ou new found subdomains:
`curl -s http://192.168.10.10 -H "Host: dev-admin.randomtarget.com"`

### Automate Virtual Host Discovery
`ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612`

    -w: Path to our wordlist
    -u: URL we want to fuzz
    -H "HOST: FUZZ.randomtarget.com": This is the HOST Header, and the word FUZZ will be used as the fuzzing point.
    -fs 612: Filter responses with a size of 612, default response size in this case.
to use `fuff`
```bash
ffuf -w /opt/useful/SecLists/Discovery/DNS/namelist.txt  -H "Host: FUZZ.inlanefreight.htb" -u http://10.129.151.226 -mr "FLAG No. 1" -fs 10918 -mc 200

# Here we get loads of suggestions which we:
url -s http://10.129.151.226 -H "Host: <word>.inlanefreight.htb" 

# e.g.,
curl -s http://10.129.151.226 -H "Host: app.inlanefreight.htb"
```

# Find hidden files
We can use fuff to find hidden files:
```bash
ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
```

    -recursion: Activates the recursive scan.
    -recursion-depth: Specifies the maximum depth to scan.
    -u: Our target URL, and FUZZ will be the injection point.
    -w: Path to our wordlist.

We can create a folder `folders.txt`
containing:
```bash
wp-admin
wp-content
wp-includes
```
`cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10`

The next step will be to combine everything in ffuf to see if we can find some juicy information. For this, we will use the following parameters in ffuf:

    -w: We separate the wordlists by coma and add an alias to them to inject them as fuzzing points later
    -u: Our target URL with the fuzzing points.

`ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://192.168.10.10/FOLDERS/WORDLISTEXTENSIONS`

`curl http://192.168.10.10/wp-content/secret~`

# Knowledge check:
 What is the registrar IANA ID number for the githubapp.com domain?
 ```bash
 whois  githubapp.com | grep -ni IANA
 ```

 What is the last mailserver returned when querying the MX records for githubapp.com
 `dig mx githubapp.com`

 Perform active infrastructure identification against the host https://i.imgur.com. What server name is returned for the host? 
 `whatweb -a3 https://i.imgur.com -v`

 Perform subdomain enumeration against the target githubapp.com. Which subdomain has the word 'triage' in the name? 
 Check (crt.sh)[https://crt.sh/?q=githubapp.com]