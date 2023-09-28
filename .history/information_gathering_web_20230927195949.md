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

```