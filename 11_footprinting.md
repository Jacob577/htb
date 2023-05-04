# Footprinting

The goal is not to get at the system but to find all the ways to gain access to it

    What can we see?
    What reasons can we have for seeing it?
    What image does what we see create for us?
    What do we gain from it?
    How can we use it?
    What can we not see?
    What reasons can there be that we do not see?
    What image results for us from what we do not see?

## Three categories:
    Infrastructure-based enumeration 	Host-based enumeration 	OS-based enumeration

<b>Through:</b>

    1. Internet Presence 	Identification of internet presence and externally accessible infrastructure. 	Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures
    2. Gateway 	Identify the possible security measures to protect the company's external and internal infrastructure. 	Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare
    3. Accessible Services 	Identify accessible interfaces and services that are hosted externally or internally. 	Service Type, Functionality, Configuration, Port, Version, Interface
    4. Processes 	Identify the internal processes, sources, and destinations associated with the services. 	PID, Processed Data, Tasks, Source, Destination
    5. Privileges 	Identification of the internal permissions and privileges to the accessible services. 	Groups, Users, Permissions, Restrictions, Environment
    6. OS Setup 	Identification of the internal components and systems setup. 	OS Type, Patch Level, Network config, OS Environment, Configuration files, sensitive private files

### 1. Internet presence
The goal of this layer is to identify all possible target systems and interfaces that can be tested. 

### 2. Gateway
The goal is to understand what we are dealing with and what we have to watch out for.

### 3. Accessible Services
This layer aims to understand the reason and functionality of the target system and gain the necessary knowledge to communicate with it and exploit it for our purposes effectively.


### 4. Processes
The goal here is to understand these factors and identify the dependencies between them.

### 5. Privileges
It is crucial to identify these and understand what is and is not possible with these privileges.

### 6. OS Setup
The goal here is to see how the administrators manage the systems and what sensitive internal information we can glean from them.

One option to discover subdomains is to look at the `SSL` cert. 
[crt.sh](https://crt.sh/)

<b>sample of cert transparency</b>
```bash
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .

# Or filter by unique subdomains
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
```

### Company hosted Servers
```bash
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```

<b>Thereafter we can run it through Shodan - IP List</b>
```bash
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done

for i in $(cat ip-addresses.txt);do shodan host $i;done

# Display all available DNS records
dig any inlanefreight.com
```

<b>Company hosted Servers</b>
```bash
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```

### Cloud searches:
<b>AWS</b>
`intext: inurl:amazonaws.com`
<b>Azure</b>
`intext: inurl:blob.core.windows.net`

### Search online for information about the company to gather information about what technologies they use

Differentiate between active and passive FTP.

TFTP does not require user authentication

Default ftp conf can be found in `/etc/vsftpd`, `/etc/ftpusers`

#### Lookout for
    anonymous_enable=YES 	Allowing anonymous login?
    anon_upload_enable=YES 	Allowing anonymous to upload files?
    anon_mkdir_write_enable=YES 	Allowing anonymous to create new directories?
    no_anon_password=YES 	Do not ask anonymous for password?
    anon_root=/home/username/ftp 	Directory for anonymous.
    write_enable=YES 	Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE?


Recursive listing `ls -R`

```bash
# Download all available files:
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

```bash
# Upload a file
ftp> put testupload.txt 
```

### Nmap FTP Scripts
```bash
sudo nmap --script-updatedb

# All these NSE scipts are located in: /usr/share/nmap/scripts/, to find, use
find / -type f -name ftp* 2>/dev/null | grep scripts
```

### Service Interaction
```bash
nc -nv 10.129.14.136 21

telnet 10.129.14.136 21

# If FTP runs with TLS/SSL
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```