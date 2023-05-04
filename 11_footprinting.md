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

CIFS - Common Internet File System. (SAMBA)

    CIFS 	Windows NT 4.0 	Communication via NetBIOS interface
    SMB 1.0 	Windows 2000 	Direct connection via TCP
    SMB 2.0 	Windows Vista, Windows Server 2008 	Performance upgrades, improved message signing, caching feature
    SMB 2.1 	Windows 7, Windows Server 2008 R2 	Locking mechanisms
    SMB 3.0 	Windows 8, Windows Server 2012 	Multichannel connections, end-to-end encryption, remote storage access
    SMB 3.0.2 	Windows 8.1, Windows Server 2012 R2 	
    SMB 3.1.1 	Windows 10, Windows Server 2016 	Integrity checking, AES-128 encryption

<b>Default settings for smb</b>
```bash
cat /etc/samba/smb.conf | grep -v "#\|\;" 
```

<b>Worst is: Browsable = yes</b>

    browseable = yes 	Allow listing available shares in the current share?
    read only = no 	Forbid the creation and modification of files?
    writable = yes 	Allow users to create and modify files?
    guest ok = yes 	Allow connecting to the service without using a password?
    enable privileges = yes 	Honor privileges assigned to specific SID?
    create mask = 0777 	What permissions must be assigned to the newly created files?
    directory mask = 0777 	What permissions must be assigned to the newly created directories?
    logon script = script.sh 	What script needs to be executed on the user's login?
    magic script = script.sh 	Which script should be executed when the script gets closed?
    magic output = script.out 	Where the output of the magic script needs to be stored?

<b>Restart samba: `sudo systemctl restart smbd`</b>
<b>Connect to samba: `smbclient -N -L //<IP>`</b>
Output:
```bash
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        home            Disk      INFREIGHT Samba
        dev             Disk      DEVenv
        notes           Disk      CheckIT
        IPC$            IPC       IPC Service (DEVSM)
```

To connect to /notes: `smbclient //10.129.14.128/notes`

Status of samba: `smbstatus` (connected to samba share)

<b>Footprint Samba:</b>
```bash
sudo nmap 10.129.14.128 -sV -sC -p139,445
```

Other ways of getting information of a samba share: `rpcclient -U "" <IP>`

    srvinfo 	Server information.
    enumdomains 	Enumerate all domains that are deployed in the network.
    querydominfo 	Provides domain, server, and user information of deployed domains.
    netshareenumall 	Enumerates all available shares.
    netsharegetinfo <share> 	Provides information about a specific share.
    enumdomusers 	Enumerates all domain users.
    queryuser <RID> 	Provides information about a specific user.

Query groups: `querygroup 0x201`

### Brute forcing user RIDs
```bash
for i in $(seq 500 1100);do rpcclient -N -U "" <IP> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```
Alternatively, use `samrdump.py` from [samrdump](https://github.com/fortra/impacket/blob/master/examples/samrdump.py)

<b>Map out SMB</b>
```bash
smbmap -H 10.129.14.128

# or
crackmapexec smb 10.129.14.128 --shares -u '' -p ''
```

<b>Enum4Linux-ng</b>
```bash
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt

./enum4linux-ng.py 10.129.14.128 -A
```
