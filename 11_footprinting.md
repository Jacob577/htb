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


# NFS
Network File System
`RPC- Remote Procedure Call`

 Default conf: `/etc/exports`

    rw 	Read and write permissions.
    ro 	Read only permissions.
    sync 	Synchronous data transfer. (A bit slower)
    async 	Asynchronous data transfer. (A bit faster)
    secure 	Ports above 1024 will not be used.
    insecure 	Ports above 1024 will be used.
    no_subtree_check 	This option disables the checking of subdirectory trees.
    root_squash 	Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents root from accessing files on an NFS mount.

mount sample: 
```bash
echo '/mnt/nfs  10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports
systemctl restart nfs-kernel-server
exportfs
```

<b>Dangerous settings</b>

    rw 	Read and write permissions.
    insecure 	Ports above 1024 will be used.
    nohide 	If another file system was mounted below an exported directory, this directory is exported by its own exports entry.
    no_root_squash 	All files created by root are kept with the UID/GID 0.


## Footprinting NFS
Ports: `111`, and `2049`
```bash
sudo nmap 10.129.14.128 -p111,2049 -sV -sC
```

The rpc NSE script retrieves a list of all currently running RPC services, their names and descriptions, and ports they use.
```bash
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
```

<b>Show available NFS Shares:</b>
```bahs
showmount -e 10.129.14.128

# Mounting NFS shares
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS
tree .

# List contents with Usernames & Group names
ls -l mnt/nfs/

# List Contents with UIDs & GUIDs
ls -n mnt/nfs/
```

## DNS

<b>Types of DNS servers</b>

    DNS root server
    Authoritative name server
    Non-authoritative name server
    Caching server
    Forwarding server
    Resolver

![](./images/DNS_image.png)

    A 	Returns an IPv4 address of the requested domain as a result.
    AAAA 	Returns an IPv6 address of the requested domain.
    MX 	Returns the responsible mail servers as a result.
    NS 	Returns the DNS servers (nameservers) of the domain.
    TXT 	This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam.
    CNAME 	This record serves as an alias. If the domain www.hackthebox.eu should point to the same IP, and we create an A record for one and a CNAME record for the other.
    PTR 	The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.
    SOA 	Provides information about the corresponding DNS zone and email address of the administrative contact.

```bash
# Get IP
dig soa www.inlanefreight.com
```

### Default Configuration for DNS
Often used
[bind 9](https://www.isc.org/bind/)

    local DNS configuration files
    zone files
    reverse name resolution files

Distinction between global opetions and zone options
Global options are general and affect all zones. A zone option only affects the zone to which it is assigned. Options not listed in named.conf have default values. If an option is both global and zone-specific, the the zone option takes precedence
`cat /etc/bind/named.conf.local`

<b>Zone files</b>
`cat /etc/bind/db.domain.com`

FQDN must have a reverse lookup file. In this file, the computer name (FQDN) is assigned to the last octet of an IP address, which corresponds to the respective host, using a PTR record. The PTR records are responsible for the reverse translation of IP addresses into names. 
`cat /etc/bind/db.10.129.14`

<b>Dangerous settings</b>

    allow-query 	Defines which hosts are allowed to send requests to the DNS server.
    allow-recursion 	Defines which hosts are allowed to send recursive requests to the DNS server.
    allow-transfer 	Defines which hosts are allowed to receive zone transfers from the DNS server.
    zone-statistics 	Collects statistical data of zones.

### Footprinting a service:
The footprinting at DNS servers is done as a result of the requests we send. So, first of all, the DNS server can be queried as to which other name servers are known. We do this using the NS record and the specification of the DNS server we want to query using the @ character. This is because if there are other DNS servers, we can also use them and query the records. However, other DNS servers may be configured differently and, in addition, may be permanent for other zones.
`dig ns inlanefreight.htb @10.129.14.128`

<b>DIG - Version Query</b>
`dig CH TXT version.bind 10.129.120.85`
Dig any:
`dig any inlanefreight.htb @10.129.14.128`

<b>DIG AXFR Zone Transfer</b>
```bash
dig axfr inlanefreight.htb @10.129.14.128

# Internal
dig axfr internal.inlanefreight.htb @10.129.14.128
```

<b>Brute force list: [brute force list](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-5000.txt)</b>

```bash
for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

Otherwise, we can use DNSenum
```bash
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

[sub domain list](https://github.com/danielmiessler/SecLists)

Command for finding the last FQDN:
```bash
dnsenum --dnsserver 10.129.95.44 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/fierce-hostlist.txt dev.inlanefreight.htb
```
We are using another zone because not always the way forward is through the normal zone? 

## SMTP
Simple Mail Transfer Protocol
Default port for SMTP is `25` but also `587`, encrypted, it can be `465`

    Client (MUA) 	➞ 	Submission Agent (MSA) 	➞ 	Open Relay (MTA) 	➞ 	Mail Delivery Agent (MDA) 	➞ 	Mailbox (POP3/IMAP)

Users are not authenticated when connection is active

<b>Default config</b>
```bash
cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"
```

    AUTH PLAIN 	AUTH is a service extension used to authenticate the client.
    HELO 	The client logs in with its computer name and thus starts the session.
    MAIL FROM 	The client names the email sender.
    RCPT TO 	The client names the email recipient.
    DATA 	The client initiates the transmission of the email.
    RSET 	The client aborts the initiated transmission but keeps the connection between client and server.
    VRFY 	The client checks if a mailbox is available for message transfer.
    EXPN 	The client also checks if a mailbox is available for messaging with this command.
    NOOP 	The client requests a response from the server to prevent disconnection due to time-out.
    QUIT 	The client terminates the session.

### To interact with SMTP, use telnet
```bash
telnet 10.129.14.128 25
```

[SMTP error codes](https://serversmtp.com/smtp-error/)

<b>Dangerous settings</b>
`mynetworks = 0.0.0.0/0`

### Footprint SMTP
The default Nmap scripts include smtp-commands, which uses the EHLO command to list all possible commands that can be executed on the target SMTP server.
```bash
sudo nmap 10.129.14.128 -sC -sV -p25
```

We can also use `Open Relay`, it will run 16 different scripts
```bash
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
```

# IMAP/POP3
Internet Message Access Protocol (IMAP)
Post Office Protocol (POp3)

<b>To configure:</b>
Install `dovecot-imapd` & `dovecot-pop3d`

<b>IMAP Commands</b>
```bash
1 LOGIN username password 	User's login.
1 LIST "" * 	Lists all directories.
1 CREATE "INBOX" 	Creates a mailbox with a specified name.
1 DELETE "INBOX" 	Deletes a mailbox.
1 RENAME "ToRead" "Important" 	Renames a mailbox.
1 LSUB "" * 	Returns a subset of names from the set of names that the User has declared as being active or subscribed.
1 SELECT INBOX 	Selects a mailbox so that messages in the mailbox can be accessed.
1 UNSELECT INBOX 	Exits the selected mailbox.
1 FETCH <ID> all 	Retrieves data associated with a message in the mailbox.
1 CLOSE 	Removes all messages with the Deleted flag set.
1 LOGOUT 	Closes the connection with the IMAP server.
```

<b>POP3 commands:</b>
```bash
USER username 	Identifies the user.
PASS password 	Authentication of the user using its password.
STAT 	Requests the number of saved emails from the server.
LIST 	Requests from the server the number and size of all emails.
RETR id 	Requests the server to deliver the requested email by ID.
DELE id 	Requests the server to delete the requested email by ID.
CAPA 	Requests the server to display the server capabilities.
RSET 	Requests the server to reset the transmitted information.
QUIT 	Closes the connection with the POP3 server.
```

<b>Dangerous settings:</b>
Configuration options that were improperly configured could allow us to obtain more information, such as debugging the executed commands on the service or logging in as anonymous, similar to the FTP service. Most companies use third-party email providers such as Goocle etc. However, some companies use their own mail servers for many different reasons. One of these reasons is to maintain the privacy that they want to keep in their own hands. Many configuration mistakes can be made by administrators, which in the wors cases will allow us to read all the emails sent and received, which may even contain confidential or sensitive information. Some of these configuration options include: 
```bash
auth_debug 	Enables all authentication debug logging.
auth_debug_passwords 	This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged.
auth_verbose 	Logs unsuccessful authentication attempts and their reasons.
auth_verbose_passwords 	Passwords used for authentication are logged and can also be truncated.
auth_anonymous_username 	This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism.
```

## Footprinting the Service:
default ports: `110`, `143`, `993`, `995`
```bash
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```

<b>cURL</b>
```bash
curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd

# May add -v for verbose
```

<b>Interact with IMAP & POP3 over ssl:</b>
```bash
openssl s_client -connect 10.129.14.128:pop3s

openssl s_client -connect 10.129.14.128:imaps
```

To fetch a message in IMAP: `tag FETCH 1 RFC822`

IMAP commands are difficult af....


# SNMP
Simple Network Management Protocol, was created to monitor network devices. Can also change settings remotely. 

<b>Port `162`</b>

### MIB - Management Information Base ensure SNMP access works across manufactrurers and with different client-server combinations. 

SNMPv1 Do not support authentication or encryption
SNMPv2 (v2c), c - community string
SNMPv3 - security has been increased with authentication and encrypted transmission (via pre-shared key). 

<b>SNMP Daemon Config</b>
```bash
cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'
```

<b>Dangerous settings:</b>

    rwuser noauth 	Provides access to the full OID tree without authentication.
    rwcommunity <community string> <IPv4 address> 	Provides access to the full OID tree regardless of where the requests were sent from.
    rwcommunity6 <community string> <IPv6 address> 	Same access as with rwcommunity with the difference of using IPv6.

### Footprinting the service:
`snmpwalk`, `onesixtyone`, and `braa`.
```bash
# snmpwalk
snmpwalk -v2c -c public 10.129.14.128

# OneSixtyOne
sudo apt install onesixtyone
onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt 10.129.14.1

# Braa
sudo apt install braa
braa <community string>@<IP>:.1.3.6.*   # Syntax
braa public@10.129.14.128:.1.3.6.*
```

Often, when certain community strings are bound to specific IP addresses, they are named with the hostname of the host, and sometimes even symbols are added to these names to make them more challenging to identify. However, if we imagine an extensive network with over 100 different servers managed using SNMP, the labels, in that case, will have some pattern to them. Therefore, we can use different rules to guess them.

We can use [crunch](https://secf00tprint.github.io/blog/passwords/crunch/advanced/en) as a wordlist and crack passwords with [HashCat](https://academy.hackthebox.com/course/preview/cracking-passwords-with-hashcat). 


# MySQL
works according to the client-server principle and consists of a MySQL server and a MySQL client

`MariaDB` is often connected to MySQL

Default Configuration: `database administrator`, 
<b>Default configuration:</b>
```bash
sudo apt install mysql-server -y
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'
```

<b>Dangerous settings:</b>

    user 	Sets which user the MySQL service will run as.
    password 	Sets the password for the MySQL user.
    admin_address 	The IP address on which to listen for TCP/IP connections on the administrative network interface.
    debug 	This variable indicates the current debugging settings
    sql_warnings 	This variable controls whether single-row INSERT statements produce an information string if warnings occur.
    secure_file_priv 	This variable is used to limit the effect of data import and export operations.



### Footprinting the service
```bash
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```

Always on Port `3306`

<b>Interact with service</b>
```bash
mysql -u root -h 10.129.14.132

mysql -u root -pP4SSw0rd -h 10.129.14.128
```

<b>Common commands</b>
    mysql -u <user> -p<password> -h <IP address> 	Connect to the MySQL server. There should not be a space between the '-p' flag, and the password.
    show databases; 	Show all databases.
    use <database>; 	Select one of the existing databases.
    show tables; 	Show all available tables in the selected database.
    show columns from <table>; 	Show all columns in the selected database.
    select * from <table>; 	Show everything in the desired table.
    select * from <table> where <column> = "<string>";


# MSSQL
Microsoft SQL
`SSMS` is used to analyze MSSQL

<b>MSSQL Clients</b>
```bash
locate mssqlclient
```

<b>Defaults</b>

    Default System Database 	Description
    master 	Tracks all system information for an SQL server instance
    model 	Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database
    msdb 	The SQL Server Agent uses this database to schedule jobs & alerts
    tempdb 	Stores temporary objects
    resource 	Read-only database containing system objects included with SQL server

Encryption is not forced by default

<b>Dangerous settings (some of them)</b>


    MSSQL clients not using encryption to connect to the MSSQL server

    The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates

    The use of named pipes

    Weak & default sa credentials. Admins may forget to disable this account

[named pipes](https://learn.microsoft.com/en-us/sql/tools/configuration-manager/named-pipes-properties?view=sql-server-ver15)

### Footprinting service
`port 1433`

The scripted NMAP scan below provides us with helpful information. We can see the hostname, database instance name, software version of MSSQL and named pipes are enabled. We will benefit from adding these discoveries to our notes.

<b>Great nmap scan</b>
```bash
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248

# Readable format:
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,
ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,
ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,
mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

We can also use mssql_ping from metasploit `auxiliary/scanner/mssql/mssql_ping`


<b>Connecting to `mssql`</b>
```bash
python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
```

