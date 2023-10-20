# This is a list of general commands that can be useful

Initial scan:
`nmap -sV -sC -(nP) <IP> --script banner.nse`
General ports:
`nmap -sV -T4 -p- 10.10.10.5`

`sudo nmap -sV -sC -Pn -p 2121 10.129.203.6`

In msfconsole:
if we have a shell, search `exploit suggest` or `search local exploit suggester`

General:
- Look around. Files on desktop. Take a step back. 
- look for familiar words, `aspnet`, `httpd` etc.

Enumerating cifs:
`smbmap -H 10.129.202.221 -u jason -p C4mNKjAtL2dydsYa6`

mounting cifs:
`sudo mount -t cifs -o username="jason" //10.129.202.221/SHAREDRIVE smb_target`
`net use d: \\10.10.14.174\share /user:test test`

Check if there is an SQL database running´

Also try reusing id_rsa keys, people reuse everything

to brute force rdp: `crowbar -b rdp -s xx.xxx.xxx.xxx/32 -u johanna -C <full-mutated-password-list>`



