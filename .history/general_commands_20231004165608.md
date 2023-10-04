# This is a list of general commands that can be useful

Initial scan:
`nmap -sV -sC -(nP) <IP> --script banner.nse`
General ports:
`nmap -sV -T4 -p- 10.10.10.5`

In msfconsole:
if we have a shell, search `exploit suggest` or `search local exploit suggester`

General:
- Look around. Files on desktop. Take a step back. 
- look for familiar words, `aspnet`, `httpd` etc.