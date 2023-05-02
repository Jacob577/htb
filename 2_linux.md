How do you execute a command as another user?
`su -c [command] [other_user]`

Create a timer:
```bash
zirap98@htb[/htb]$ sudo mkdir /etc/systemd/system/mytimer.timer.d
zirap98@htb[/htb]$ sudo vim /etc/systemd/system/mytimer.timer

Code: txt

[Unit]
Description=My Timer

[Timer]
OnBootSec=3min
OnUnitActiveSec=1hour

[Install]
WantedBy=timers.target

```

Assign IP Address to an Interface
Assign IP Address to an Interface

`zirap98@htb[/htb]$ sudo ifconfig eth0 192.168.1.2`

To set the netmask for a network interface, we can run the following command with the name of the interface and the netmask:
Assign a Netmask to an Interface
Assign a Netmask to an Interface

`zirap98@htb[/htb]$ sudo ifconfig eth0 netmask 255.255.255.0`

Assign the Route to an Interface
Assign the Route to an Interface

`zirap98@htb[/htb]$ sudo route add default gw 192.168.1.1 eth0`


Cursor Movement

[CTRL] + A - Move the cursor to the beginning of the current line.

[CTRL] + E - Move the cursor to the end of the current line.

[CTRL] + [←] / [→] - Jump at the beginning of the current/previous word.

[ALT] + B / F - Jump backward/forward one word.
Erase The Current Line

[CTRL] + U - Erase everything from the current position of the cursor to the beginning of the line.

[Ctrl] + K - Erase everything from the current position of the cursor to the end of the line.

[Ctrl] + W - Erase the word preceding the cursor position.

Erase The Current Line

[CTRL] + U - Erase everything from the current position of the cursor to the beginning of the line.

[Ctrl] + K - Erase everything from the current position of the cursor to the end of the line.

[Ctrl] + W - Erase the word preceding the cursor position.
Paste Erased Contents

[Ctrl] + Y - Pastes the erased text or word.
Ends Task

[CTRL] + C - Ends the current task/process by sending the SIGINT signal. For example, this can be a scan that is running by a tool. If we are watching the scan, we can stop it / kill this process by using this shortcut. While not configured and developed by the tool we are using. The process will be killed without asking us for confirmation.
End-of-File (EOF)

[CTRL] + D - Close STDIN pipe that is also known as End-of-File (EOF) or End-of-Transmission.
Clear Terminal

[CTRL] + L - Clears the terminal. An alternative to this shortcut is the clear command you can type to clear our terminal.
Background a Process

[CTRL] + Z - Suspend the current process by sending the SIGTSTP signal.
Search Through Command History

[CTRL] + R - Search through command history for commands we typed previously that match our search patterns.

[↑] / [↓] - Go to the previous/next command in the command history.
Switch Between Applications

[ALT] + [TAB] - Switch between opened applications.
Zoom

[CTRL] + [+] - Zoom in.

[CTRL] + [-] - Zoom out.