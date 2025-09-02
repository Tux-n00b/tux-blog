#  Empire-Breakout #
This is a write-up on the vulnerable machine **Empire-Breakout**

Enumeration
---
So we begin with fist hosting both machines in the same network in VMware machine. We can use these commands to discover the `target IP` (of the Empire vulnbox);
> + **netdiscover -i eth0**  - is used for **network reconnaissance** and host discovery on a local network. 
> 
> + **arp-scan -l** - is a command-line network scanning tool that uses the **ARP (Address Resolution Protocol)** to *discover active hosts on a local network*.

Here were my findings;

![](/post-images/Empire-Breakout/netdiscover.png)

![Nmap](/post-images/Empire-Breakout/nmap.png)

We get to access the ports ;
> + 80 - Apache2 Debian Default Page: It works
> + 139 - Samba smbd 4
> + 445 - Samba smbd 4
> + 10000 - http-server-header: MiniServ/1.981
> + 20000 - http-server-header: MiniServ/1.830

I hosted the IP using port **80** and stumbled upon a `Apache Website`
Since ports `10000 & 20000` are mini servers so I tried hosting them too and they both had the same output but with different port numbers.

![portsites](/post-images/Empire-Breakout/80.png)

Viewed the page source code and found this just chilling down there.

```brainfuck
<!--
don't worry no one will get here, it's safe to share with you my access. Its encrypted :)

++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>++++++++++++++++.++++.>>+++++++++++++++++.----.<++++++++++.-----------.>-----------.++++.<<+.>-.--------.++++++++++++++++++++.<------------.>>---------.<<++++++.++++++.


-->

```
so I fired up [dcode](https://www.dcode.fr/) and submitted my findings and fired up the decrypter and found the encoded message to be `.2uqPEfj3D<P'a-3`. Which really seems like a very strong password someone might say.

I then checked the other ports and found logins, and since we are running **Samba smbd 4** on both ports and we have login pages, I first tried to perform a samba access using;
> ***smbclient//192.168.168.129/***

That was all for nothing.

I decided to enmarate the *target IP* `192.168.168.129` using;

> ***enum4linux -a 192.168.168.129***

![enum](/post-images/Empire-Breakout/cyber.png)

We find a local user `cyber`, wonder if that would have been his password we found before. So I tested it out on the logins and found a dashboard (*login succesfull*).

![login](/post-images/Empire-Breakout/usermin.png)

At the bottom I spotted what looked like a `shell` icon so I clicked, and was refered to a shell with the user **cyber**

![webshell](/post-images/Empire-Breakout/webshell.png)

So I `cat` the file ***user.txt*** and found a flag
![flag1](/post-images/Empire-Breakout/flag1.png)

```
3mp!r3{You_Manage_To_Break_To_My_Secure_Access}
```


---
Privilage Escalation
---

As usual with these boxes, if its a privilage escalation there must be two flags so we found the first one with the user now we pull to the next.

So I travelled to the home `var` directory and found a `backups` folder, which had a hidden file `.old_pass.bak`. 

I tried to copy the file to my host machine since I couldn't read it with my target user, so I had some *ideas* to host a `python server` in my host machine and try and `wget` the file, still permission denied, I even tried using `curl`.

![](/post-images/Empire-Breakout/pythonserverdenied.png)

Since we saw `tar` file in the our `home/cyber/`

I thought that this might be a slightly *modified* version of tar. So I tried to archive the file `.old_pass.bak` and copy it to `/home/cyber/` since the tar tool couldn't work out side the directory.

>  ***./tar -cvf <New file name> /var/backups/.old_pass.bak***

With the file archived in the home directory, I was able to extract the file.

![pass](/post-images/Empire-Breakout/passwords.png)

we then go to the other port and open the other user who we assume to be the admin.

![](/post-images/Empire-Breakout/root%20dash.png)

We open the shell similar to the one we found at cyber and find out its the root shell. On the home folder we find another flag in the rOOt.txt file 

![](/post-images/Empire-Breakout/flag2.png)

```
3mp!r3{You_Manage_To_BreakOut_From_My_System_Congratulation}
```

Interesting vulnbox.

References
---

[Ra-Sec](https://ra2302.github.io/posts/Breakout/)  has a site with multiple writeups.

[Galihabraa](https://medium.com/@galihabraa/empire-breakout-vulnhub-walkthrough-ea32716662d0) in Meduim
