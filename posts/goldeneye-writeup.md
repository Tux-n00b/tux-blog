---
title: "A walkthrough of Golden Eye vulnerable machine"
date: "2025-04-08"
tags: ["Pentesting","Vulnhub"]
---

# Golden-Eye Writeup

I did simple enumeration to identify the vuln machine.
So I first did some enumeration to identify our vulnerable machine. Using `arp-scan -l`

![Enumaration](/post-images/Golden-Eye/01Enum.png)

I found the machine's IP address and started a nmap scan to identify open ports we take a next step to enumerate 
once more by also checking for hidden directories in the machine by performing a `dirb`

![Enumaration](/post-images/Golden-Eye/02Enum.png)

`Nmap  -A -p- <IP>` -p- :scans all available ports since without it we don’t get the pop3 ports (55007,55006)

![Enumaration](/post-images/Golden-Eye/Enum0.png)

**NOTE :**<mark> This will be of use later on in the trial so we went ahead and did some research 
on pop3 and found its documentation and did some perusing and found some 
common commands. </mark>

![pop3-doc](/post-images/Golden-Eye/pop3%20doc.png)

Did some googling on POP3, and found that it has a command called `STAT` which returns the number of messages in the mailbox and the size of the mailbox. We can use this to our advantage to find the number of messages in the mailbox and the size of the mailbox.

So I opened the vulnrable machine IP on the browser to host the site.

![servenya](/post-images/Golden-Eye/01site.png)

Checking the site for more information I checked through the DevTools and then viewed the page's source code and I stumbled upon a link `teminal.js` in the source
code 

![teminal](/post-images/Golden-Eye/terminal.js.png)

Following on the link it took me to another source code with some vital information; 
I also found out that there was another user called Natalya who is said to be able to see 
Boris’ password.  
Based on this we have two users who we can enumerate and find out more about them.

![01terminal](/post-images/Golden-Eye/01terminal.js.png)

So I then took the encoded password and decoded it in [Cyberchef](https://gchq.github.io/CyberChef/) to get the password of the user Boris.

![boris](/post-images/Golden-Eye/Boris.png)

I then accessed the /sev-home/ as instructed by http://172.168.48.132 and input Boris’ 
logins; 

![log](/post-images/Golden-Eye/log.png)

There was nothing much but it was hinted out that there was use of a non-default port 
pop3 which we had found in our enumeration. 
From the documentation we understood that we could communicate though the pop3 port 
so we had to netcat the IP through the pop3 ports and it worked we got a pop3 terminal of 
some sorts but we couldn’t get anything so we deviced a python script; 

***Its commands were to run hydra on the set IP, set port, set username, and protocol (just for certainty so as it doesn’t scour through all protocols)***

Here is the Python script;

```

import subprocess 
import uuid 
# Fixed wordlist path 
WORDLIST_PATH = "/usr/share/wordlists/fasttrack.txt" 
# Prompt the user for inputs (allowing copy-paste) 
print("You can copy and paste the following inputs:") 
username = input("Enter the username: ") 
ip_address = input("Enter the IP address: ") 
port = input("Enter the port: ") 
protocol = input("Enter the protocol (e.g., pop3, ssh, ftp): ") 
# Construct the Hydra command 
hydra_command = [ 
"hydra", 
    "-l", username, 
    "-P", WORDLIST_PATH, 
    "-f", 
    ip_address, 
    "-s", port, 
    protocol 
] 
 
# Execute the Hydra command and capture output 
try: 
    print("\nRunning Hydra... Please wait.") 
    result = subprocess.run(hydra_command, capture_output=True, text=True, 
check=True) 
     
    # Extract the successful login credentials from Hydra's output 
    output = result.stdout 
    credentials = [line for line in output.splitlines() if "login:" in line and "password:" in 
line] 
     
    if credentials: 
        print("\nCredentials found:") 
        for cred in credentials: 
            print(cred) 
         
        # Save credentials to a file with a randomized name 
        random_filename = f"credentials_{uuid.uuid4().hex}.txt" 
        with open(random_filename, "w") as file: 
            file.write("\n".join(credentials)) 
        print(f"\nCredentials saved to: {random_filename}") 
    else: 
        print("\nNo credentials found.") 
except subprocess.CalledProcessError as e: 
    print(f"An error occurred while executing Hydra: {e.stderr}") 
except FileNotFoundError: 
    print("Hydra is not installed or not found in your system's PATH.") 

```

After running the brute.py code on both Boris and Natalya(who was mentioned in the 
terminal.js source code we found) we found the following login credentials; 
 
We then got the following on Boris and so we ran the code again on Natalya and also 
found some login credentials which we would then use to access their pop3 ***“terminals”***

![credentials-from-hydra](/post-images/Golden-Eye/credz.png)

![credentials-from-hydra](/post-images/Golden-Eye/credz1.png)

With everything in order we logged into Natalya first since previously we were informed 
that Natalya could be abale to break Boris’ password, so most probably Natalya was a 
stronger or superior security **‘persons’**. 
Lucky for us Natalya had very important information; 
 + Including the logins of a user named xenia, 
 + Instructions on how to run the Domain remotely

So we add the servernaya-station.com in our /etc/hosts file.

![host](/post-images/Golden-Eye/hostserv.png)

![host](/post-images/Golden-Eye/etchost.png)

So we logged In as Xenia and checked on his profile found messages which was 
interesting since it was similar that we found messages in pop3; 

![Doak](/post-images/Golden-Eye/Drmember.png)

We checked his messages and found communications with Dr. Doak, with Doak 
informing him that his email username is doak. 

It was tempting enough to check his pop3 connection to the network and we found his 
credentials; 
 + His username being: doak 
 + Password being: goat 

![dr-credz](/post-images/Golden-Eye/drcredz.png)

In Doak’s module we found from his messages some secret.txt file; 

![secret](/post-images/Golden-Eye/secret.png)

Downloaded it, this was our findings; 

![secret](/post-images/Golden-Eye/txt.png)

We navigated to the URL in place and found an image and downloaded the image;

![secret-pic](/post-images/Golden-Eye/pic.png)

We then used a tool called exiftool in kali to get information on the image, these were our 
findings; 

![exif](/post-images/Golden-Eye/exif1.png)

The image Description really stood out as it looked like a `base64 encoding which tends to 
have double (==) at the end of the encoding`; 
We decoded it and found;

![decode](/post-images/Golden-Eye/listener2.png)

We then logged In as the admin; 

![admin](/post-images/Golden-Eye/admin.png)

having this as his password as the image hinted out on that we have ***“picked an access key”*** which might have ment that whatever our findings we would have the admin pass 
key. 
Having being the admin we first ran through the system settings and on the system path 
we found an aspell path, since we are informed that it has its path usually in Unix and 
Linux in ***“/usr/bin/aspell”*** . 
We can inject a code listener to get a bash if the machine has one. Here is the python2 
code listener.

![listener](/post-images/Golden-Eye/listener3.png)

![listener](/post-images/Golden-Eye/0__R97O_bdm-8PGbp3.png)

After saving the changes we navigated once more to the site administration to plugins and 
changed the default spell checker to pspellshell since it is the one that communicates with 
the aspell: 

![listener](/post-images/Golden-Eye/pspellshell.png)

We then changed it to Pspellshell since it was set to Google Spell by default; 

![tiny](/post-images/Golden-Eye/pspell.png)

After saving all changes we added an entry in the site pages <b>(but wherever you choose basically as long as there is a spell checker it will have to execute the listener). </b> 

![tester](/post-images/Golden-Eye/test01.png)

Running the spellchecker loads the site infinatly, and the listener in our terminal lauches 
a bash shell; 

![netcat](/post-images/Golden-Eye/nc.png)

Since we are www-data we must find a way to escalate our privileges to root, which is 
the aim of the game. We have an idea that the machine runs on Ubuntu so we look for a 
exploitation within the version range of the ubuntu we have and get the exploit; this is 
just basic searchsploit; 

`searchsploit ubuntu 3.13`

gets you the available exploits for the version of ubuntu we are running on;

copy the exploit to your golden eye folder `37292.c`

`cp /usr/share/exploitdb/exploits/linux/local/37292.c /home/user/Golden-Eye/`

we check the version of gcc running on the vuln machine and we get this but it runs cc 
on clang so we can modify how our code compiles; 

So we make changes on how our C code compiles; 

![netcat](/post-images/Golden-Eye/cc.png)

By searching on gcc in the file we found and converted them to be compatible with the cc 
compiler; 
We proceed to opening a python simple http server so as to download the exploit to our 
vuln machine bash; 
**NOTE;** We used port 8000 since port 80 and 8080 were already in use<mark>(You can choose 
whatever port number you wish as long as the machine you are on is not using it)</mark> 

![netcat](/post-images/Golden-Eye/compile.png)

Then to compile and run the C file; 

With it compiled we run the exploit and just like that we get a root bash;

![](/post-images/Golden-Eye/whoami.png)

Thank you. Next I will do Metasploitable 1.