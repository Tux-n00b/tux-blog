# Empire LupinOne

## Enumeration

I started by performing an Nmap scan on the target IP `192.168.168.130`. Below are the results of the scan:

![Nmap Scan Results](/public/post-images/empire-lupinOne/1netscan.png)

The scan revealed that ports 22 (SSH) and 80 (HTTP) are open on the target machine `192.168.168.130`.

> Port 22 is typically used for secure remote access via SSH, which could allow for command-line interaction if valid credentials are found. Port 80 is used for web services, indicating that a website or web application is hosted on the machine.

---

## Exploring the Web Service

Next, I opened the target IP `192.168.168.130` in my browser using port 80. The page displayed an image, but nothing else of interest was immediately visible. To dig deeper, I viewed the page's source code.

![Page Source Code](/public/post-images/empire-lupinOne/2sourcecode.png)

The source code did not contain any useful information or hints for further exploitation. At this stage, the web service appears minimal, so additional enumeration will be necessary to uncover potential vulnerabilities or hidden content.

---

## Checking robots.txt

I decided to check the `robots.txt` file for any hidden directories or files. In the file, I found a reference to **~/myfiles**. I navigated to this location in the browser, but it did not contain anything useful and returned a 403 Forbidden error.

![robots.txt](/public/post-images/empire-lupinOne/3robotstxt.png)

Despite the 404 error, the existence of this directory suggests that there may be additional files or directories of interest in the `/myfiles` path that are not accessible due to permission restrictions.

---

## Fuzzing for Hidden Directories

To continue the enumeration, I used `ffuf` to fuzz the target machine `192.168.168.130` for hidden directories and files. This technique helps uncover content that may not be immediately visible or linked on the main page.

During the fuzzing process, I discovered a folder named `secret` in the root of the target directory.

![ffuf Fuzzing Results](/public/post-images/empire-lupinOne/5fuzz.png)

---

## Exploring the `secret` Directory

After discovering the `secret` directory through fuzzing, I opened `http://192.168.168.130/~secret/` in my browser. Upon accessing this directory, I was presented with the following page:

![Secret Directory](/public/post-images/empire-lupinOne/6~secret.png)

The author has left us a useful hint and now we can try and fuzz to look for the file with the ssh private key.
