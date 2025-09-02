# Command Injection — Deep-Dive (Expanded, Beginner-Friendly)


>
Command Injection

> Author: Weilin Zhong
> Contributor(s): Wichers, Amwestgate, Rezos, Clow808, KristenS, Jason Li, Andrew Smith, Jmanico, Tal Mel, kingthorin

### Description ###

Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell. In this attack, the attacker-supplied operating system commands are usually executed with the privileges of the vulnerable application. Command injection attacks are possible largely due to insufficient input validation.

This attack differs from Code Injection, in that code injection allows the attacker to add their own code that is then executed by the application. In Command Injection, the attacker extends the default functionality of the application, which execute system commands, without the necessity of injecting code.
> ### Examples ###
>
> The following code is a wrapper around the UNIX command cat which prints the contents of a file to standard output. It is also injectable:
```C
 #include <stdio.h>
 #include <unistd.h>

 int main(int argc, char **argv) {
  char cat[] = "cat ";
  char *command;
  size_t commandLength;

  commandLength = strlen(cat) + strlen(argv[1]) + 1;
  command = (char *) malloc(commandLength);
  strncpy(command, cat, commandLength);
  strncat(command, argv[1], (commandLength - strlen(cat)) );

  system(command);
  return (0);
}
```
Used normally, the output is simply the contents of the file requested:

> $ ./catWrapper Story.txt
> When last we left our heroes...

However, if we add a semicolon and another command to the end of this line, the command is executed by catWrapper with no complaint:

> $ ./catWrapper "Story.txt; ls"

`When last we left our heroes...
Story.txt  doubFree.c              nullpointer.c
unstosig.c              www*                    a.out*
format.c                strlen.c                useFree*
catWrapper*             misnull.c               strlength.c             useFree.c
commandinjection.c      nodefault.c             trunc.c                 writeWhatWhere.c
`
> If catWrapper had been set to have a higher privilege level than the standard user, arbitrary commands could be executed with that higher privilege.

> Example 2
>
> The following simple program accepts a filename as a command line argument, and displays the contents of the file back to the user. The program is installed setuid root because it is intended for use as a learning tool to allow system administrators in-training to inspect privileged system files without giving them the ability to modify them or damage the system.

```C++ C
 int main(char* argc, char** argv) {
  char cmd[CMD_MAX] = "/usr/bin/cat ";
  strcat(cmd, argv[1]);
  system(cmd);
 }
```

Because the program runs with root privileges, the call to system() also executes with root privileges. If a user specifies a standard filename, the call works as expected. However, if an attacker passes a string of the form “;rm -rf /”, then the call to system() fails to execute cat due to a lack of arguments and then plows on to recursively delete the contents of the root partition.

> Example 3
>
> The following code from a privileged program uses the environment variable $APPHOME to determine the application’s installation directory, and then executes an initialization script in that directory.
```C
 ...
 char* home=getenv("APPHOME");
 char* cmd=(char*)malloc(strlen(home)+strlen(INITCMD));
 if (cmd) {
  strcpy(cmd,home);
  strcat(cmd,INITCMD);
  execl(cmd, NULL);
 }
 ...
```
> As in Example 2, the code in this example allows an attacker to execute arbitrary commands with the elevated privilege of the application. In this example, the attacker can modify the environment variable $APPHOME to specify a different path containing a malicious version of INITCMD. Because the program does not validate the value read from the environment, by controlling the environment variable, the attacker can fool the application into running malicious code.

The attacker is using the environment variable to control the command that the program invokes, so the effect of the environment is explicit in this example. We will now turn our attention to what can happen when the attacker changes the way the command is interpreted.

> Example 4
>
> The code below is from a web-based CGI utility that allows users to change their passwords. The password update process under NIS includes running make in the /var/yp directory. Note that since the program updates password records, it has been installed setuid root.
>
> The program invokes make as follows:
>
> system("cd /var/yp && make &> /dev/null");
>
> Unlike the previous examples, the command in this example is hardcoded, so an attacker cannot control the argument passed to system(). However, since the program does not specify an absolute path for make, and does not scrub any environment variables prior to invoking the command, the attacker can modify their $PATH variable to point to a malicious binary named make and execute the CGI script from a shell prompt. And since the program has been installed setuid root, the attacker’s version of make now runs with root privileges.
>
> The environment plays a powerful role in the execution of system commands within programs. Functions like system() and exec() use the environment of the program that calls them, and therefore attackers have a potential opportunity to influence the behavior of these calls.
>
> There are many sites that will tell you that Java’s Runtime.exec is exactly the same as C’s system function. This is not true. Both allow you to invoke a new program/process. However, C’s system function passes its arguments to the shell (/bin/sh) to be parsed, whereas Runtime.exec tries to split the string into an array of words, then executes the first word in the array with the rest of the words as parameters. Runtime.exec does NOT try to invoke the shell at any point. The key difference is that much of the functionality provided by the shell that could be used for mischief (chaining commands using “&”, “&&”, “|”, “||”, etc, redirecting input and output) would simply end up as a parameter being passed to the first command, and likely causing a syntax error, or being thrown out as an invalid parameter.
> Example 5
>
> The following trivial code snippets are vulnerable to OS command injection on the Unix/Linux platform:
>
```C

 #include <stdlib.h>
 #include <stdio.h>
 #include <string.h>

 int main(int argc, char **argv)
 {
      char command[256];

      if(argc != 2) {
           printf("Error: Please enter a program to time!\n");
           return -1;
      }

      memset(&command, 0, sizeof(command));

     strcat(command, "time ./");
      strcat(command, argv[1]);

      system(command);
      return 0;
 }
```
> If this were a suid binary, consider the case when an attacker enters the following: ls; cat /etc/shadow. In the Unix environment, shell commands are separated by a semi-colon. We now can execute system commands at will!
>
> Java:
>
> There are many sites that will tell you that Java’s Runtime.exec is exactly the same as C’s system function. This is not true. Both allow you to invoke a new program/process. However, C’s system function passes its arguments to the shell (/bin/sh) to be parsed, whereas Runtime.exec tries to split the string into an array of words, then executes the first word in the array with the rest of the words as parameters. Runtime.exec does NOT try to invoke the shell at any point. The key difference is that much of the functionality provided by the shell that could be used for mischief (chaining commands using &, &&, |, ||, etc, redirecting input and output) would simply end up as a parameter being passed to the first command, and likely causing a syntax error, or being thrown out as an invalid parameter.
> Example 6
>
> The following PHP code snippet is vulnerable to a command injection attack:
```PHP
 <?php
 print("Please specify the name of the file to delete");
 print("<p>");
 $file=$_GET['filename'];
 system("rm $file");
 ?>
```
> The following request and response is an example of a successful attack:
>
> Request http://127.0.0.1/delete.php?filename=bob.txt;id
>
> Response
>
> Please specify the name of the file to delete
>
> uid=33(www-data) gid=33(www-data) groups=33(www-data)
>
> Sanitizing Input
>
> Replace or Ban arguments with “;”
> Other shell escapes available
> Example:
> –  &&
> –  |
> –  ...
>
> Related Controls
>
> Ideally, a developer should use existing API for their language. For example (Java): Rather than use Runtime.exec() to issue a ‘mail’ command, use the available Java API located at javax.mail.*.
>
> If no such available API exists, the developer should scrub all input for malicious characters. Implementing a positive security model would be most efficient. Typically, it is much easier to define the legal characters than the illegal characters.
>
---

## What Is Command Injection? (Beginner-Friendly Explanation)

**Command injection** happens when an application takes user input and passes it to the operating system *shell* (like `/bin/sh` on Linux) without strict checks. The shell then interprets metacharacters (such as `;`, `&&`, `|`) and may run *additional commands* the developer never intended.

### Key ideas
- **Shell vs. Program**: Running `system("cat file")` uses a shell to interpret the string; semicolons, pipes, and redirections *change behavior*. Running `execve("/bin/cat", ["cat","file"], env)` does **not** invoke a shell—no metacharacters are interpreted.
- **Privilege context**: The injected command runs with **the same privileges as the vulnerable app** (e.g., `www-data`, or even `root` if the binary is setuid). This can turn small bugs into full system compromise.
- **Root causes**: Concatenating strings to form commands, trusting environment variables (`PATH`, custom vars), not using absolute paths, and weak input validation.

> **Mental model:** If your code constructs a single string and hands it to a shell, assume attackers can *append, split, or redirect* commands unless you strictly constrain the input.

---

## Example 1 — C `system()` with string concatenation

> **Original code (kept intact):**
>
> ```c
> #include <stdio.h>
> #include <unistd.h>
>
> int main(int argc, char **argv) {
>  char cat[] = "cat ";
>  char *command;
>  size_t commandLength;
>
>  commandLength = strlen(cat) + strlen(argv[1]) + 1;
>  command = (char *) malloc(commandLength);
>  strncpy(command, cat, commandLength);
>  strncat(command, argv[1], (commandLength - strlen(cat)) );
>
>  system(command);
>  return (0);
> }
> ```
>
> **Injection demo (kept intact):**
>
> ```bash
> $ ./catWrapper "Story.txt; ls"
> ```

### Why it’s vulnerable
- `system()` hands the *entire* `command` string to the shell.
- Attackers can inject `; ls` (or `&&`, `|`) to **chain** additional commands.
- Memory ops here also risk subtle off-by-one issues (e.g., null terminator), but the main problem is *shell interpretation*.

### Safer approach
- **Avoid the shell entirely**; pass arguments as an array:
  ```c
  #include <unistd.h>
  int main(int argc, char **argv) {
      if (argc != 2) return 1;
      execl("/bin/cat", "cat", argv[1], (char*)NULL);  // No shell involved
  }
  ```
- **Constrain input**: if you expect a *filename*, enforce a tight allowlist regex like `^[A-Za-z0-9._/-]{1,128}$` and deny `..`, leading `/`, or NUL bytes.
- **Use absolute paths**: never rely on `$PATH` to find `cat`.

> **Tip:** If you must time or compose multiple commands, do the orchestration **in your program**, not by concatenating shell strings.

---

## Example 2 — Setuid + `system()`

> **Original narrative (kept intact):**
>
> Program is setuid root and does:
> ```c
> char cmd[CMD_MAX] = "/usr/bin/cat ";
> strcat(cmd, argv[1]);
> system(cmd);
> ```
> Attack payload: `";rm -rf /"`

### Why it’s catastrophic
- Running `system()` as root means *the shell also runs as root*.
- The injected `;rm -rf /` becomes a separate command and can destroy the system.

### Safer approach
- **Never** use `system()` (or any shell) in setuid programs.
- Drop privileges immediately:
  ```c
  setgid(getgid()); setuid(getuid());  // Drop to real user
  ```
- Use `execve("/usr/bin/cat", argv_array, clean_env)` with a **clean environment** (see below) and **whitelisted files** only.
- Consider reading files *in-process* (e.g., `open`, `read`, `write`) and avoid external commands entirely.

---

## Example 3 — Environment variable controls the command

> **Original snippet (kept intact):**
>
> ```c
> char* home=getenv("APPHOME");
> char* cmd=(char*)malloc(strlen(home)+strlen(INITCMD));
> if (cmd) {
>  strcpy(cmd,home);
>  strcat(cmd,INITCMD);
>  execl(cmd, NULL);
> }
> ```

### What goes wrong
- Attacker sets `APPHOME=/tmp/evil/` and places a malicious `INITCMD` there.
- Program executes attacker-controlled binary **with elevated privileges**.

### Safer approach
- **Do not trust environment** in privileged code. Before exec:
  - `clearenv();` then `setenv("PATH","/usr/bin:/bin",1);` and set only what you need.
- Use **fixed absolute paths** and verify executables with `stat()`/ownership/permissions.
- Prefer `execve()` with an explicitly constructed `envp` (environment) array.

---

## Example 4 — PATH hijacking (`make` without absolute path)

> **Original (kept intact):**
>
> ```c
> system("cd /var/yp && make &> /dev/null");
> ```

### Why it’s vulnerable
- The shell looks up `make` via `$PATH`. An attacker can run the CGI with a crafted `PATH` that points to a malicious `make` first.
- Since the CGI is setuid root, the malicious `make` runs as root.

### Safer approach
- Don’t use `system()` here. Use:
  ```c
  chdir("/var/yp");
  execl("/usr/bin/make","make",(char*)NULL);
  ```
- Or sanitize environment first and set `PATH` to a minimal, trusted value.
- Better: avoid setuid CGI entirely; use a root-owned helper with strict IPC and **no shell**.

---

## Java note — `Runtime.exec` vs C `system`

> **Original (kept intact):**
>
> Runtime.exec **does not** invoke a shell; it splits the string and executes the first token as a program. Shell operators like `&`, `&&`, `|`, `||`, redirection are not interpreted.

### Practical guidance
- Prefer `ProcessBuilder` with an **argument list**:
  ```java
  new ProcessBuilder("/usr/bin/cat", "/var/log/app.log")
      .inheritIO()
      .start();
  ```
- Still validate inputs (paths, lengths) and avoid passing untrusted strings as program names.
- If you need “shell features,” implement them safely in Java instead of delegating to a shell.

---

## Example 5 — C program building `"time ./<arg>"`

> **Original (kept intact):**
>
> ```c
> strcat(command, "time ./");
> strcat(command, argv[1]);
> system(command);
> ```
>
> Attack input: `ls; cat /etc/shadow`

### Why it breaks
- `system()` hands `"time ./<user input>"` to the shell. `;` splits into another command.

### Safer approach
- If you only want to run a **specific program**, call it directly:
  ```c
  execl("/usr/bin/time","time","./prog",(char*)NULL);
  ```
  But this still executes `./prog`. Validate `argv[1]` strictly: allow only known program names or map to safe paths.
- Better: **measure time in-process** (`clock_gettime`, `std::chrono`) and run the target via `fork/execve` with arguments array.
- Ensure the binary is **not setuid**; avoid granting elevated privileges to timing helpers.

---

## Example 6 — PHP `system("rm $file")`

> **Original (kept intact):**
>
> ```php
> <?php
> print("Please specify the name of the file to delete");
> print("<p>");
> $file=$_GET['filename'];
> system("rm $file");
> ?>
> ```
>
> Example attack: `?filename=bob.txt;id`

### Why it’s vulnerable
- The string is executed by a shell; `;id` runs as a second command and leaks the process identity (e.g., `www-data`).

### Safer approach
- **Never** shell out for simple file deletion. Use PHP’s API:
  ```php
  <?php
  $base = '/var/www/uploads';
  $name = $_GET['filename'] ?? '';
  if (!preg_match('/^[A-Za-z0-9._-]{1,64}$/', $name)) { http_response_code(400); exit; }
  $path = realpath("$base/$name");
  if ($path !== false && str_starts_with($path, realpath($base).DIRECTORY_SEPARATOR)) {
      @unlink($path);
  }
  ?>
  ```
- If you must use shell commands (not recommended), escape *arguments* with `escapeshellarg()` and still validate allowlists.

---

## Sanitizing Input — What to Watch For

> **Original (kept intact):** Replace or Ban arguments with “;” … Example: `&&`, `|`, `...`

### Broader set of dangerous shell metacharacters
- `;`, `&`, `&&`, `|`, `||`
- `<`, `>`, `>>`, `<<`, `2>&1`
- `` `cmd` ``, `$(cmd)`, `$VAR`
- `*`, `?`, `[ ]`, `{ }`, `~`
- Newlines, control chars
- On Windows: `&`, `|`, `^`, `%VAR%`

> **Important:** Blacklists are brittle. Prefer a **positive security model** (allowlist) with strict patterns and length limits. Normalize inputs (trim, decode once), and reject on failure.

---

## Related Controls — Do This Instead

> **Original (kept intact):** Use language APIs (e.g., `javax.mail.*`) rather than shelling out. If no API exists, scrub inputs and use a positive security model.

### Practical defensive checklist
1. **Avoid the shell**: prefer library calls or direct `execve`/`ProcessBuilder` with argument arrays.
2. **Absolute paths**: reference binaries by full path; don’t rely on `$PATH`.
3. **Clean environment**: `clearenv()` then set only needed variables before `exec` in privileged programs.
4. **Whitelists**: define legal inputs (charset, length, format); reject everything else.
5. **Drop privileges**: do not use setuid; if unavoidable, drop to least privilege ASAP.
6. **Chroot/containers**: execute helpers in a constrained environment.
7. **No concatenation**: never build commands by string concatenation.
8. **Logging & auditing**: log rejections and unexpected inputs; monitor for anomalies.
9. **Unit/integration tests**: include tests for metacharacters and dangerous sequences.
10. **Review & threat model**: look for any code path that constructs shell command strings.

---

## Quick Reference — Safe Patterns by Language

### C/C++
- Use `fork` + `execve`/`execvpe` with **argv arrays** and a **clean envp**.
- File ops via system calls (`open`, `unlink`) instead of `rm`, `cat`, etc.

### Java
- Use `ProcessBuilder(List<String> args)`; avoid passing a single shell string.
- Prefer libraries (e.g., Mail via `javax.mail`) over CLI tools.

### PHP
- Prefer native functions: `unlink`, `copy`, `move_uploaded_file`, etc.
- If external tools are unavoidable, use `proc_open` with arrays/descriptors and validate allowlists.

---

## Summary

- **Command injection** occurs when untrusted input is interpreted by a shell.
- The risk scales with **privileges** and **environment influence** (e.g., `$PATH`, custom env vars).
- The most reliable fix is to **avoid the shell**, validate inputs with **allowlists**, use **absolute paths**, and **drop privileges**.