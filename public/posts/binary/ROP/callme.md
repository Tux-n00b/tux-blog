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