# Reverse Engineering Report — `a.out`

## 1. Executive Summary

This report documents the static reverse engineering of the uploaded `a.out` ELF executable.

The binary is a small, dynamically linked Linux x86-64 PIE executable. It is **not stripped** and contains useful symbols and build metadata. Its application-level behavior is extremely simple: `main()` obtains the address of the constant string `"hello"`, passes it as the first argument to `puts()`, and returns `0`.

The reconstructed application source is effectively:

```c
#include <stdio.h>

int main(void)
{
    puts("hello");
    return 0;
}
```

The complete execution path is:

```text
Linux Kernel
    |
    v
ELF loader / ld-linux-x86-64.so.2
    |
    v
_start @ 0x1060
    |
    v
__libc_start_main()
    |
    v
main() @ 0x1149
    |
    v
puts@plt @ 0x1050
    |
    v
GOT / dynamic linker
    |
    v
libc puts()
    |
    v
stdout -> "hello\n"
    |
    v
return 0
```

No application-level evidence was found for networking, file processing, command execution, cryptography, heap allocation, complex input parsing, loops, or conditional logic.

---

# 2. Target Identification

| Property | Finding |
|---|---|
| Target | `a.out` |
| Format | ELF64 |
| Architecture | x86-64 / AMD64 |
| Endianness | Little-endian |
| OS ABI | System V / Linux |
| ELF Type | `ET_DYN` — Position Independent Executable (PIE) |
| Dynamic Linking | Yes |
| Stripped | No |
| Entry Point | `0x1060` |
| `main()` | `0x1149` |
| `puts@plt` | `0x1050` |
| String `"hello"` | `0x2004` |
| Dynamic dependency | `libc.so.6` |
| Dynamic loader | `/lib64/ld-linux-x86-64.so.2` |
| Compiler metadata | GCC 9.4.0 |
| Embedded source filename | `test.c` |
| Build ID | `211ce4f5eddb5d1fb3dd19a35562d53a2c7ebbe0` |
| Output | `hello` |

The ELF header reports:

```text
Type:                     DYN (Position-Independent Executable file)
Machine:                  Advanced Micro Devices X86-64
Entry point address:      0x1060
Number of program headers: 13
Number of section headers: 31
```

---

# 3. Compiler / Build Evidence

The binary contains GCC version information:

```text
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
```

It also contains the source filename:

```text
test.c
```

This strongly suggests that the executable was built from a small C source file named `test.c`.

The exact source cannot be proven byte-for-byte from the executable alone, but the disassembly and strings make the following reconstruction highly reliable:

```c
#include <stdio.h>

int main(void)
{
    puts("hello");
    return 0;
}
```

---

# 4. ELF Execution Workflow

The normal runtime sequence is:

```text
1. Linux executes a.out
        |
        v
2. Kernel parses ELF headers
        |
        v
3. Dynamic loader is started
   /lib64/ld-linux-x86-64.so.2
        |
        v
4. libc.so.6 is mapped
        |
        v
5. Dynamic relocations are processed
        |
        v
6. Execution reaches ELF entry point 0x1060
        |
        v
7. _start prepares process state
        |
        v
8. _start invokes __libc_start_main()
        |
        v
9. __libc_start_main() invokes main()
        |
        v
10. main() loads address of "hello"
        |
        v
11. main() calls puts@plt
        |
        v
12. PLT/GOT resolves libc puts()
        |
        v
13. puts() writes "hello" to stdout
        |
        v
14. main() returns 0
        |
        v
15. libc performs process termination
```

---

# 5. Entry Point Analysis — `_start`

The ELF entry point is:

```text
0x1060
```

The relevant disassembly is:

```asm
0000000000001060 <_start>:
    endbr64
    xor    ebp,ebp
    mov    r9,rdx
    pop    rsi
    mov    rdx,rsp
    and    rsp,0xfffffffffffffff0
    push   rax
    push   rsp
    lea    r8,[rip+0x166]        # 11e0 <__libc_csu_fini>
    lea    rcx,[rip+0xef]        # 1170 <__libc_csu_init>
    lea    rdi,[rip+0xc1]        # 1149 <main>
    call   QWORD PTR [rip+0x2f52] # 3fe0 <__libc_start_main@GLIBC_2.2.5>
    hlt
```

The key instruction is:

```asm
lea rdi,[rip+0xc1]        # 1149 <main>
```

This places the address of `main()` into `RDI` before the call to `__libc_start_main()`.

Therefore the startup flow is:

```text
_start
  |
  +-- address of main -> RDI
  |
  +-- __libc_csu_init -> RCX
  |
  +-- __libc_csu_fini -> R8
  |
  v
__libc_start_main()
```

## Important Reverse Engineering Point

The ELF entry point is **not** the same thing as the C `main()` function.

The actual chain is:

```text
ELF Entry
    |
    v
_start
    |
    v
__libc_start_main
    |
    v
main
```

This distinction is important when analyzing Linux binaries in Ghidra, IDA, Binary Ninja, or GDB.

---

# 6. `main()` Analysis

The application's main function begins at:

```text
0x1149
```

Disassembly:

```asm
0000000000001149 <main>:
    endbr64
    push   rbp
    mov    rbp,rsp
    lea    rdi,[rip+0xeac]       # 2004 <_IO_stdin_used+0x4>
    call   1050 <puts@plt>
    mov    eax,0x0
    pop    rbp
    ret
```

This is the most important application-level code in the executable.

---

# 7. Instruction-by-Instruction `main()` Analysis

## 7.1 `endbr64`

```asm
endbr64
```

This instruction is associated with Intel Control-flow Enforcement Technology, specifically Indirect Branch Tracking (IBT).

It marks a valid target for an indirect branch/call under CET/IBT.

---

## 7.2 Function Prologue

```asm
push rbp
mov rbp,rsp
```

This creates the traditional stack frame:

```text
old RBP saved
    |
    v
RBP = current stack frame
```

There are no meaningful local variables in this function.

---

## 7.3 Loading the String Address

```asm
lea rdi,[rip+0xeac]
```

The effective target is:

```text
0x2004
```

The bytes at that location represent:

```text
68 65 6c 6c 6f 00
```

ASCII:

```text
h e l l o \0
```

Therefore, immediately before the function call:

```text
RDI -> "hello\0"
```

Under the System V AMD64 calling convention, `RDI` contains the first integer/pointer argument.

Thus this instruction sequence is equivalent to:

```c
const char *arg1 = "hello";
```

---

# 8. Calling `puts()`

The next instruction is:

```asm
call 1050 <puts@plt>
```

At the C level, this corresponds to:

```c
puts("hello");
```

The program therefore produces:

```text
hello
```

followed by the newline added by `puts()`.

---

# 9. PLT / GOT / Dynamic Linking Flow

The executable is dynamically linked, so `main()` does not contain the implementation of `puts()`.

Instead, the call goes through the Procedure Linkage Table (PLT):

```text
main()
   |
   v
puts@plt @ 0x1050
   |
   v
GOT entry
   |
   v
dynamic linker / resolved address
   |
   v
libc.so.6: puts()
```

The PLT entry is:

```asm
0000000000001050 <puts@plt>:
    endbr64
    bnd jmp QWORD PTR [rip+0x2f75] # 3fd0 <puts@GLIBC_2.2.5>
    nop
```

The dynamic symbol table identifies:

```text
puts@GLIBC_2.2.5
```

The binary therefore uses the normal ELF dynamic linking mechanism rather than statically embedding libc's `puts()` implementation.

---

# 10. `puts()` Dependency

The dynamic section reports:

```text
NEEDED Shared library: [libc.so.6]
```

The program's main external functionality is therefore provided by glibc.

Conceptually:

```text
a.out
 |
 +-- puts@plt
       |
       +-- GOT
             |
             +-- libc.so.6
                    |
                    +-- puts()
```

---

# 11. Returning From `main()`

After `puts()` returns:

```asm
mov eax,0x0
```

sets the return value to zero.

At the C level:

```c
return 0;
```

Then:

```asm
pop rbp
ret
```

restores the stack frame and returns from `main()`.

---

# 12. Reconstructed C Source

The most likely original source is:

```c
#include <stdio.h>

int main(void)
{
    puts("hello");
    return 0;
}
```

A decompiler would produce essentially the same logic:

```c
int main(void)
{
    puts("hello");
    return 0;
}
```

---

# 13. Control-Flow Graph

The `main()` control flow is completely linear:

```text
                 main()
                   |
                   v
          Create stack frame
                   |
                   v
          Load "hello" address
                   |
                   v
             puts("hello")
                   |
                   v
               EAX = 0
                   |
                   v
            Destroy stack frame
                   |
                   v
                return
```

There are no application-level `if`, `else`, `switch`, `for`, or `while` constructs in `main()`.

---

# 14. Complete Codeflow Diagram

```text
                    +----------------------+
                    |     Linux Kernel     |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |     ELF Loader       |
                    | ld-linux-x86-64.so.2 |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |       _start         |
                    |       0x1060         |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | __libc_start_main()  |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |        main()        |
                    |       0x1149         |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | RDI = "hello"       |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |      puts@plt        |
                    |       0x1050         |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |      GOT / PLT       |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |      libc puts()     |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |     stdout / TTY     |
                    +----------+-----------+
                               |
                               v
                            hello\n
                               |
                               v
                            return 0
```

---

# 15. Function Map

The executable contains several functions, but most are compiler/runtime support rather than application logic.

| Address | Function | Classification |
|---|---|---|
| `0x1000` | `_init` | Runtime |
| `0x1050` | `puts@plt` | Dynamic linking |
| `0x1060` | `_start` | Runtime entry |
| `0x1090` | `deregister_tm_clones` | Compiler/runtime |
| `0x10c0` | `register_tm_clones` | Compiler/runtime |
| `0x1100` | `__do_global_dtors_aux` | Compiler/runtime |
| `0x1140` | `frame_dummy` | Compiler/runtime |
| `0x1149` | `main` | **Application logic** |
| `0x1170` | `__libc_csu_init` | Runtime |
| `0x11e0` | `__libc_csu_fini` | Runtime |
| `0x11e8` | `_fini` | Runtime |

The critical application function is:

```text
main @ 0x1149
```

---

# 16. String Analysis

The primary application string is:

```text
hello
```

located at approximately:

```text
0x2004
```

Raw bytes:

```text
68 65 6c 6c 6f 00
```

ASCII:

```text
hello\0
```

The string is directly referenced by `main()` through RIP-relative addressing:

```asm
lea rdi,[rip+0xeac]        # 0x2004
```

This is a direct static correlation between the data and the execution path.

---

# 17. Important ELF Sections

The binary follows normal ELF organization.

### `.text`

Contains executable machine code such as:

```text
_start
main
runtime functions
PLT code
```

### `.rodata`

Contains read-only constants, including:

```text
"hello"
```

### `.data`

Contains initialized writable data.

### `.bss`

Contains zero-initialized writable data.

### `.got`

Contains Global Offset Table entries used by dynamic linking.

### `.plt`

Contains Procedure Linkage Table stubs used to call imported functions.

### `.dynamic`

Contains metadata consumed by the dynamic loader.

### `.rela.plt`

Contains relocation information associated with dynamic function calls.

---

# 18. Dynamic Dependencies

The executable requires:

```text
libc.so.6
```

and uses:

```text
/lib64/ld-linux-x86-64.so.2
```

as its ELF interpreter.

This means the program relies on the standard Linux dynamic linking environment.

---

# 19. Imported Functionality

The significant application-level external function is:

```text
puts@GLIBC_2.2.5
```

No evidence was found in the application code for imports associated with:

```text
Networking:
    socket()
    connect()
    send()
    recv()

File operations:
    open()
    read()
    write()

Process execution:
    system()
    execve()
    fork()

Heap allocation:
    malloc()
    calloc()
    realloc()
    free()

Debugging:
    ptrace()

Dynamic module loading:
    dlopen()
```

This makes the application-level attack surface very small.

---

# 20. Security Mitigations / Hardening

The executable contains several modern ELF hardening characteristics.

## 20.1 PIE

The ELF type is:

```text
DYN (Position-Independent Executable file)
```

This supports loading at a randomized base address under ASLR.

## 20.2 CET / IBT / SHSTK

The ELF GNU property notes report:

```text
x86 feature: IBT, SHSTK
```

and the code contains:

```asm
endbr64
```

at valid function entry points.

## 20.3 GNU_RELRO

The binary contains:

```text
GNU_RELRO
```

which provides protection for relevant relocation-related memory after dynamic linking.

## 20.4 Non-executable stack

The `GNU_STACK` program header is:

```text
RW
```

rather than `RWX`, indicating the stack is not marked executable.

---

# 21. Attack Surface Assessment

## User Input

No obvious user-controlled input is processed.

## Network

No networking functionality was identified.

## Files

No application-level file processing was identified.

## Command Execution

No `system()`/`exec*()` functionality was identified.

## Heap

No heap allocation was identified.

## Parsing

No complex parser is present.

## Memory Operations

No obvious dangerous memory-copy primitive such as `strcpy`, `strcat`, `gets`, `sprintf`, or application-level `memcpy` was identified.

Overall, there is no obvious vulnerability surface in the application logic itself.

---

# 22. Static Reverse Engineering Findings

The key findings are:

1. The target is an ELF64 Linux executable.
2. The architecture is x86-64 / AMD64.
3. The executable is little-endian.
4. The executable is PIE (`ET_DYN`).
5. It is dynamically linked against glibc.
6. The binary is not stripped.
7. The ELF entry point is `0x1060`.
8. `_start` passes the address of `main()` to `__libc_start_main()`.
9. `main()` is located at `0x1149`.
10. `main()` loads the address of the string `"hello"` at `0x2004`.
11. The first function argument is passed through `RDI` according to the System V AMD64 ABI.
12. `main()` calls `puts@plt` at `0x1050`.
13. `puts()` is supplied by `libc.so.6`.
14. The program returns `0` from `main()`.
15. The binary contains GCC 9.4.0 metadata.
16. The embedded source filename is `test.c`.
17. The binary contains CET-related IBT/SHSTK properties.
18. The stack is not executable.
19. GNU_RELRO is present.
20. No complex application-level control flow was identified.
21. No networking, file processing, command execution, cryptographic logic, or user-input processing was identified.

---

# 23. Behavioral Model

The behavior can be reduced to:

```text
Input:
    None

Processing:
    Load constant string "hello"

Action:
    puts("hello")

Output:
    hello\n
Return value:
    0
```

Pseudocode:

```text
PROGRAM START

    initialize runtime

    CALL main()

        LOAD address of "hello"

        CALL puts("hello")

        RETURN 0

    terminate process

PROGRAM END
```

---

# 24. Suggested Reproduction Commands

The analysis can be reproduced with standard Linux reverse-engineering tools.

## Identify the binary

```bash
file a.out
```

## Inspect ELF header

```bash
readelf -h a.out
```

## Inspect sections

```bash
readelf -S a.out
```

## Inspect program headers

```bash
readelf -lW a.out
```

## Inspect symbols

```bash
readelf -s a.out
nm -C a.out
```

## Inspect dynamic symbols

```bash
readelf -d a.out
readelf -r a.out
objdump -T a.out
```

## Extract strings

```bash
strings -a -t x a.out
```

## Disassemble

```bash
objdump -d -M intel a.out
```

## Inspect dependencies

```bash
ldd a.out
```

---

# 25. GDB Workflow

A simple dynamic validation workflow is:

```bash
gdb ./a.out
```

Then:

```gdb
info files
info functions
disassemble main
break main
run
```

Inspect the string:

```gdb
x/s 0x2004
```

Inspect registers:

```gdb
info registers
```

At the `puts()` call, the important relationship is:

```text
RDI -> "hello"
```

Single-step with:

```gdb
si
```

This can be used to observe the transition through the PLT and into libc.

---

# 26. Ghidra Workflow

A suitable Ghidra workflow is:

```text
Import a.out
    |
    v
Auto Analyze
    |
    v
ELF Headers
    |
    v
Symbol Tree
    |
    v
Functions
    |
    v
main()
    |
    +--> Decompiler
    |
    +--> Listing
    |
    +--> Function Graph
    |
    v
Strings
    |
    v
Cross References to "hello"
    |
    v
puts()
```

The decompiler should reduce the application logic to approximately:

```c
int main(void)
{
    puts("hello");
    return 0;
}
```

---

# 27. Reverse Engineering Lessons

Although the binary is trivial, it demonstrates several concepts that are essential when analyzing larger Linux binaries, malware, and firmware:

- ELF headers and program headers
- ELF entry points
- `_start`
- C runtime initialization
- `__libc_start_main`
- x86-64 System V calling convention
- `RDI` as the first function argument register
- RIP-relative addressing
- `.rodata`
- PLT
- GOT
- dynamic symbols
- relocations
- PIE
- ASLR compatibility
- CET / IBT
- SHSTK metadata
- RELRO
- stack permissions
- compiler-generated runtime functions
- separation of runtime code from application logic

A key practical lesson is to distinguish compiler/runtime functions such as:

```text
_start
register_tm_clones
deregister_tm_clones
__do_global_dtors_aux
frame_dummy
__libc_csu_init
__libc_csu_fini
```

from actual application logic:

```text
main
```

This distinction becomes especially important in large binaries, where automatically generated functions can otherwise consume a significant amount of analysis time.

---

# 28. Final Codeflow Summary

```text
a.out
  |
  v
ELF Entry @ 0x1060
  |
  v
_start
  |
  v
__libc_start_main
  |
  v
main @ 0x1149
  |
  v
RDI = address of "hello"
  |
  v
puts@plt @ 0x1050
  |
  v
GOT / dynamic linker
  |
  v
libc puts()
  |
  v
stdout
  |
  v
"hello\n"
  |
  v
return 0
  |
  v
process termination
```

---

# 29. Final Assessment

**Target:** `a.out`

**Classification:** Minimal dynamically linked Linux ELF executable

**Architecture:** x86-64

**Application complexity:** Very low

**Primary application function:** `main()` at `0x1149`

**Primary imported function:** `puts()`

**Application output:** `hello`

**Return value:** `0`

**Obfuscation/packing identified:** No

**Symbols available:** Yes

**Network functionality identified:** No

**File I/O identified:** No

**Command execution identified:** No

**Cryptographic functionality identified:** No

**Complex input processing identified:** No

**Overall conclusion:**

`a.out` is essentially a GCC-generated Hello World-style program. Its primary reverse-engineering value is educational: it provides a compact example of the complete Linux ELF execution chain from `_start`, through `__libc_start_main()`, into `main()`, through the PLT/GOT dynamic-linking mechanism, and finally into glibc's `puts()` implementation.

---

# Appendix A — Key Addresses

```text
Entry point        : 0x1060
puts@plt            : 0x1050
frame_dummy         : 0x1140
main                : 0x1149
__libc_csu_init     : 0x1170
__libc_csu_fini     : 0x11e0
_fini               : 0x11e8
"hello"            : 0x2004
puts GOT target     : 0x3fd0
__libc_start_main   : 0x3fe0 (GOT reference)
```

---

# Appendix B — Important Raw Evidence

## ELF identification

```text
ELF 64-bit LSB pie executable, x86-64
Dynamically linked
interpreter /lib64/ld-linux-x86-64.so.2
BuildID[sha1]=211ce4f5eddb5d1fb3dd19a35562d53a2c7ebbe0
not stripped
```

## Embedded strings

```text
0x2004  hello
0x3010  GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
0x36f0  test.c
```

## Security properties

```text
GNU property: x86 feature: IBT, SHSTK
GNU_RELRO present
GNU_STACK: RW (non-executable)
```

---

# Appendix C — Reconstructed Source

```c
#include <stdio.h>

int main(void)
{
    puts("hello");
    return 0;
}
```

---

# Appendix D — One-Line Summary

```text
a.out -> _start -> __libc_start_main -> main -> puts("hello") -> return 0
```

---

**Report prepared from static analysis of the uploaded `a.out` binary.**
