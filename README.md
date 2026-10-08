# ARM Firmware Reverse Engineering Report --- `base.bin` vs `aes.bin`

## Executive Summary

The supplied archive contains two firmware images for the same small ARM
microcontroller:

-   **`base.bin`** --- baseline firmware providing startup, clock/GPIO
    setup, UART communication, trigger handling, serial command parsing,
    and command dispatch, but no AES implementation.
-   **`aes.bin`** --- the same general firmware skeleton with AES-128
    encryption, key handling, AES tables, and repeated-encryption
    commands added.

The binary-level findings and the supplied disassembly/emulation
findings agree on the central conclusion: **`aes.bin` contains a
conventional software AES-128 implementation with the hard-coded key
`2B7E151628AED2A6ABF7158809CF4F3C`.**

The key is located at:

``` text
aes.bin + 0x563F
virtual address 0x0800563F
16 bytes
```

The firmware also contains the standard AES S-box and Rcon constants,
and the reported emulator verification matches the official FIPS-197
AES-128 known-answer test.

------------------------------------------------------------------------

## 1. File Identification

  -------------------------------------------------------------------------------------------------------------------------------------------------------------
  Property                                                                      `base.bin`                                                            `aes.bin`
  ------------------- -------------------------------------------------------------------- --------------------------------------------------------------------
  Size                                                                         32768 bytes                                                          32768 bytes

  Size in KiB                                                                       32 KiB                                                               32 KiB

  SHA-256               `572d6ee4f8924977698da355225cb428720e3cc5add262a9b630f17f05ac2a3c`   `97e776614b2369b2fb8354cdebc8e2c2d6b2e5b981a16f4b5bbc8cbd3c044ab6`

  Architecture                                                                       ARM32                                                                ARM32

  Endianness                                                                 Little-endian                                                        Little-endian

  Instruction style                                                                  Thumb                                                                Thumb

  Firmware role                                                           Baseline/control                                                           AES target
  -------------------------------------------------------------------------------------------------------------------------------------------------------------

Both files are fixed-size/truncated firmware artifacts. The ELF metadata
is present, but the supplied images do not provide a complete usable
section/symbol table; consequently, analyst-assigned function names and
raw addresses are used throughout the reverse engineering.

------------------------------------------------------------------------

## 2. Memory Layout and Vector Table

The firmware uses the following inferred memory map:

``` text
Flash:          0x08000000 ...
RAM:            0x20000000 ...
Vector table:   0x08004000
Initial MSP:    0x2000A000
```

### Initial Stack Pointer

At `0x08004000`, both binaries contain:

``` text
00 A0 00 20
```

which is little-endian:

``` text
0x2000A000
```

Therefore:

``` text
Initial stack pointer = 0x2000A000
```

### Reset vector --- `base.bin`

Raw vector entry:

``` text
0x0800527D
```

Bit 0 indicates Thumb state on Cortex-M. Clearing it gives:

``` text
0x0800527C
```

Therefore:

``` text
base.bin reset handler = 0x0800527C
```

### Reset vector --- `aes.bin`

Raw vector entry:

``` text
0x08005581
```

Clearing the Thumb bit:

``` text
0x08005580
```

Therefore:

``` text
aes.bin reset handler = 0x08005580
```

------------------------------------------------------------------------

## 3. Firmware Startup / Boot Flow

The common startup sequence reconstructed from the disassembly is:

1.  Reset vector transfers control to startup code.
2.  Initialized `.data` is copied from flash into RAM.
3.  `.bss` is cleared.
4.  C runtime initialization executes.
5.  `main()` is called.
6.  Clock/peripheral configuration is performed.
7.  UART and GPIO/trigger hardware are initialized.
8.  Serial commands are registered.
9.  The firmware enters the polling serial receive loop.

Reported application entry points:

``` text
base.bin main() = 0x080041EC
aes.bin  main() = 0x08004258
```

`aes.bin` additionally initializes the AES state/key schedule before
entering the normal command-processing loop.

------------------------------------------------------------------------

## 4. Hardware Inferences

The disassembly contains register constants consistent with:

``` text
USART1
PA9 / PA10
38400 baud
PA12 trigger output
```

These should be described as **reverse-engineering inferences**, not
absolute hardware facts, because the exact MCU/datasheet mapping was not
independently checked.

High-confidence observations are that the firmware has:

-   a UART/serial interface;
-   a GPIO trigger;
-   clock configuration;
-   an ARM Cortex-M-style vector table.

The observed behaviour is strongly consistent with an STM32-class
target.

------------------------------------------------------------------------

## 5. Serial Protocol

The firmware implements a SimpleSerial-like protocol.

The conceptual packet is:

``` text
<command byte><hex encoded data><newline>
```

Handlers can return data using:

``` text
r<hex data>
```

and the transaction ends with:

``` text
z<2 hexadecimal status digits>
```

The receive mechanism is polling-based and includes a timeout reported
by the disassembly as approximately five seconds.

------------------------------------------------------------------------

## 6. Command Dispatch

The reconstructed command lookup table is around:

``` text
0x2000001C
```

The table supports up to approximately 16 entries.

Each entry contains information corresponding to:

-   command character;
-   expected input length;
-   handler pointer;
-   flags/control information.

This table is shared conceptually by the baseline and AES firmware.

------------------------------------------------------------------------

## 7. Command Comparison

  -------------------------------------------------------------------------
  Command                         Length `base.bin`        `aes.bin`
  ---------------- --------------------- ----------------- ----------------
  `v`                                  0 Version-related   Same
                                         command           

  `w`                                  0 Lists commands    Same

  `y`                                  0 Counts commands   Same

  `k`                                 16 No cryptographic  Loads and
                                         action            expands AES key

  `p`                                 16 Trigger + echo    Trigger + AES
                                         input             encryption +
                                                           ciphertext

  `x`                                  0 Reset/no-op       Same
                                         behaviour         

  `m`                                 18 Not present       Empty stub

  `s`                                  2 Not present       Sets repeat
                                                           count

  `f`                                 16 Not present       Performs
                                                           repeated
                                                           encryption
  -------------------------------------------------------------------------

The important architectural difference is that `aes.bin` adds
cryptographic command handlers while retaining the common serial
infrastructure.

------------------------------------------------------------------------

# 8. `base.bin` --- Baseline Firmware

`base.bin` contains the common firmware infrastructure:

-   clock initialization;
-   UART setup;
-   GPIO setup;
-   trigger control;
-   serial receive;
-   command registration;
-   command lookup/dispatch;
-   result/status transmission.

It does not contain the AES implementation identified in `aes.bin`.

For the `p` command, the baseline firmware performs trigger activity and
echoes the input instead of performing AES encryption.

This makes it useful as a control/baseline image.

------------------------------------------------------------------------

# 9. `aes.bin` --- Cryptographic Firmware

`aes.bin` retains the baseline architecture and adds:

-   AES-128 key storage;
-   AES-128 key expansion;
-   AES S-box;
-   AES Rcon;
-   AES round transformations;
-   encryption routine;
-   runtime key loading;
-   repeated encryption;
-   trigger-controlled cryptographic execution.

The cryptographic implementation is conventional byte-oriented software
AES.

------------------------------------------------------------------------

# 10. Recovered AES-128 Key

The most important finding is the embedded AES key.

### Exact location

``` text
File offset:     0x563F
Virtual address: 0x0800563F
Length:          16 bytes / 128 bits
```

### Raw bytes

``` text
2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C
```

### Hex

``` text
2B7E151628AED2A6ABF7158809CF4F3C
```

### Python

``` python
key = bytes.fromhex(
    "2b7e151628aed2a6abf7158809cf4f3c"
)
```

This is the standard FIPS-197 AES-128 example key.

------------------------------------------------------------------------

# 11. Why the Key Identification Is Conclusive

Several independent observations support the identification.

### AES key size

The recovered value is exactly 16 bytes:

``` text
16 × 8 = 128 bits
```

### Canonical FIPS-197 value

The exact value is:

``` text
2B7E151628AED2A6ABF7158809CF4F3C
```

which is the standard AES-128 example key.

### AES S-box nearby

The standard AES S-box occurs in `aes.bin`, beginning:

``` text
63 7C 77 7B F2 6B 6F C5 ...
```

The S-box was located around:

``` text
0x565A
```

### AES Rcon nearby

The AES round constants are also present, beginning:

``` text
01 02 04 08 10 20 40 80 1B 36
```

around:

``` text
0x575B
```

### AES code exists

The firmware contains the expected key expansion and AES encryption
routines.

Therefore, the 16-byte value is not simply a coincidental constant.

------------------------------------------------------------------------

# 12. AES Key Expansion

The supplied disassembly identifies the key expansion routine at:

``` text
0x0800533C
```

AES-128 expands:

``` text
16-byte master key
```

into:

``` text
11 × 16-byte round keys
```

for:

``` text
176 bytes total
```

The expected operations are:

``` text
RotWord
SubWord
Rcon
XOR
```

The supplied emulator analysis additionally reports that round key 10
matched the expected AES-128 key schedule.

------------------------------------------------------------------------

# 13. AES Core Functions

The supplied reverse engineering identifies:

  Function                           Address
  --------------------------- --------------
  Key expansion                 `0x0800533C`
  AddRoundKey                   `0x080053E8`
  SubBytes                      `0x0800541C`
  ShiftRows                     `0x0800544C`
  `xtime` / GF(2⁸) doubling     `0x08005488`
  AES encryption                `0x0800549C`

These labels are analyst-assigned because original source symbols are
not available.

------------------------------------------------------------------------

# 14. AES Round Structure

The implementation follows standard AES-128:

### Initial operation

``` text
AddRoundKey
```

### Rounds 1--9

``` text
SubBytes
ShiftRows
MixColumns
AddRoundKey
```

### Final round

``` text
SubBytes
ShiftRows
AddRoundKey
```

The final AES round correctly omits MixColumns.

------------------------------------------------------------------------

# 15. AES S-box

The implementation contains the standard AES S-box.

Beginning:

``` text
63 7C 77 7B F2 6B 6F C5
30 01 67 2B FE D7 AB 76
...
```

The table is around:

``` text
aes.bin + 0x565A
```

Its presence strongly confirms the AES implementation.

------------------------------------------------------------------------

# 16. AES Rcon

The key schedule uses the standard AES round constants:

``` text
01
02
04
08
10
20
40
80
1B
36
```

The table is around:

``` text
aes.bin + 0x575B
```

These values are used by AES-128 key expansion.

------------------------------------------------------------------------

# 17. GF(2⁸) Arithmetic / `xtime`

The implementation contains an `xtime`-style helper at:

``` text
0x08005488
```

AES operates in GF(2⁸) using the irreducible polynomial:

``` text
x^8 + x^4 + x^3 + x + 1
```

commonly represented by:

``` text
0x11B
```

and reduced in the byte implementation using:

``` text
0x1B
```

This is consistent with the MixColumns operation.

------------------------------------------------------------------------

# 18. AES Encryption Routine

The supplied analysis identifies the encryption routine at:

``` text
0x0800549C
```

It implements the expected AES sequence:

``` text
Initial AddRoundKey
       ↓
Rounds 1–9:
  SubBytes
  ShiftRows
  MixColumns
  AddRoundKey
       ↓
Round 10:
  SubBytes
  ShiftRows
  AddRoundKey
```

The implementation is plain software AES and shows no identified masking
or other obvious side-channel countermeasure.

------------------------------------------------------------------------

# 19. FIPS-197 Known-Answer Test

The recovered key is:

``` text
2B7E151628AED2A6ABF7158809CF4F3C
```

The standard FIPS-197 plaintext is:

``` text
3243F6A8885A308D313198A2E0370734
```

Expected ciphertext:

``` text
3925841D02DC09FBDC118597196A0B32
```

The supplied emulator verification produced exactly:

``` text
3925841D02DC09FBDC118597196A0B32
```

The supplied analysis also reports that round key 10 matched the
expected FIPS-197 key schedule.

This provides strong functional confirmation that the identified
implementation is AES-128 and that the recovered key is correct.

------------------------------------------------------------------------

# 20. `k` --- Runtime Key Loading

The AES firmware provides a 16-byte `k` command.

Conceptually:

``` text
k <16-byte key>
```

The handler:

1.  receives the key;
2.  stores it;
3.  expands it into the AES round-key schedule.

Thus the firmware supports runtime key replacement.

The hard-coded key recovered from the image is the default key.

------------------------------------------------------------------------

# 21. `p` --- Single Encryption

The AES firmware provides a 16-byte `p` command.

The reconstructed execution sequence is:

``` text
receive plaintext
      ↓
trigger HIGH
      ↓
AES encryption
      ↓
trigger LOW
      ↓
return ciphertext
      ↓
return status
```

This explicit trigger boundary is important because it gives an external
measurement window around the AES operation.

------------------------------------------------------------------------

# 22. `s` --- Repeat Count

The AES firmware provides an `s` command accepting two bytes.

The supplied reverse engineering identifies the value as a big-endian
16-bit repeat count:

``` text
repeat_count = uint16_be(input)
```

This value controls the number of subsequent AES operations.

------------------------------------------------------------------------

# 23. `f` --- Repeated Encryption

The AES firmware provides an `f` command accepting 16 bytes.

It repeatedly encrypts the supplied input according to the count
configured with `s`.

Conceptually:

``` text
TRIGGER HIGH

AES
AES
AES
...
AES

TRIGGER LOW
```

This is useful for producing repeated cryptographic activity inside a
controlled measurement window.

------------------------------------------------------------------------

# 24. Why the Two-Firmware Design Matters

The two binaries form a useful differential-analysis pair.

### `base.bin`

``` text
UART
clock
GPIO
trigger
command parser
```

### `aes.bin`

``` text
UART
clock
GPIO
trigger
command parser
+
AES
+
AES key
+
AES commands
```

The common infrastructure reduces differences unrelated to AES.

This is consistent with a laboratory setup where an analyst wants to
compare:

``` text
baseline execution
```

against:

``` text
baseline + AES execution
```

for power/side-channel measurements.

------------------------------------------------------------------------

# 25. Side-Channel / Fault-Injection Relevance

Several design choices strongly support an embedded cryptography
training use case:

-   conventional table-based AES;
-   fixed/default embedded key;
-   controllable plaintext;
-   explicit trigger GPIO;
-   repeat count;
-   repeated AES command;
-   separate baseline firmware.

The firmware therefore provides a convenient target for:

-   power analysis;
-   correlation power analysis;
-   differential power analysis;
-   fault-injection experiments;
-   embedded crypto reverse engineering.

No masking, randomized S-box, bitsliced implementation, or other obvious
software side-channel countermeasure was identified in the supplied
analysis.

------------------------------------------------------------------------

# 26. Likely Origin

The behaviour is strongly consistent with
ChipWhisperer/SimpleSerial-style training firmware.

Supporting evidence:

-   single-character commands;
-   hex-encoded data;
-   `r` result prefix;
-   `z` status response;
-   trigger-controlled AES execution;
-   separate baseline/target firmware;
-   repeated encryption functionality.

However, exact provenance is an inference. The stripped/truncated
firmware does not retain enough source metadata to prove the exact
project/device without external source comparison.

Recommended wording:

> The firmware behaviour is strongly consistent with ChipWhisperer
> SimpleSerial-style STM32 training firmware, but exact provenance
> cannot be proven from the supplied stripped/truncated binaries alone.

------------------------------------------------------------------------

# 27. Other Files in the Archive

### `a.out`

A 64-bit x86-64 executable associated with the simple test program.

It is unrelated to the ARM AES firmware.

### `test.c`

Simple C source for the unrelated test executable.

### `notes`

Linux shared-library/tutorial material.

### `README.md`

Repository boilerplate/documentation.

None of these files form part of the AES implementation.

------------------------------------------------------------------------

# 28. Confirmed Findings

The following are directly supported by the uploaded binaries:

-   ARM32 ELF format.
-   Little-endian ARM.
-   32 KiB size for both firmware files.
-   Vector table at `0x08004000`.
-   Initial MSP `0x2000A000`.
-   `base.bin` raw reset vector `0x0800527D` → Thumb address
    `0x0800527C`.
-   `aes.bin` raw reset vector `0x08005581` → Thumb address
    `0x08005580`.
-   AES key exists at `aes.bin+0x563F`.
-   Exact key: `2B7E151628AED2A6ABF7158809CF4F3C`.
-   AES S-box exists in `aes.bin`.
-   AES Rcon exists in `aes.bin`.
-   The key is absent from `base.bin`.
-   AES-specific constant material is absent from the baseline firmware.

------------------------------------------------------------------------

# 29. Findings Supported by Disassembly and Emulation

The supplied reverse-engineering work additionally establishes:

-   `main()` locations.
-   Startup `.data`/`.bss` flow.
-   UART polling behaviour.
-   Serial command dispatch.
-   Command-table structure.
-   `k`, `p`, `s`, and `f` semantics.
-   AES key-expansion routine.
-   AES primitive addresses.
-   Trigger placement.
-   FIPS-197 ciphertext verification.
-   Round-key-10 verification.

These findings agree with the binary-level evidence.

------------------------------------------------------------------------

# 30. Findings That Should Remain Qualified

The following are reasonable but should be described as inferences
unless separately validated:

-   Exact ChipWhisperer provenance.
-   Exact STM32F3 part number.
-   Exact USART/pin mapping.
-   Exact 38400-baud configuration.
-   Approximate application-code size.
-   Original compiler/source-level function names.

This distinction makes the report technically stronger and avoids
presenting reverse-engineering hypotheses as direct facts.

------------------------------------------------------------------------

# 31. Final Challenge Finding

The primary cryptographic secret recovered from the firmware is:

``` text
AES-128 KEY

2B7E151628AED2A6ABF7158809CF4F3C
```

Location:

``` text
aes.bin + 0x563F
```

Virtual address:

``` text
0x0800563F
```

Size:

``` text
16 bytes / 128 bits
```

------------------------------------------------------------------------

# 32. Final Technical Conclusion

`base.bin` and `aes.bin` are two versions of the same embedded ARM
firmware architecture.

``` text
                     Firmware Pair
                          |
             +------------+------------+
             |                         |
             v                         v
         base.bin                  aes.bin
             |                         |
             |                         +-- AES-128
             |                         +-- Key expansion
             |                         +-- S-box
             |                         +-- Rcon
             |                         +-- Embedded key
             |                         +-- k command
             |                         +-- p command
             |                         +-- s command
             |                         +-- f command
             |
             +-- UART
             +-- Clock
             +-- GPIO
             +-- Trigger
             +-- Command parser
```

The recovered key is:

``` text
2B7E151628AED2A6ABF7158809CF4F3C
```

The AES implementation is functionally consistent with AES-128 because
the FIPS-197 known-answer test produces:

``` text
Plaintext:
3243F6A8885A308D313198A2E0370734

Key:
2B7E151628AED2A6ABF7158809CF4F3C

Ciphertext:
3925841D02DC09FBDC118597196A0B32
```

Therefore the challenge's cryptographic target is conclusively
identified as a conventional AES-128 firmware implementation, with the
embedded default key recovered from `aes.bin`.

------------------------------------------------------------------------

# 33. Suggested Reproduction Workflow

For a complete independent reproduction:

1.  Load `base.bin` and `aes.bin` into Ghidra as ARM/Thumb firmware.
2.  Set the image base to `0x08000000`.
3.  Inspect the vector table at `0x08004000`.
4.  Set the reset handlers to:
    -   `0x0800527C` for `base.bin`;
    -   `0x08005580` for `aes.bin`.
5.  Recover the command dispatch table around `0x2000001C`.
6.  Trace the AES `k` handler.
7.  Follow the key into `0x0800533C`.
8.  Trace the encryption command `p`.
9.  Trace `s` and `f`.
10. Extract the key from `aes.bin+0x563F`.
11. Verify the AES S-box and Rcon.
12. Run the FIPS-197 known-answer test.
13. Compare baseline and AES execution traces.

This workflow provides both static and dynamic confirmation of the
analysis.

------------------------------------------------------------------------

# 34. Final Answer / Key Finding

**Baseline:**

``` text
base.bin
```

**AES target:**

``` text
aes.bin
```

**Algorithm:**

``` text
AES-128
```

**Recovered default key:**

``` text
2B7E151628AED2A6ABF7158809CF4F3C
```

**Key location:**

``` text
aes.bin + 0x563F
```

**Reset handlers:**

``` text
base.bin = 0x0800527C
aes.bin  = 0x08005580
```

**Initial stack:**

``` text
0x2000A000
```

**Vector table:**

``` text
0x08004000
```

**FIPS-197 verification:**

``` text
Key:
2B7E151628AED2A6ABF7158809CF4F3C

Plaintext:
3243F6A8885A308D313198A2E0370734

Ciphertext:
3925841D02DC09FBDC118597196A0B32
```

## Overall Conclusion

`base.bin` is the baseline/control firmware. `aes.bin` is the
cryptographic target containing a conventional AES-128 implementation,
embedded default key, runtime key loading, single encryption, repeated
encryption, and trigger-controlled execution. The recovered key and AES
implementation are independently consistent with the FIPS-197
specification and the supplied emulator results.
