# ghidra-tlcs900h

Ghidra processor module for Toshiba TLCS-900/H

## Status

Work in progress:

* Instruction set should be fully disassembled, if you notice anything missing, please open an issue / pull request!
    * Note: Disassemblers usually disagree on presentation / ambiguity:
        * Disabled interrupts: `di` vs. `ei 0x07`;
        * Mnemonic qualifiers for word/long sized operands: `sll` vs. `sllw`;
        * Flag shown for conditional instructions: `jp NZ,XWA` vs. `jp NE,XWA`;
        * Destination register shown when result storage space is larger than loaded values: `mul A,(XWA)` vs. `mul WA,(XWA)`;
* Semantics are mostly done, and are now being thoroughly tested through pcode emulation.

## Examples

See [ghidra\-neogeopocket\-loader](https://github.com/nevesnunes/ghidra-neogeopocket-loader).
