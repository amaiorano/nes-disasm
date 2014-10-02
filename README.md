# nes-disasm

A command line disassembler for NES roms written in C++

# Example

    > nes-disasm "roms\Donkey Kong (JU).nes"

Output:

    ; nes-disasm - Disassembler for NES roms
    ; Author: Antonio Maiorano (amaiorano at gmail dot com)
    ; Source code available at http://github.com/amaiorano/nes-disasm/
    
    ; Input file: roms\Donkey Kong (JU).nes
    ; PRG ROM size: 16384 bytes
    ; CHR ROM size: 8192 bytes
    ; Mapper number: 0
    ; Has SRAM: no
    
    $8000	207006 	JSR $0670
    $8003	00   	BRK 
    $8004	206406 	JSR $0664
    $8007	00   	BRK 
    $8008	207806 	JSR $0678
    $800B	00   	BRK 
    $800C	20B704 	JSR $04B7
    $800F	00   	BRK 
    $8010	20BC01 	JSR $01BC
    $8013	00   	BRK 
    $8014	0108  	ORA ($08,X)
    $8016	08  	.byte $02
    $8017	08   	PHP 
    $8018	00  	.byte $02
    $8019	00   	BRK 
    $801A	0501  	ORA $01
    $801C	00   	BRK 
    ...
