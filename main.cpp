#include <cstdio>
#include <memory>
#include <cassert>
#include <string>
#include <cstdarg>

typedef unsigned char uint8;
typedef char int8;
typedef unsigned short uint16;
typedef short int16;
typedef unsigned int uint32;
typedef int int32;
static_assert(sizeof(uint8)==1, "Invalid type size");
static_assert(sizeof(int8)==1, "Invalid type size");
static_assert(sizeof(uint16)==2, "Invalid type size");
static_assert(sizeof(int16)==2, "Invalid type size");
static_assert(sizeof(uint32)==4, "Invalid type size");
static_assert(sizeof(int32)==4, "Invalid type size");

#define KB(n) (n*1024)
#define MB(n) (n*1024*1024)

#define ARRAYSIZE(arr) (sizeof(arr)/sizeof(arr[0]))

template <typename N> struct CTPrintSize;

template <int MaxLength = 1024>
struct FormatString
{
	FormatString(const char* format, ...)
	{
		va_list args;
		va_start(args, format);
		vsnprintf(buffer, MaxLength, format, args);
		va_end(args);
	}

	const char* Value() const { return buffer; }

	operator const char*() const { return Value(); }

	char buffer[MaxLength];
};

class FileStream
{
public:
	FileStream() : m_pFile(nullptr)
	{
	}
	
	~FileStream()
	{
		Close();
	}

	FileStream(const char* name, const char* mode) : m_pFile(nullptr)
	{
		if (!Open(name, mode))
			throw std::exception(FormatString<>("Failed to open file: %s", name));
	}

	bool Open(const char* name, const char* mode)
	{
		Close();
		m_pFile = fopen(name, mode);
		return m_pFile != nullptr;
	}

	void Close()
	{
		if (m_pFile)
		{
			fclose(m_pFile);
			m_pFile = nullptr;
		}
	}

	template <typename T>
	bool Read(T* pDestBuffer, int count = 1)
	{
		return fread(pDestBuffer, sizeof(T), count, m_pFile) == (sizeof(T) * count);
	}

private:
	FILE* m_pFile;
};

enum class ScreenArrangement
{
	Vertical,		// Horizontal mirroring (CIRAM A10 = PPU A11)
	Horizontal,		// Vertical mirroring (CIRAM A10 = PPU A10)
	FourScreen		// Four-screen VRAM
};

#pragma pack(1)
struct RomHeader
{
	uint8 name[4];
	uint8 prgRomUnits; // in 16kb units
	uint8 chrRomUnits; // in 8 kb units (if 0, board uses CHR RAM)
	uint8 flags6;
	uint8 flags7;
	uint8 prgRamUnits; // in 8kb units *IGNORE*: Recently added to spec, most roms don't have this set
	uint8 flags9;
	uint8 flags10; // Unofficial
	uint8 zero[5]; // Should all be 0

	size_t GetPrgRomSizeBytes() const
	{
		return prgRomUnits * KB(16);
	}

	// If 0, board uses CHR RAM
	size_t GetChrRomSizeBytes() const
	{
		return chrRomUnits * KB(8);
	}

	ScreenArrangement GetScreenArrangement() const
	{
		if (flags6 & 0x80)
			return ScreenArrangement::FourScreen;

		return (flags6 & 0x01)==1? ScreenArrangement::Horizontal : ScreenArrangement::Vertical;
	}

	uint8 GetMapperNumber() const
	{
		const uint8 result = ((flags7 & 0xF0) << 4) | (flags6 & 0xF0);
		return result;
	}

	// SRAM in CPU $6000-$7FFF, if present, is battery backed
	bool HasSRAM() const
	{
		return (flags6 & 0x02) != 0;
	}

	bool HasTrainer() const
	{
		return (flags6 & 0x04) != 0;
	}

	bool IsVSUnisystem() const
	{
		return (flags7 & 0x01) != 0;
	}

	// 8KB of Hint Screen data stored after CHR data
	bool IsPlayChoice10() const
	{
		return (flags7 & 0x02) != 0;
	}

	bool IsNES2Header() const
	{
		return (flags7 & 0xC0) == 2;
	}

	bool IsValidHeader() const
	{
		if (memcmp((const char*)name, "NES\x1A", 4) != 0)
			return false;

		// A general rule of thumb: if the last 4 bytes are not all zero, and the header is not marked for
		// NES 2.0 format, an emulator should either mask off the upper 4 bits of the mapper number or simply
		// refuse to load the ROM.
		if ( (zero[1]!=0 || zero[2]!=0 || zero[3]!=0 || zero[4]!=0) && IsNES2Header() )
			return false;

		return true;
	}
};
static_assert(sizeof(RomHeader)==16, "RomHeader must be 16 bytes");

enum eAddressMode
{
	Immedt,	// Immediate : #value
	Implid,	// Implied : no operand
	Accumu,	// Accumulator : no operand
	Relatv, // Relative : $addr8 used with branch instructions
	ZeroPg,	// Zero Page : $addr8
	ZPIdxX,	// Zero Page Indexed with X : $addr8 + X
	ZPIdxY, // Zero Page Indexed with Y : $addr8 + Y
	Absolu, // Absolute : $addr16
	AbIdxX, // Absolute Indexed with X : $addr16 + X
	AbIdxY, // Absolute Indexed with Y : $addr16 + Y
	Indrct, // Indirect : ($addr8) used only with JMP
	IdxInd, // Indexed with X Indirect : ($addr8 + X)
	IndIdx, // Indirect Indexed with Y : ($addr8) + Y
};

struct OpCodeEntry
{
	uint8 opCode;
	uint8 numBytes;
	uint8 numCycles;
	eAddressMode addrMode;
	const char* formatString;
};

void ValidateOpCodeTable(OpCodeEntry opCodeTable[], size_t numEntries);

#define ADDR_8 "$%02X"
#define ADDR_16 "$%04X"

OpCodeEntry** GetOpCodeTable()
{
	static OpCodeEntry opCodeTable[] =
	{
		{ 0x69, 2, 2, Immedt, "ADC #"ADDR_8 },
		{ 0x65, 2, 3, ZeroPg, "ADC "ADDR_8 },
		{ 0x75, 2, 4, ZPIdxX, "ADC "ADDR_8",X" },
		{ 0x6D, 3, 4, Absolu, "ADC "ADDR_16 },
		{ 0x7D, 3, 4, AbIdxX, "ADC "ADDR_16",X" },
		{ 0x79, 3, 4, AbIdxY, "ADC "ADDR_16",Y" },
		{ 0x61, 2, 6, IdxInd, "ADC ("ADDR_8",X)" },
		{ 0x71, 2, 5, IndIdx, "ADC ("ADDR_8"),Y" },

		{ 0x29, 2, 2, Immedt, "AND #"ADDR_8 },
		{ 0x25, 2, 3, ZeroPg, "AND "ADDR_8 },
		{ 0x35, 2, 4, ZPIdxX, "AND "ADDR_8",X" },
		{ 0x2D, 3, 4, Absolu, "AND "ADDR_16 },
		{ 0x3D, 3, 4, AbIdxX, "AND "ADDR_16",X" },
		{ 0x39, 3, 4, AbIdxY, "AND "ADDR_16",Y" },
		{ 0x21, 2, 6, IdxInd, "AND ("ADDR_8",X)" },
		{ 0x31, 2, 5, IndIdx, "AND ("ADDR_8"),Y" },

		{ 0x0A, 1, 2, Accumu, "ASL A" },
		{ 0x06, 2, 5, ZeroPg, "ASL "ADDR_8 },
		{ 0x16, 2, 6, ZPIdxX, "ASL "ADDR_8",X" },
		{ 0x0E, 3, 6, Absolu, "ASL "ADDR_16 },
		{ 0x1E, 3, 7, AbIdxX, "ASL "ADDR_16",X" },

		{ 0x90, 2, 2, Relatv, "BCC "ADDR_8 },
		
		{ 0xB0, 2, 2, Relatv, "BCS "ADDR_8 },
		
		{ 0xF0, 2, 2, Relatv, "BEQ "ADDR_8 },

		{ 0x24, 2, 3, ZeroPg, "BIT "ADDR_8 },
		{ 0x2C, 3, 4, Absolu, "BIT "ADDR_16 },

		{ 0x30, 2, 2, Relatv, "BMI "ADDR_8 },

		{ 0xD0, 2, 2, Relatv, "BNE "ADDR_8 },

		{ 0x10, 2, 2, Relatv, "BPL "ADDR_8 },

		{ 0x00, 1, 7, Implid, "BRK" },

		{ 0x50, 2, 2, Relatv, "BVC "ADDR_8 },

		{ 0x70, 2, 2, Relatv, "BVS "ADDR_8 },

		{ 0x18, 1, 2, Implid, "CLC" },

		{ 0xD8, 1, 2, Implid, "CLD" },

		{ 0x58, 1, 2, Implid, "CLI" },

		{ 0xB8, 1, 2, Implid, "CLV" },

		{ 0xC9, 2, 2, Immedt, "CMP #"ADDR_8 },
		{ 0xC5, 2, 3, ZeroPg, "CMP "ADDR_8 },
		{ 0xD5, 2, 4, ZPIdxX, "CMP "ADDR_8",X" },
		{ 0xCD, 3, 4, Absolu, "CMP "ADDR_16 },
		{ 0xDD, 3, 4, AbIdxX, "CMP "ADDR_16",X" },
		{ 0xD9, 3, 4, AbIdxY, "CMP "ADDR_16",Y" },
		{ 0xC1, 2, 6, IdxInd, "CMP ("ADDR_8",X)" },
		{ 0xD1, 2, 5, IndIdx, "CMP ("ADDR_8"),Y" },

		{ 0xE0, 2, 2, Immedt, "CPX #"ADDR_8 },
		{ 0xE4, 2, 3, ZeroPg, "CPX "ADDR_8 },
		{ 0xEC, 3, 4, Absolu, "CPX "ADDR_16 },

		{ 0xC0, 2, 2, Immedt, "CPY #"ADDR_8 },
		{ 0xC4, 2, 3, ZeroPg, "CPY "ADDR_8 },
		{ 0xCC, 3, 4, Absolu, "CPY "ADDR_16 },

		{ 0xC6, 2, 5, ZeroPg, "DEC "ADDR_8 },
		{ 0xD6, 2, 6, ZPIdxX, "DEC "ADDR_8",X" },
		{ 0xCE, 3, 6, Absolu, "DEC "ADDR_16 },
		{ 0xDE, 3, 7, AbIdxX, "DEC "ADDR_16",X" },

		{ 0xCA, 1, 2, Implid, "DEX" },

		{ 0x88, 1, 2, Implid, "DEY" },

		{ 0x49, 2, 2, Immedt, "EOR #"ADDR_8 },
		{ 0x45, 2, 3, ZeroPg, "EOR "ADDR_8 },
		{ 0x55, 2, 4, ZPIdxX, "EOR "ADDR_8",X" },
		{ 0x4D, 3, 4, Absolu, "EOR "ADDR_16 },
		{ 0x5D, 3, 4, AbIdxX, "EOR "ADDR_16",X" },
		{ 0x59, 3, 4, AbIdxY, "EOR "ADDR_16",Y" },
		{ 0x41, 2, 6, IdxInd, "EOR ("ADDR_8",X)" },
		{ 0x51, 2, 5, IndIdx, "EOR ("ADDR_8"),Y" },

		{ 0xE6, 2, 5, ZeroPg, "INC "ADDR_8 },
		{ 0xF6, 2, 6, ZPIdxX, "INC "ADDR_8",X" },
		{ 0xEE, 3, 6, Absolu, "INC "ADDR_16 },
		{ 0xFE, 3, 7, AbIdxX, "INC "ADDR_16",X" },

		{ 0xE8, 1, 2, Implid, "INX" },

		{ 0xC8, 1, 2, Implid, "INY" },

		{ 0x4C, 3, 3, Absolu, "JMP "ADDR_16 },
		{ 0x6C, 3, 5, Indrct, "JMP ("ADDR_16")" },

		{ 0x20, 3, 6, Absolu, "JSR "ADDR_16 },

		{ 0xA9, 2, 2, Immedt, "LDA #"ADDR_8 },
		{ 0xA5, 2, 3, ZeroPg, "LDA "ADDR_8 },
		{ 0xB5, 2, 4, ZPIdxX, "LDA "ADDR_8",X" },
		{ 0xAD, 3, 4, Absolu, "LDA "ADDR_16 },
		{ 0xBD, 3, 4, AbIdxX, "LDA "ADDR_16",X" },
		{ 0xB9, 3, 4, AbIdxY, "LDA "ADDR_16",Y" },
		{ 0xA1, 2, 6, IdxInd, "LDA ("ADDR_8",X)" },
		{ 0xB1, 2, 5, IndIdx, "LDA ("ADDR_8"),Y" },

		{ 0xA2, 2, 2, Immedt, "LDX #"ADDR_8 },
		{ 0xA6, 2, 3, ZeroPg, "LDX "ADDR_8 },
		{ 0xB6, 2, 4, ZPIdxY,  "LDX "ADDR_8",Y" },
		{ 0xAE, 3, 4, Absolu, "LDX "ADDR_16 },
		{ 0xBE, 3, 4, AbIdxY, "LDX "ADDR_16",Y" },

		{ 0xA0, 2, 2, Immedt, "LDY #"ADDR_8 },
		{ 0xA4, 2, 3, ZeroPg, "LDY "ADDR_8 },
		{ 0xB4, 2, 4, ZPIdxX, "LDY "ADDR_8",X" },
		{ 0xAC, 3, 4, Absolu, "LDY "ADDR_16 },
		{ 0xBC, 3, 4, AbIdxX, "LDY "ADDR_16",X" },

		{ 0x4A, 1, 2, Accumu, "LSR A" },
		{ 0x46, 2, 5, ZeroPg, "LSR "ADDR_8 },
		{ 0x56, 2, 6, ZPIdxX, "LSR "ADDR_8",X" },
		{ 0x4E, 3, 6, Absolu, "LSR "ADDR_16 },
		{ 0x5E, 3, 7, AbIdxX, "LSR "ADDR_16",X" },

		{ 0xEA, 1, 2, Implid, "NOP" },

		{ 0x09, 2, 2, Immedt, "ORA #"ADDR_8 },
		{ 0x05, 2, 3, ZeroPg, "ORA "ADDR_8 },
		{ 0x15, 2, 4, ZPIdxX, "ORA "ADDR_8",X" },
		{ 0x0D, 3, 4, Absolu, "ORA "ADDR_16 },
		{ 0x1D, 3, 4, AbIdxX, "ORA "ADDR_16",X" },
		{ 0x19, 3, 4, AbIdxY, "ORA "ADDR_16",Y" },
		{ 0x01, 2, 6, IdxInd, "ORA ("ADDR_8",X)" },
		{ 0x11, 2, 5, IndIdx, "ORA ("ADDR_8"),Y" },

		{ 0x48, 1, 3, Implid, "PHA" },

		{ 0x08, 1, 3, Implid, "PHP" },

		{ 0x68, 1, 4, Implid, "PLA" },

		{ 0x28, 1, 4, Implid, "PLP" },

		{ 0x2A, 1, 2, Accumu, "ROL A" },
		{ 0x26, 2, 5, ZeroPg, "ROL "ADDR_8 },
		{ 0x36, 2, 6, ZPIdxX, "ROL "ADDR_8",X" },
		{ 0x2E, 3, 6, Absolu, "ROL "ADDR_16 },
		{ 0x3E, 3, 7, AbIdxX, "ROL "ADDR_16",X" },

		{ 0x6A, 1, 2, Accumu, "ROR A" },
		{ 0x66, 2, 5, ZeroPg, "ROR "ADDR_8 },
		{ 0x76, 2, 6, ZPIdxX, "ROR "ADDR_8",X" },
		{ 0x6E, 3, 6, Absolu, "ROR "ADDR_16 },
		{ 0x7E, 3, 7, AbIdxX, "ROR "ADDR_16",X" },

		{ 0x40, 1, 6, Implid, "RTI" },

		{ 0x60, 1, 6, Implid, "RTS" },

		{ 0xE9, 2, 2, Immedt, "SBC #"ADDR_8 },
		{ 0xE5, 2, 3, ZeroPg, "SBC "ADDR_8 },
		{ 0xF5, 2, 4, ZPIdxX, "SBC "ADDR_8",X" },
		{ 0xED, 3, 4, Absolu, "SBC "ADDR_16 },
		{ 0xFD, 3, 4, AbIdxX, "SBC "ADDR_16",X" },
		{ 0xF9, 3, 4, AbIdxY, "SBC "ADDR_16",Y" },
		{ 0xE1, 2, 6, IdxInd, "SBC ("ADDR_8",X)" },
		{ 0xF1, 2, 5, IndIdx, "SBC ("ADDR_8"),Y" },

		{ 0x38, 1, 2, Implid, "SEC" },

		{ 0xF8, 1, 2, Implid, "SED" },

		{ 0x78, 1, 2, Implid, "SEI" },

		{ 0x85, 2, 3, ZeroPg, "STA "ADDR_8 },
		{ 0x95, 2, 4, ZPIdxX, "STA "ADDR_8",X" },
		{ 0x8D, 3, 4, Absolu, "STA "ADDR_16 },
		{ 0x9D, 3, 5, AbIdxX, "STA "ADDR_16",X" },
		{ 0x99, 3, 5, AbIdxY, "STA "ADDR_16",Y" },
		{ 0x81, 2, 6, IdxInd, "STA ("ADDR_8",X)" },
		{ 0x91, 2, 6, IndIdx, "STA ("ADDR_8"),Y" },

		{ 0x86, 2, 3, ZeroPg, "STX "ADDR_8 },
		{ 0x96, 2, 4, ZPIdxY, "STX "ADDR_8",Y" },
		{ 0x8E, 3, 4, Absolu, "STX "ADDR_16 },

		{ 0x84, 2, 3, ZeroPg, "STY "ADDR_8 },
		{ 0x94, 2, 4, ZPIdxX, "STY "ADDR_8",X" },
		{ 0x8C, 3, 4, Absolu, "STY "ADDR_16 },

		{ 0xAA, 1, 2, Implid, "TAX" },

		{ 0xA8, 1, 2, Implid, "TAY" },

		{ 0xBA, 1, 2, Implid, "TSX" },

		{ 0x8A, 1, 2, Implid, "TXA" },

		{ 0x9A, 1, 2, Implid, "TXS" },

		{ 0x98, 1, 2, Implid, "TYA" },
	};

	static OpCodeEntry* opCodeTableOrdered[256];
	static bool initialized = false;
	if (!initialized)
	{
		initialized = true;
		ValidateOpCodeTable(opCodeTable, ARRAYSIZE(opCodeTable));
		
		memset(opCodeTableOrdered, 0, sizeof(opCodeTableOrdered));
		for (size_t i = 0; i < ARRAYSIZE(opCodeTable); ++i)
		{
			const uint8 opCode = opCodeTable[i].opCode;
			
			assert(opCode < ARRAYSIZE(opCodeTableOrdered) && "Ordered table not large enough");
			assert(opCodeTableOrdered[opCode] == 0 && "Error in table: opCode collision");
			
			opCodeTableOrdered[opCode] = &opCodeTable[i];
		}
	}

	return opCodeTableOrdered;
}

void ValidateOpCodeTable(OpCodeEntry opCodeTable[], size_t numEntries)
{
	auto BeginsWith = [] (const std::string& in, const std::string& sub)
	{
		return in.find(sub) == 0;
	};

	auto EndsWith = [] (const std::string& in, const std::string& sub)
	{
		return in.rfind(sub) == in.size() - sub.size();
	};

	for (size_t i = 0; i < numEntries; ++i)
	{
		const OpCodeEntry& entry = opCodeTable[i];
		switch (opCodeTable[i].addrMode)
		{
		case Immedt:
			assert(entry.numBytes == 2);
			assert(entry.formatString[4] == '#');
			break;
		case Implid:
			assert(entry.numBytes == 1);
			assert(strlen(entry.formatString)==3);
			break;
		case Accumu:
			assert(entry.numBytes == 1);
			assert(entry.formatString[4] == 'A' && "Expected Accumulator operand");
			break;
		case Relatv:
			assert(entry.numBytes == 2);
			assert(entry.formatString[0] == 'B' && "Expected Branch instruction");
			break;
		case ZeroPg:
			assert(entry.numBytes == 2);
			break;
		case ZPIdxX:
			assert(entry.numBytes == 2);
			assert(EndsWith(entry.formatString, ",X"));
			break;
		case ZPIdxY:
			assert(entry.numBytes == 2);
			assert(EndsWith(entry.formatString, ",Y"));
			break;
		case Absolu:
			assert(entry.numBytes == 3);
			break;
		case AbIdxX:
			assert(entry.numBytes == 3);
			assert(EndsWith(entry.formatString, ",X"));
			break;
		case AbIdxY:
			assert(entry.numBytes == 3);
			assert(EndsWith(entry.formatString, ",Y"));
			break;
		case Indrct:
			assert(entry.numBytes == 3);
			assert(BeginsWith(entry.formatString, "JMP (") && EndsWith(entry.formatString, ")"));
			break;
		case IdxInd:
			assert(entry.numBytes == 2);
			assert(entry.formatString[4] == '(' && EndsWith(entry.formatString, ",X)"));
			break;
		case IndIdx:
			assert(entry.numBytes == 2);
			assert(entry.formatString[4] == '(' && EndsWith(entry.formatString, "),Y"));
			break;
		}
	}
}

void Disassemble(uint8* pPrgRom, size_t prgRomSize)
{
	OpCodeEntry** ppOpCodeTable = GetOpCodeTable();
	const uint16 startAddress = 0x8000;

	size_t PC = 0;

	while (PC < prgRomSize)
	{
		const uint8 opCode = pPrgRom[PC];
		const OpCodeEntry* pEntry = ppOpCodeTable[opCode];

		// Print PC
		printf(ADDR_16"\t", startAddress + PC);

		if (pEntry == nullptr)
		{
			printf("%02X  \t", pPrgRom[PC+1]);
			printf(".byte "ADDR_8"; Invalid opcode\n", opCode);
			PC += 1;
			continue;
		}

		// Print instruction in hex
		for (int i = 0; i < 4; ++i)
		{
			if (i < pEntry->numBytes)
				printf("%02X", pPrgRom[PC + i]);
			else
				printf(" ");

		}
		printf("\t");

		// TEMP: if this works out, we'll store these in a table and the index in the opcode table
		char opCodeName[4] = {0};
		memcpy(opCodeName, pEntry->formatString, 3);

		// Print opcode name
		printf("%s ", opCodeName);

		// Print operand
		switch (pEntry->addrMode)
		{
		case Immedt:
			{
			const uint8 address = pPrgRom[PC+1];
			printf("#"ADDR_8, address);
			}
			break;

		case Implid:
		case Accumu:
			// No operand to output
			break;

		case Relatv:
			{
			// For branch instructions, resolve the target address and print it in comments
			const int8 offset = pPrgRom[PC+1]; // Signed offset in [-128,127]
			const uint16 target = startAddress + PC + pEntry->numBytes + offset;
			printf(ADDR_8" ; "ADDR_16" (%d)", pPrgRom[PC+1], target, offset);
			//const int8 operand = pPrgRom[PC+1];
			//const int8 sign = (operand & 0x80)? -1 : 1;
			//const int8 offset = (operand & 0x7F);
			//const uint16 target = startAddress + PC + pEntry->numBytes + (sign * offset);
			//printf(ADDR_8" ; "ADDR_16" (%c%d)", pPrgRom[PC+1], target, sign > 0? '+' : '-', offset);
			}
			break;
		
		case ZeroPg:
			{
			const uint8 address = pPrgRom[PC+1];
			printf(ADDR_8, address);
			}
			break;

		case ZPIdxX:
			{
			const uint8 address = pPrgRom[PC+1];
			printf(ADDR_8",X", address);
			}
			break;
		
		case ZPIdxY:
			{
			const uint8 address = pPrgRom[PC+1];
			printf(ADDR_8",Y", address);
			}
			break;

		case Absolu:
			{
			uint16 address = (pPrgRom[PC+2]<<8) | (pPrgRom[PC+1]);
			printf(ADDR_16, address);
			}
			break;

		case AbIdxX:
			{
			uint16 address = (pPrgRom[PC+2]<<8) | (pPrgRom[PC+1]);
			printf(ADDR_16",X", address);
			}
			break;

		case AbIdxY:
			{
			uint16 address = (pPrgRom[PC+2]<<8) | (pPrgRom[PC+1]);
			printf(ADDR_16",Y", address);
			}
			break;

		case Indrct:
			{
			uint16 address = (pPrgRom[PC+2]<<8) | (pPrgRom[PC+1]);
			printf("("ADDR_16")", address);
			}
			break;

		case IdxInd:
			{
			const uint8 address = pPrgRom[PC+1];
			printf("("ADDR_8",X)", address);
			}
			break;

		case IndIdx:
			{
			const uint8 address = pPrgRom[PC+1];
			printf("("ADDR_8"),Y", address);
			}
			break;

		default:
			assert(false && "Invalid addressing mode");
			break;
		}

		printf("\n");
		PC += pEntry->numBytes;
	}

	return;


	//while (PC < prgRomSize)
	//{
	//	const uint8 opcode = pPrgRom[PC];
	//	const OpCodeEntry* pEntry = ppOpCodeTable[opcode];

	//	// Print PC
	//	//printf("%08X:\t", PC);
	//	printf(ADDR_16"\t", startAddress + PC);

	//	
	//	static OpCodeEntry UnknownOpCodeEntry = { 0x00, 1, 0, Immedt, ".byte "ADDR_8"\t; Invalid Opcode!" };
	//	if (pEntry == nullptr)
	//		pEntry = &UnknownOpCodeEntry;

	//	// Print instruction in hex
	//	for (int i = 0; i < pEntry->numBytes; ++i)
	//		printf("%02X", pPrgRom[PC+i]);
	//	for (int i = pEntry->numBytes; i < 3; ++i)
	//		printf("  ");
	//	printf("\t");

	//	/*
	//	if (!pEntry)
	//	{
	//		//static OpCodeEntry unknownOpCode = { 0x00, 2, 0, ".DB "ADDR_8 };
	//		//pEntry = &unknownOpCode;

	//		//printf("%02X\t.DB $%02X\n", pPrgRom[PC], pPrgRom[PC]);
	//		printf("\t.byte "ADDR_8"\t; INVALID OPCODE !!!\n\n", pPrgRom[PC]);
	//		PC += 1;
	//		continue;
	//	}
	//	*/

	//	// Print instruction in asm
	//	const uint8 operandSize = pEntry->numBytes - 1;
	//	switch (operandSize)
	//	{
	//	case 0:
	//		{
	//			//@HACKY: always pass current instruction so that InvalidOpCode will print it, will be ignored for all other opcodes
	//			printf(pEntry->formatString, pPrgRom[PC]);
	//		}
	//		break;

	//	case 1:
	//		{
	//			uint8 address = pPrgRom[PC+1];
	//			printf(pEntry->formatString, address);
	//			
	//			// For relative (branch), resolve and print target address in comment
	//			if (pEntry->addrMode == Relatv)
	//			{
	//				int8 offset = pPrgRom[PC+1]; // Signed offset [-128,127]
	//				uint16 jmpAddress = startAddress + PC + pEntry->numBytes + offset;
	//				printf("\t; "ADDR_16, jmpAddress);
	//			}
	//			//else
	//			//{
	//			//	uint8 address = pPrgRom[PC+1];
	//			//	printf(pEntry->formatString, address);
	//			//}
	//		}
	//		break;

	//	case 2:
	//		{
	//			uint16 address = (pPrgRom[PC+2]<<8) | (pPrgRom[PC+1]);
	//			printf(pEntry->formatString, address);
	//		}
	//		break;

	//	default:
	//		assert(false && "Invalid number of operands");
	//		break;
	//	}
	//	//printf("\t;");
	//
	//	printf("\n");

	//	PC += pEntry->numBytes;
	//}
}

int ShowUsage(const char* appPath)
{
	printf("Usage: %s <nes rom>\n\n", appPath);
	return -1;
}

int main(int argc, const char* argv[])
{
	try
	{
		if (argc != 2)
			throw std::exception("Missing argument(s)");

		FileStream fs(argv[1], "rb");

		RomHeader header;
		fs.Read((uint8*)&header, sizeof(RomHeader));

		if ( !header.IsValidHeader() )
			throw std::exception("Invalid header");

		// Next is Trainer, if present (0 or 512 bytes)
		if ( header.HasTrainer() )
			throw std::exception("Not supporting trainer roms");

		if ( header.IsPlayChoice10() || header.IsVSUnisystem() )
			throw std::exception("Not supporting arcade roms (Playchoice10 / VS Unisystem)");

		// Next is PRG-ROM data (16384 * x bytes)
		const size_t prgRomSize = header.GetPrgRomSizeBytes();
		uint8* pPrgRom = new uint8[prgRomSize];
		fs.Read(pPrgRom, prgRomSize);
		Disassemble(pPrgRom, prgRomSize);
		delete [] pPrgRom;
	}
	catch (const std::exception& ex)
	{
		printf("%s\n", ex.what());
		return ShowUsage(argv[0]);
	}
	catch (...)
	{
		printf("Unknown exception\n");
		return ShowUsage(argv[0]);
	}

	return 0;
}
