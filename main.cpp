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
struct FormattedString
{
	FormattedString(const char* format, ...)
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
			throw std::exception(FormattedString<>("Failed to open file: %s", name));
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

namespace AddressMode
{
	enum Type
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
}

namespace OpCodeName
{
	enum Type
	{
		ADC, AND, ASL,
		BCC, BCS, BEQ, BIT, BMI, BNE, BPL, BRK, BVC, BVS,
		CLC, CLD, CLI, CLV, CMP, CPX, CPY, DEC, DEX, DEY,
		EOR, INC, INX, INY,
		JMP, JSR,
		LDA, LDX, LDY, LSR,
		NOP,
		ORA,
		PHA, PHP, PLA, PLP,
		ROL, ROR, RTI, RTS,
		SBC, SEC, SED, SEI, STA, STX, STY,
		TAX, TAY, TSX, TXA, TXS, TYA,

		NumTypes
	};

	static const char* String[] =
	{
		"ADC", "AND", "ASL",
		"BCC", "BCS", "BEQ", "BIT", "BMI", "BNE", "BPL", "BRK", "BVC", "BVS",
		"CLC", "CLD", "CLI", "CLV", "CMP", "CPX", "CPY", "DEC", "DEX", "DEY",
		"EOR", "INC", "INX", "INY",
		"JMP", "JSR",
		"LDA", "LDX", "LDY", "LSR",
		"NOP",
		"ORA",
		"PHA", "PHP", "PLA", "PLP",
		"ROL", "ROR", "RTI", "RTS",
		"SBC", "SEC", "SED", "SEI", "STA", "STX", "STY",
		"TAX", "TAY", "TSX", "TXA", "TXS", "TYA",
	};

	static_assert(NumTypes == ARRAYSIZE(String), "Size mismatch");
}


struct OpCodeEntry
{
	uint8 opCode;
	OpCodeName::Type opCodeName;
	uint8 numBytes;
	uint8 numCycles;
	AddressMode::Type addrMode;
};

void ValidateOpCodeTable(OpCodeEntry opCodeTable[], size_t numEntries);

OpCodeEntry** GetOpCodeTable()
{
	using namespace OpCodeName;
	using namespace AddressMode;

	static OpCodeEntry opCodeTable[] =
	{
		{ 0x69, ADC, 2, 2, Immedt },
		{ 0x65, ADC, 2, 3, ZeroPg },
		{ 0x75, ADC, 2, 4, ZPIdxX },
		{ 0x6D, ADC, 3, 4, Absolu },
		{ 0x7D, ADC, 3, 4, AbIdxX },
		{ 0x79, ADC, 3, 4, AbIdxY },
		{ 0x61, ADC, 2, 6, IdxInd },
		{ 0x71, ADC, 2, 5, IndIdx },

		{ 0x29, AND, 2, 2, Immedt },
		{ 0x25, AND, 2, 3, ZeroPg },
		{ 0x35, AND, 2, 4, ZPIdxX },
		{ 0x2D, AND, 3, 4, Absolu },
		{ 0x3D, AND, 3, 4, AbIdxX },
		{ 0x39, AND, 3, 4, AbIdxY },
		{ 0x21, AND, 2, 6, IdxInd },
		{ 0x31, AND, 2, 5, IndIdx },

		{ 0x0A, ASL, 1, 2, Accumu },
		{ 0x06, ASL, 2, 5, ZeroPg },
		{ 0x16, ASL, 2, 6, ZPIdxX },
		{ 0x0E, ASL, 3, 6, Absolu },
		{ 0x1E, ASL, 3, 7, AbIdxX },

		{ 0x90, BCC, 2, 2, Relatv },
		
		{ 0xB0, BCS, 2, 2, Relatv },
		
		{ 0xF0, BEQ, 2, 2, Relatv },

		{ 0x24, BIT, 2, 3, ZeroPg },
		{ 0x2C, BIT, 3, 4, Absolu },

		{ 0x30, BMI, 2, 2, Relatv },

		{ 0xD0, BNE, 2, 2, Relatv },

		{ 0x10, BPL, 2, 2, Relatv },

		{ 0x00, BRK, 1, 7, Implid },

		{ 0x50, BVC, 2, 2, Relatv },

		{ 0x70, BVS, 2, 2, Relatv },

		{ 0x18, CLC, 1, 2, Implid },

		{ 0xD8, CLD, 1, 2, Implid },

		{ 0x58, CLI, 1, 2, Implid },

		{ 0xB8, CLV, 1, 2, Implid },

		{ 0xC9, CMP, 2, 2, Immedt },
		{ 0xC5, CMP, 2, 3, ZeroPg },
		{ 0xD5, CMP, 2, 4, ZPIdxX },
		{ 0xCD, CMP, 3, 4, Absolu },
		{ 0xDD, CMP, 3, 4, AbIdxX },
		{ 0xD9, CMP, 3, 4, AbIdxY },
		{ 0xC1, CMP, 2, 6, IdxInd },
		{ 0xD1, CMP, 2, 5, IndIdx },

		{ 0xE0, CPX, 2, 2, Immedt },
		{ 0xE4, CPX, 2, 3, ZeroPg },
		{ 0xEC, CPX, 3, 4, Absolu },

		{ 0xC0, CPY, 2, 2, Immedt },
		{ 0xC4, CPY, 2, 3, ZeroPg },
		{ 0xCC, CPY, 3, 4, Absolu },

		{ 0xC6, DEC, 2, 5, ZeroPg },
		{ 0xD6, DEC, 2, 6, ZPIdxX },
		{ 0xCE, DEC, 3, 6, Absolu },
		{ 0xDE, DEC, 3, 7, AbIdxX },

		{ 0xCA, DEX, 1, 2, Implid },

		{ 0x88, DEY, 1, 2, Implid },

		{ 0x49, EOR, 2, 2, Immedt },
		{ 0x45, EOR, 2, 3, ZeroPg },
		{ 0x55, EOR, 2, 4, ZPIdxX },
		{ 0x4D, EOR, 3, 4, Absolu },
		{ 0x5D, EOR, 3, 4, AbIdxX },
		{ 0x59, EOR, 3, 4, AbIdxY },
		{ 0x41, EOR, 2, 6, IdxInd },
		{ 0x51, EOR, 2, 5, IndIdx },

		{ 0xE6, INC, 2, 5, ZeroPg },
		{ 0xF6, INC, 2, 6, ZPIdxX },
		{ 0xEE, INC, 3, 6, Absolu },
		{ 0xFE, INC, 3, 7, AbIdxX },

		{ 0xE8, INX, 1, 2, Implid },

		{ 0xC8, INY, 1, 2, Implid },

		{ 0x4C, JMP, 3, 3, Absolu },
		{ 0x6C, JMP, 3, 5, Indrct },

		{ 0x20, JSR, 3, 6, Absolu },

		{ 0xA9, LDA, 2, 2, Immedt },
		{ 0xA5, LDA, 2, 3, ZeroPg },
		{ 0xB5, LDA, 2, 4, ZPIdxX },
		{ 0xAD, LDA, 3, 4, Absolu },
		{ 0xBD, LDA, 3, 4, AbIdxX },
		{ 0xB9, LDA, 3, 4, AbIdxY },
		{ 0xA1, LDA, 2, 6, IdxInd },
		{ 0xB1, LDA, 2, 5, IndIdx },

		{ 0xA2, LDX, 2, 2, Immedt },
		{ 0xA6, LDX, 2, 3, ZeroPg },
		{ 0xB6, LDX, 2, 4, ZPIdxY },
		{ 0xAE, LDX, 3, 4, Absolu },
		{ 0xBE, LDX, 3, 4, AbIdxY },

		{ 0xA0, LDY, 2, 2, Immedt },
		{ 0xA4, LDY, 2, 3, ZeroPg },
		{ 0xB4, LDY, 2, 4, ZPIdxX },
		{ 0xAC, LDY, 3, 4, Absolu },
		{ 0xBC, LDY, 3, 4, AbIdxX },

		{ 0x4A, LSR, 1, 2, Accumu },
		{ 0x46, LSR, 2, 5, ZeroPg },
		{ 0x56, LSR, 2, 6, ZPIdxX },
		{ 0x4E, LSR, 3, 6, Absolu },
		{ 0x5E, LSR, 3, 7, AbIdxX },

		{ 0xEA, NOP, 1, 2, Implid },

		{ 0x09, ORA, 2, 2, Immedt },
		{ 0x05, ORA, 2, 3, ZeroPg },
		{ 0x15, ORA, 2, 4, ZPIdxX },
		{ 0x0D, ORA, 3, 4, Absolu },
		{ 0x1D, ORA, 3, 4, AbIdxX },
		{ 0x19, ORA, 3, 4, AbIdxY },
		{ 0x01, ORA, 2, 6, IdxInd },
		{ 0x11, ORA, 2, 5, IndIdx },

		{ 0x48, PHA, 1, 3, Implid },

		{ 0x08, PHP, 1, 3, Implid },

		{ 0x68, PLA, 1, 4, Implid },

		{ 0x28, PLP, 1, 4, Implid },

		{ 0x2A, ROL, 1, 2, Accumu },
		{ 0x26, ROL, 2, 5, ZeroPg },
		{ 0x36, ROL, 2, 6, ZPIdxX },
		{ 0x2E, ROL, 3, 6, Absolu },
		{ 0x3E, ROL, 3, 7, AbIdxX },

		{ 0x6A, ROR, 1, 2, Accumu },
		{ 0x66, ROR, 2, 5, ZeroPg },
		{ 0x76, ROR, 2, 6, ZPIdxX },
		{ 0x6E, ROR, 3, 6, Absolu },
		{ 0x7E, ROR, 3, 7, AbIdxX },

		{ 0x40, RTI, 1, 6, Implid },

		{ 0x60, RTS, 1, 6, Implid },

		{ 0xE9, SBC, 2, 2, Immedt },
		{ 0xE5, SBC, 2, 3, ZeroPg },
		{ 0xF5, SBC, 2, 4, ZPIdxX },
		{ 0xED, SBC, 3, 4, Absolu },
		{ 0xFD, SBC, 3, 4, AbIdxX },
		{ 0xF9, SBC, 3, 4, AbIdxY },
		{ 0xE1, SBC, 2, 6, IdxInd },
		{ 0xF1, SBC, 2, 5, IndIdx },

		{ 0x38, SEC, 1, 2, Implid },

		{ 0xF8, SED, 1, 2, Implid },

		{ 0x78, SEI, 1, 2, Implid },

		{ 0x85, STA, 2, 3, ZeroPg },
		{ 0x95, STA, 2, 4, ZPIdxX },
		{ 0x8D, STA, 3, 4, Absolu },
		{ 0x9D, STA, 3, 5, AbIdxX },
		{ 0x99, STA, 3, 5, AbIdxY },
		{ 0x81, STA, 2, 6, IdxInd },
		{ 0x91, STA, 2, 6, IndIdx },

		{ 0x86, STX, 2, 3, ZeroPg },
		{ 0x96, STX, 2, 4, ZPIdxY },
		{ 0x8E, STX, 3, 4, Absolu },

		{ 0x84, STY, 2, 3, ZeroPg },
		{ 0x94, STY, 2, 4, ZPIdxX },
		{ 0x8C, STY, 3, 4, Absolu },

		{ 0xAA, TAX, 1, 2, Implid },

		{ 0xA8, TAY, 1, 2, Implid },

		{ 0xBA, TSX, 1, 2, Implid },

		{ 0x8A, TXA, 1, 2, Implid },

		{ 0x9A, TXS, 1, 2, Implid },

		{ 0x98, TYA, 1, 2, Implid },
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
	for (size_t i = 0; i < numEntries; ++i)
	{
		const OpCodeEntry& entry = opCodeTable[i];
		switch (opCodeTable[i].addrMode)
		{
		case AddressMode::Immedt:
			assert(entry.numBytes == 2);
			break;
		case AddressMode::Implid:
			assert(entry.numBytes == 1);
			break;
		case AddressMode::Accumu:
			assert(entry.numBytes == 1);
			break;
		case AddressMode::Relatv:
			assert(entry.numBytes == 2);
			break;
		case AddressMode::ZeroPg:
			assert(entry.numBytes == 2);
			break;
		case AddressMode::ZPIdxX:
			assert(entry.numBytes == 2);
			break;
		case AddressMode::ZPIdxY:
			assert(entry.numBytes == 2);
			break;
		case AddressMode::Absolu:
			assert(entry.numBytes == 3);
			break;
		case AddressMode::AbIdxX:
			assert(entry.numBytes == 3);
			break;
		case AddressMode::AbIdxY:
			assert(entry.numBytes == 3);
			break;
		case AddressMode::Indrct:
			assert(entry.numBytes == 3);
			assert(entry.opCodeName == OpCodeName::JMP);
			break;
		case AddressMode::IdxInd:
			assert(entry.numBytes == 2);
			break;
		case AddressMode::IndIdx:
			assert(entry.numBytes == 2);
			break;
		}
	}
}

#define ADDR_8 "$%02X"
#define ADDR_16 "$%04X"

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

		// Print opcode name
		printf("%s ", OpCodeName::String[pEntry->opCodeName]);

		// Print operand
		switch (pEntry->addrMode)
		{
		case AddressMode::Immedt:
			{
			const uint8 address = pPrgRom[PC+1];
			printf("#"ADDR_8, address);
			}
			break;

		case AddressMode::Implid:
			// No operand to output
			break;

		case AddressMode::Accumu:
			{
			printf("A");
			}
			break;

		case AddressMode::Relatv:
			{
			// For branch instructions, resolve the target address and print it in comments
			const int8 offset = pPrgRom[PC+1]; // Signed offset in [-128,127]
			const uint16 target = startAddress + PC + pEntry->numBytes + offset;
			printf(ADDR_8" ; "ADDR_16" (%d)", pPrgRom[PC+1], target, offset);
			}
			break;
		
		case AddressMode::ZeroPg:
			{
			const uint8 address = pPrgRom[PC+1];
			printf(ADDR_8, address);
			}
			break;

		case AddressMode::ZPIdxX:
			{
			const uint8 address = pPrgRom[PC+1];
			printf(ADDR_8",X", address);
			}
			break;
		
		case AddressMode::ZPIdxY:
			{
			const uint8 address = pPrgRom[PC+1];
			printf(ADDR_8",Y", address);
			}
			break;

		case AddressMode::Absolu:
			{
			uint16 address = (pPrgRom[PC+2]<<8) | (pPrgRom[PC+1]);
			printf(ADDR_16, address);
			}
			break;

		case AddressMode::AbIdxX:
			{
			uint16 address = (pPrgRom[PC+2]<<8) | (pPrgRom[PC+1]);
			printf(ADDR_16",X", address);
			}
			break;

		case AddressMode::AbIdxY:
			{
			uint16 address = (pPrgRom[PC+2]<<8) | (pPrgRom[PC+1]);
			printf(ADDR_16",Y", address);
			}
			break;

		case AddressMode::Indrct:
			{
			uint16 address = (pPrgRom[PC+2]<<8) | (pPrgRom[PC+1]);
			printf("("ADDR_16")", address);
			}
			break;

		case AddressMode::IdxInd:
			{
			const uint8 address = pPrgRom[PC+1];
			printf("("ADDR_8",X)", address);
			}
			break;

		case AddressMode::IndIdx:
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
