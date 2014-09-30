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
	uint8 numBytes;
	uint8 numCycles;
	AddressMode::Type addrMode;
	OpCodeName::Type opCodeName;
};

void ValidateOpCodeTable(OpCodeEntry opCodeTable[], size_t numEntries);

OpCodeEntry** GetOpCodeTable()
{
	using namespace OpCodeName;
	using namespace AddressMode;

	static OpCodeEntry opCodeTable[] =
	{
		{ 0x69, 2, 2, Immedt, ADC },
		{ 0x65, 2, 3, ZeroPg, ADC },
		{ 0x75, 2, 4, ZPIdxX, ADC },
		{ 0x6D, 3, 4, Absolu, ADC },
		{ 0x7D, 3, 4, AbIdxX, ADC },
		{ 0x79, 3, 4, AbIdxY, ADC },
		{ 0x61, 2, 6, IdxInd, ADC },
		{ 0x71, 2, 5, IndIdx, ADC },

		{ 0x29, 2, 2, Immedt, AND },
		{ 0x25, 2, 3, ZeroPg, AND },
		{ 0x35, 2, 4, ZPIdxX, AND },
		{ 0x2D, 3, 4, Absolu, AND },
		{ 0x3D, 3, 4, AbIdxX, AND },
		{ 0x39, 3, 4, AbIdxY, AND },
		{ 0x21, 2, 6, IdxInd, AND },
		{ 0x31, 2, 5, IndIdx, AND },

		{ 0x0A, 1, 2, Accumu, ASL },
		{ 0x06, 2, 5, ZeroPg, ASL },
		{ 0x16, 2, 6, ZPIdxX, ASL },
		{ 0x0E, 3, 6, Absolu, ASL },
		{ 0x1E, 3, 7, AbIdxX, ASL },

		{ 0x90, 2, 2, Relatv, BCC },
		
		{ 0xB0, 2, 2, Relatv, BCS },
		
		{ 0xF0, 2, 2, Relatv, BEQ },

		{ 0x24, 2, 3, ZeroPg, BIT },
		{ 0x2C, 3, 4, Absolu, BIT },

		{ 0x30, 2, 2, Relatv, BMI },

		{ 0xD0, 2, 2, Relatv, BNE },

		{ 0x10, 2, 2, Relatv, BPL },

		{ 0x00, 1, 7, Implid, BRK },

		{ 0x50, 2, 2, Relatv, BVC },

		{ 0x70, 2, 2, Relatv, BVS },

		{ 0x18, 1, 2, Implid, CLC },

		{ 0xD8, 1, 2, Implid, CLD },

		{ 0x58, 1, 2, Implid, CLI },

		{ 0xB8, 1, 2, Implid, CLV },

		{ 0xC9, 2, 2, Immedt, CMP },
		{ 0xC5, 2, 3, ZeroPg, CMP },
		{ 0xD5, 2, 4, ZPIdxX, CMP },
		{ 0xCD, 3, 4, Absolu, CMP },
		{ 0xDD, 3, 4, AbIdxX, CMP },
		{ 0xD9, 3, 4, AbIdxY, CMP },
		{ 0xC1, 2, 6, IdxInd, CMP },
		{ 0xD1, 2, 5, IndIdx, CMP },

		{ 0xE0, 2, 2, Immedt, CPX },
		{ 0xE4, 2, 3, ZeroPg, CPX },
		{ 0xEC, 3, 4, Absolu, CPX },

		{ 0xC0, 2, 2, Immedt, CPY },
		{ 0xC4, 2, 3, ZeroPg, CPY },
		{ 0xCC, 3, 4, Absolu, CPY },

		{ 0xC6, 2, 5, ZeroPg, DEC },
		{ 0xD6, 2, 6, ZPIdxX, DEC },
		{ 0xCE, 3, 6, Absolu, DEC },
		{ 0xDE, 3, 7, AbIdxX, DEC },

		{ 0xCA, 1, 2, Implid, DEX },

		{ 0x88, 1, 2, Implid, DEY },

		{ 0x49, 2, 2, Immedt, EOR },
		{ 0x45, 2, 3, ZeroPg, EOR },
		{ 0x55, 2, 4, ZPIdxX, EOR },
		{ 0x4D, 3, 4, Absolu, EOR },
		{ 0x5D, 3, 4, AbIdxX, EOR },
		{ 0x59, 3, 4, AbIdxY, EOR },
		{ 0x41, 2, 6, IdxInd, EOR },
		{ 0x51, 2, 5, IndIdx, EOR },

		{ 0xE6, 2, 5, ZeroPg, INC },
		{ 0xF6, 2, 6, ZPIdxX, INC },
		{ 0xEE, 3, 6, Absolu, INC },
		{ 0xFE, 3, 7, AbIdxX, INC },

		{ 0xE8, 1, 2, Implid, INX },

		{ 0xC8, 1, 2, Implid, INY },

		{ 0x4C, 3, 3, Absolu, JMP },
		{ 0x6C, 3, 5, Indrct, JMP },

		{ 0x20, 3, 6, Absolu, JSR },

		{ 0xA9, 2, 2, Immedt, LDA },
		{ 0xA5, 2, 3, ZeroPg, LDA },
		{ 0xB5, 2, 4, ZPIdxX, LDA },
		{ 0xAD, 3, 4, Absolu, LDA },
		{ 0xBD, 3, 4, AbIdxX, LDA },
		{ 0xB9, 3, 4, AbIdxY, LDA },
		{ 0xA1, 2, 6, IdxInd, LDA },
		{ 0xB1, 2, 5, IndIdx, LDA },

		{ 0xA2, 2, 2, Immedt, LDX },
		{ 0xA6, 2, 3, ZeroPg, LDX },
		{ 0xB6, 2, 4, ZPIdxY, LDX },
		{ 0xAE, 3, 4, Absolu, LDX },
		{ 0xBE, 3, 4, AbIdxY, LDX },

		{ 0xA0, 2, 2, Immedt, LDY },
		{ 0xA4, 2, 3, ZeroPg, LDY },
		{ 0xB4, 2, 4, ZPIdxX, LDY },
		{ 0xAC, 3, 4, Absolu, LDY },
		{ 0xBC, 3, 4, AbIdxX, LDY },

		{ 0x4A, 1, 2, Accumu, LSR },
		{ 0x46, 2, 5, ZeroPg, LSR },
		{ 0x56, 2, 6, ZPIdxX, LSR },
		{ 0x4E, 3, 6, Absolu, LSR },
		{ 0x5E, 3, 7, AbIdxX, LSR },

		{ 0xEA, 1, 2, Implid, NOP },

		{ 0x09, 2, 2, Immedt, ORA },
		{ 0x05, 2, 3, ZeroPg, ORA },
		{ 0x15, 2, 4, ZPIdxX, ORA },
		{ 0x0D, 3, 4, Absolu, ORA },
		{ 0x1D, 3, 4, AbIdxX, ORA },
		{ 0x19, 3, 4, AbIdxY, ORA },
		{ 0x01, 2, 6, IdxInd, ORA },
		{ 0x11, 2, 5, IndIdx, ORA },

		{ 0x48, 1, 3, Implid, PHA },

		{ 0x08, 1, 3, Implid, PHP },

		{ 0x68, 1, 4, Implid, PLA },

		{ 0x28, 1, 4, Implid, PLP },

		{ 0x2A, 1, 2, Accumu, ROL },
		{ 0x26, 2, 5, ZeroPg, ROL },
		{ 0x36, 2, 6, ZPIdxX, ROL },
		{ 0x2E, 3, 6, Absolu, ROL },
		{ 0x3E, 3, 7, AbIdxX, ROL },

		{ 0x6A, 1, 2, Accumu, ROR },
		{ 0x66, 2, 5, ZeroPg, ROR },
		{ 0x76, 2, 6, ZPIdxX, ROR },
		{ 0x6E, 3, 6, Absolu, ROR },
		{ 0x7E, 3, 7, AbIdxX, ROR },

		{ 0x40, 1, 6, Implid, RTI },

		{ 0x60, 1, 6, Implid, RTS },

		{ 0xE9, 2, 2, Immedt, SBC },
		{ 0xE5, 2, 3, ZeroPg, SBC },
		{ 0xF5, 2, 4, ZPIdxX, SBC },
		{ 0xED, 3, 4, Absolu, SBC },
		{ 0xFD, 3, 4, AbIdxX, SBC },
		{ 0xF9, 3, 4, AbIdxY, SBC },
		{ 0xE1, 2, 6, IdxInd, SBC },
		{ 0xF1, 2, 5, IndIdx, SBC },

		{ 0x38, 1, 2, Implid, SEC },

		{ 0xF8, 1, 2, Implid, SED },

		{ 0x78, 1, 2, Implid, SEI },

		{ 0x85, 2, 3, ZeroPg, STA },
		{ 0x95, 2, 4, ZPIdxX, STA },
		{ 0x8D, 3, 4, Absolu, STA },
		{ 0x9D, 3, 5, AbIdxX, STA },
		{ 0x99, 3, 5, AbIdxY, STA },
		{ 0x81, 2, 6, IdxInd, STA },
		{ 0x91, 2, 6, IndIdx, STA },

		{ 0x86, 2, 3, ZeroPg, STX },
		{ 0x96, 2, 4, ZPIdxY, STX },
		{ 0x8E, 3, 4, Absolu, STX },

		{ 0x84, 2, 3, ZeroPg, STY },
		{ 0x94, 2, 4, ZPIdxX, STY },
		{ 0x8C, 3, 4, Absolu, STY },

		{ 0xAA, 1, 2, Implid, TAX },

		{ 0xA8, 1, 2, Implid, TAY },

		{ 0xBA, 1, 2, Implid, TSX },

		{ 0x8A, 1, 2, Implid, TXA },

		{ 0x9A, 1, 2, Implid, TXS },

		{ 0x98, 1, 2, Implid, TYA },
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
