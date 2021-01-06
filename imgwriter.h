#include <windows.h>
#include <vector>

struct Address
{
	WORD Section;
	DWORD Offset;
};

struct SectionInfo
{
	const char * Name;
	DWORD Characteristics;
	DWORD Size;
	DWORD DataSize;
	PBYTE Data;
	size_t FileSize;
	size_t FileOffset;
	size_t VirtualSize;
	size_t VirtualAddress;
};

struct DirInfo
{
	Address Addr;
	DWORD Size;
};

struct ImageInfo
{
	DWORD FileAlignment;
	DWORD SectionAlignment;
	DirInfo Directories[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	std::vector<SectionInfo> Sections;

	WORD Machine;
	DWORD ImageBase;
	WORD Characteristics;
	WORD Subsystem;
	Address EntryPoint;
	Address BaseOfCode;
	Address BaseOfData;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorVersion;
	WORD MinorVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Win32VersionValue;
	WORD DllCharacteristics;
	DWORD SizeOfStackReserve;
	DWORD SizeOfStackCommit;
	DWORD SizeOfHeapReserve;
	DWORD SizeOfHeapCommit;
	DWORD LoaderFlags;
};

void CalculateSectionsPositions(ImageInfo & img);
bool StoreImage(const char * fileName, const ImageInfo & img);
void ParseImage(PBYTE address, ImageInfo & img);
void EmitDebugInfo(DWORD type, WORD section, DWORD size, PBYTE data, ImageInfo & img);