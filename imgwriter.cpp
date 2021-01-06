#include "imgwriter.h"
#include <io.h>
#include <cstdio>
#include <ctime>
#include <cassert>

const DWORD MAJOR_LINKER_VER = 5;
const DWORD MINOR_LINKER_VER = 0;

const BYTE DOS_IMAGE[] =
	"\xBA\x10\x00\x0E\x1F\xB4\x09\xCD"
	"\x21\xB8\x01\x4C\xCD\x21\x90\x90"
	"This program must be run under Win32\r\n\x24\x37";

const DWORD PE_HEADER_OFFSET = 0x200;


inline size_t RoundUp(size_t value, size_t boundary)
{
	return ((value + boundary - 1) / boundary) * boundary;
}

static const SectionInfo * SectionsInfos;

inline DWORD AddrToRva(Address addr)
{
	if (addr.Section == 0)
	{
		assert(addr.Offset == 0);
		return 0;
	}
	return SectionsInfos[addr.Section - 1].VirtualAddress + addr.Offset;
}

static PIMAGE_NT_HEADERS pehdr;
static PIMAGE_SECTION_HEADER sec;

inline Address RvaToAddr(DWORD rva)
{
	Address result = {0};
	for (WORD i = 0; i < pehdr->FileHeader.NumberOfSections; i++)
	{
		if (sec[i].VirtualAddress <= rva && rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
		{
			result.Section = i + 1;
			result.Offset = rva - sec[i].VirtualAddress;
			return result;
		}
	}
	return result;
}

void CalculateSectionsPositions(ImageInfo & img)
{
	size_t sizeOfHeaders = RoundUp(PE_HEADER_OFFSET + sizeof(IMAGE_NT_HEADERS) +
		IMAGE_SIZEOF_SECTION_HEADER * (DWORD)img.Sections.size(), img.FileAlignment);

	// calculating positions of sections
	size_t filePos = sizeOfHeaders;
	size_t virtPos = RoundUp(sizeOfHeaders, img.SectionAlignment);
	for (size_t i = 0; i < img.Sections.size(); i++)
	{
		img.Sections[i].FileSize = RoundUp(img.Sections[i].DataSize, img.FileAlignment);
		img.Sections[i].VirtualSize = RoundUp(img.Sections[i].Size, img.SectionAlignment);
		img.Sections[i].FileOffset = filePos;
		img.Sections[i].VirtualAddress = virtPos;
		filePos += img.Sections[i].FileSize;
		virtPos += img.Sections[i].VirtualSize;
	}
}

bool StoreImage(const char * fileName, const ImageInfo & img)
{
	SectionsInfos = &img.Sections.front();

	IMAGE_DOS_HEADER doshdr = {0};
	doshdr.e_magic = IMAGE_DOS_SIGNATURE;
	doshdr.e_cblp = 0x50;
	doshdr.e_cp = 2;
	doshdr.e_cparhdr = 4;
	doshdr.e_minalloc = 0xf;
	doshdr.e_maxalloc = 0xffff;
	doshdr.e_sp = 0xb8;
	doshdr.e_lfarlc = 0x40;
	doshdr.e_ovno = 0x1A;
	doshdr.e_lfanew = 0x200;

	DWORD pesign = IMAGE_NT_SIGNATURE;

	IMAGE_FILE_HEADER hdr = {0};
	hdr.Characteristics = img.Characteristics;
	hdr.Machine = img.Machine;
	hdr.SizeOfOptionalHeader = sizeof IMAGE_OPTIONAL_HEADER32;
	hdr.TimeDateStamp = (DWORD)_time32(0);
	hdr.NumberOfSections = (WORD)img.Sections.size();

	IMAGE_OPTIONAL_HEADER32 opthdr = {0};

	size_t sizeOfHeaders = RoundUp(doshdr.e_lfanew + sizeof pesign + IMAGE_SIZEOF_FILE_HEADER +
		sizeof opthdr +
		IMAGE_SIZEOF_SECTION_HEADER * (DWORD)img.Sections.size(), img.FileAlignment);

	size_t sizeInitData = 0;
	size_t sizeUninitData = 0;
	size_t sizeCode = 0;
	size_t imageSize = RoundUp(sizeOfHeaders, img.SectionAlignment);
	for (size_t i = 0; i < img.Sections.size(); i++)
	{
		if (img.Sections[i].Characteristics & IMAGE_SCN_CNT_CODE)
		{
			sizeCode += img.Sections[i].VirtualSize;
		}
		if (img.Sections[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
		{
			sizeInitData += img.Sections[i].FileSize;
		}
		if (img.Sections[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
		{
			sizeUninitData += img.Sections[i].FileSize;
		}
		imageSize += img.Sections[i].VirtualSize;
	}

	opthdr.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	opthdr.MajorLinkerVersion = MAJOR_LINKER_VER;
	opthdr.MinorLinkerVersion = MINOR_LINKER_VER;
	opthdr.SizeOfCode = sizeCode;
	opthdr.SizeOfInitializedData = sizeInitData;
	opthdr.SizeOfUninitializedData = sizeUninitData;
	opthdr.AddressOfEntryPoint = AddrToRva(img.EntryPoint);
	opthdr.BaseOfCode = AddrToRva(img.BaseOfCode);
	opthdr.BaseOfData = AddrToRva(img.BaseOfData);
	opthdr.ImageBase = img.ImageBase;
	opthdr.SectionAlignment = img.SectionAlignment;
	opthdr.FileAlignment = img.FileAlignment;
	opthdr.MajorOperatingSystemVersion = img.MajorOperatingSystemVersion;
	opthdr.MinorOperatingSystemVersion = img.MinorOperatingSystemVersion;
	opthdr.MajorImageVersion = img.MajorVersion;
	opthdr.MinorImageVersion = img.MinorVersion;
	opthdr.MajorSubsystemVersion = img.MajorSubsystemVersion;
	opthdr.MinorSubsystemVersion = img.MinorSubsystemVersion;
	opthdr.Win32VersionValue = img.Win32VersionValue;
	opthdr.SizeOfImage = (DWORD)imageSize;
	opthdr.SizeOfHeaders = (DWORD)sizeOfHeaders;
	opthdr.Subsystem = img.Subsystem;
	opthdr.DllCharacteristics = img.DllCharacteristics;
	opthdr.SizeOfStackReserve = img.SizeOfStackReserve;
	opthdr.SizeOfStackCommit = img.SizeOfStackCommit;
	opthdr.SizeOfHeapReserve = img.SizeOfHeapReserve;
	opthdr.SizeOfHeapCommit = img.SizeOfHeapCommit;
	opthdr.LoaderFlags = img.LoaderFlags;
	opthdr.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		opthdr.DataDirectory[i].VirtualAddress = AddrToRva(img.Directories[i].Addr);
		opthdr.DataDirectory[i].Size = img.Directories[i].Size;
	}

	FILE * file = fopen(fileName, "wb");
	fwrite(&doshdr, sizeof doshdr, 1, file);
	fpos_t pos = doshdr.e_lfanew;
	fwrite(DOS_IMAGE, sizeof DOS_IMAGE, 1, file);
	fsetpos(file, &pos);
	fwrite(&pesign, sizeof pesign, 1, file);
	fwrite(&hdr, IMAGE_SIZEOF_FILE_HEADER, 1, file);
	fwrite(&opthdr, sizeof opthdr, 1, file);
	for (size_t i = 0; i < img.Sections.size(); i++)
	{
		IMAGE_SECTION_HEADER sechdr = {0};
		strncpy((PCHAR)sechdr.Name, img.Sections[i].Name, IMAGE_SIZEOF_SHORT_NAME);
		sechdr.Misc.VirtualSize = (DWORD)RoundUp(img.Sections[i].Size, img.SectionAlignment);
		sechdr.VirtualAddress = img.Sections[i].VirtualAddress;
		sechdr.SizeOfRawData = (DWORD)RoundUp(img.Sections[i].DataSize, img.FileAlignment);
		sechdr.PointerToRawData = img.Sections[i].FileOffset;
		sechdr.Characteristics = img.Sections[i].Characteristics;
		fwrite(&sechdr, IMAGE_SIZEOF_SECTION_HEADER, 1, file);
	}
	for (size_t i = 0; i < img.Sections.size(); i++)
	{
		pos = img.Sections[i].FileOffset;
		fsetpos(file, &pos);
		fwrite(img.Sections[i].Data, 1, img.Sections[i].DataSize, file);
	}
	const SectionInfo * lastSection = &img.Sections[img.Sections.size() - 1];
	long size = lastSection->FileOffset + RoundUp(lastSection->DataSize, img.FileAlignment);
	_chsize(_fileno(file), size);
	fclose(file);
	return true;
}


#define COPY_FIELD(to, from, fld) (to).fld = (from).fld


void ParseImage(PBYTE address, ImageInfo & img)
{
	PIMAGE_DOS_HEADER doshdr = (PIMAGE_DOS_HEADER)address;
	if (doshdr->e_magic != IMAGE_DOS_SIGNATURE)
		throw 0;
	pehdr = (PIMAGE_NT_HEADERS)(address + doshdr->e_lfanew);
	if (pehdr->Signature != IMAGE_NT_SIGNATURE)
		throw 0;
	if (pehdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		throw 0;
	sec = IMAGE_FIRST_SECTION(pehdr);
	img.FileAlignment = pehdr->OptionalHeader.FileAlignment;
	img.SectionAlignment = pehdr->OptionalHeader.SectionAlignment;
	img.Sections.resize(pehdr->FileHeader.NumberOfSections);
	for (int i = 0; i < pehdr->FileHeader.NumberOfSections; i++)
	{
		img.Sections[i].Name = (const char *)sec[i].Name;
		img.Sections[i].Characteristics = sec[i].Characteristics;
		img.Sections[i].Size = sec[i].Misc.VirtualSize;
		img.Sections[i].DataSize = sec[i].SizeOfRawData;
		img.Sections[i].Data = address + sec[i].PointerToRawData;
		img.Sections[i].FileOffset = sec[i].PointerToRawData;
		img.Sections[i].VirtualAddress = sec[i].VirtualAddress;
	}
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		img.Directories[i].Addr = RvaToAddr(pehdr->OptionalHeader.DataDirectory[i].VirtualAddress);
		img.Directories[i].Size = pehdr->OptionalHeader.DataDirectory[i].Size;
	}
	img.Machine = pehdr->FileHeader.Machine;
	img.ImageBase = pehdr->OptionalHeader.ImageBase;
	img.Characteristics = pehdr->FileHeader.Characteristics;
	img.Subsystem = pehdr->OptionalHeader.Subsystem;
	img.EntryPoint = RvaToAddr(pehdr->OptionalHeader.AddressOfEntryPoint);
	img.BaseOfCode = RvaToAddr(pehdr->OptionalHeader.BaseOfCode);
	img.BaseOfData = RvaToAddr(pehdr->OptionalHeader.BaseOfData);
	COPY_FIELD(img, pehdr->OptionalHeader, MajorOperatingSystemVersion);
	COPY_FIELD(img, pehdr->OptionalHeader, MinorOperatingSystemVersion);
	img.MajorVersion = pehdr->OptionalHeader.MajorImageVersion;
	img.MinorVersion = pehdr->OptionalHeader.MinorImageVersion;
	COPY_FIELD(img, pehdr->OptionalHeader, MajorSubsystemVersion);
	COPY_FIELD(img, pehdr->OptionalHeader, MinorSubsystemVersion);
	COPY_FIELD(img, pehdr->OptionalHeader, Win32VersionValue);
	COPY_FIELD(img, pehdr->OptionalHeader, DllCharacteristics);
	COPY_FIELD(img, pehdr->OptionalHeader, SizeOfStackReserve);
	COPY_FIELD(img, pehdr->OptionalHeader, SizeOfStackCommit);
	COPY_FIELD(img, pehdr->OptionalHeader, SizeOfHeapReserve);
	COPY_FIELD(img, pehdr->OptionalHeader, SizeOfHeapCommit);
	COPY_FIELD(img, pehdr->OptionalHeader, LoaderFlags);
}
