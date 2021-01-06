#include "imgwriter.h"
#include <tchar.h>
#include <windows.h>
#include <ctime>

PIMAGE_DOS_HEADER doshdr;
PIMAGE_NT_HEADERS pehdr;
PIMAGE_SECTION_HEADER sec;

DWORD VirtToRaw(DWORD virt)
{
	for (WORD i = 0; i < pehdr->FileHeader.NumberOfSections; i++)
	{
		if (sec[i].VirtualAddress <= virt && virt < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
			return sec[i].PointerToRawData + virt - sec[i].VirtualAddress;
	}
	return -1;
}

const DWORD CVLINK_SIGNATURE = 0x53445352; // "RSDS"

#pragma pack(1)
struct CVHEADER
{
	DWORD Signature;
	GUID Guid;
	DWORD Unknown;
};

struct MISCHEADER
{
	DWORD Type;
	DWORD Size;
	DWORD Unknown;
};

int main(int argc, const char * argv)
{
	HANDLE hfile = CreateFile(_TEXT("test.exe"), FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	HANDLE hmap = CreateFileMapping(hfile, 0, PAGE_READONLY, 0, 0, 0);
	LPBYTE ptr = (LPBYTE)MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, 0);
	ImageInfo img;
	ParseImage(ptr, img);
	struct DBGSECT
	{
		IMAGE_DEBUG_DIRECTORY dbgdir;
		struct
		{
			CVHEADER hdr;
			char link[10];
		} cv;
	} dbgSect = {0};
	dbgSect.dbgdir.TimeDateStamp = (DWORD)_time32(0);
	dbgSect.dbgdir.Type = IMAGE_DEBUG_TYPE_CODEVIEW;
	dbgSect.dbgdir.SizeOfData = sizeof dbgSect.cv;
	dbgSect.cv.hdr.Signature = CVLINK_SIGNATURE;
	UuidCreate(&dbgSect.cv.hdr.Guid);
	dbgSect.cv.hdr.Unknown = 1;
	strncpy(dbgSect.cv.link, "test2.pdb", sizeof dbgSect.cv.link);
	/*struct DBGSECT
	{
		IMAGE_DEBUG_DIRECTORY dbgdir;
		struct
		{
			MISCHEADER hdr;
			char link[10];
		} misc;
	} dbgSect = {0};
	dbgSect.dbgdir.TimeDateStamp = (DWORD)_time32(0);
	dbgSect.dbgdir.Type = IMAGE_DEBUG_TYPE_MISC;
	dbgSect.misc.hdr.Size = dbgSect.dbgdir.SizeOfData = sizeof dbgSect.misc;
	dbgSect.misc.hdr.Type = 1;
	strncpy(dbgSect.misc.link, "test2.dbg", sizeof dbgSect.misc.link);*/

	SectionInfo dbgsec;
	dbgsec.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
	dbgsec.Data = reinterpret_cast<PBYTE>(&dbgSect);
	dbgsec.Size = dbgsec.DataSize = sizeof dbgSect;
	dbgsec.Name = ".dbg";
	img.Sections.push_back(dbgsec);
	img.Directories[IMAGE_DIRECTORY_ENTRY_DEBUG].Addr.Section = img.Sections.size();
	img.Directories[IMAGE_DIRECTORY_ENTRY_DEBUG].Addr.Offset = 0;
	img.Directories[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = sizeof dbgSect.dbgdir;
	CalculateSectionsPositions(img);
	dbgSect.dbgdir.PointerToRawData = img.Sections[img.Sections.size() - 1].FileOffset + FIELD_OFFSET(DBGSECT, cv);
	StoreImage("test2.exe", img);
}
