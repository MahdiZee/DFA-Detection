#ifndef BPeFileH
#define BPeFileH
#include "BFile.h"
#include "ScanGeneral.h"

#define DoAlignment(Size, Align) ((Size)+(((Size)%(Align)==0)?0:(Align))-((Size)%(Align)))

class BPeFile : public BFile
{
public:
    DWORD PeOffset;
    DWORD ImageBase;
    DWORD ImageSize;
    DWORD EntryPoint;
    DWORD EntryPointOffset;
    ErrorMessage Error;
private:
    DWORD NumberOfSection;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    IMAGE_SECTION_HEADER* SectionEntrys;
    DWORD* SectionOffset;
    BOOL  Init();
public:
    ~BPeFile();
    BPeFile();
    BPeFile(BPeFile& PeFile);

    BOOL  Open(TCHAR* FileName, DWORD Access = AccessRead);
    BOOL  Init(BFile* File);
    DWORD ConvertRvaToOffset(DWORD RVA);
    DWORD ConvertAddressToOffset(DWORD Address);
    IMAGE_SECTION_HEADER* ReadLastSectionEntry();
    IMAGE_SECTION_HEADER* ReadSectionEntryForRVA(DWORD RVA);
    IMAGE_SECTION_HEADER* ReadSectionEntryForOffset(DWORD Offset);
#if defined(Zeynali)
    BOOL ZeroSection(DWORD Offset);
    BOOL ZeroBlockEndSection(DWORD Offset);
    BOOL CleanEndOfFile ();
    ErrorMessage DeleteSection(DWORD Offset);
    ErrorMessage DeleteBlockFromSection(DWORD Offset, DWORD Size);
    ErrorMessage DeleteBlockFromEndOfSection(DWORD Offset);
    ErrorMessage ChangeEntryPoint(DWORD OriginalEntryPoint);
    ErrorMessage WriteEntryPoint(PVOID Buffer, UINT Size);
#endif
};

#endif