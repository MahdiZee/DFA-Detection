#include "BPeFile.h"
#include <windows.h>

#define SECTION_SIZE (sizeof(IMAGE_SECTION_HEADER))

BPeFile::~BPeFile()
{
    if (SectionEntrys != NULL)
        delete[] SectionEntrys;
}
//------------------------------------------------------------------------------
BPeFile::BPeFile()
{
    ImageBase = 0;
    ImageSize = 0;
    EntryPoint = 0;
    NumberOfSection = 0;
    EntryPointOffset = 0;
    Error = NoError;
    SectionEntrys = NULL;
}
//------------------------------------------------------------------------------
BPeFile::BPeFile(BPeFile& PeFile)
{
    ImageBase = 0;
    ImageSize = 0;
    EntryPoint = 0;
    NumberOfSection = 0;
    EntryPointOffset = 0;
    Error = NoError;
    SectionEntrys = NULL;
    *this = PeFile;
}
//------------------------------------------------------------------------------
BOOL BPeFile::Open(TCHAR* FileName, DWORD Access)
{
    if (Access == AccessReadWrite) 
    {
        if (OpenTemp(FileName) == FALSE)
        {
            Error = NotOpen;
            return FALSE;
        }
    }
    else
    {
        if (BFile::Open(FileName, Access) == FALSE)
        {
            Error = NotOpen;
            return FALSE;
        }
    }

    Init();
    return TRUE;
}
//------------------------------------------------------------------------------
BOOL BPeFile::Init()
{
    DWORD i;
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS NTHeader;

    Read (&dosHeader, sizeof(IMAGE_DOS_HEADER));
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) // 0x5A4D, MZ
    {
        Error = NotExeFileMZ;
        return FALSE;
    }

    PeOffset = dosHeader.e_lfanew;
    Seek (PeOffset);
    Read (&NTHeader, sizeof(IMAGE_NT_HEADERS));
    if (NTHeader.Signature != IMAGE_NT_SIGNATURE) // 0x00004550, PE00
    {
        Error = NotExeFilePE;
        return FALSE;
    }

    if ((NTHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_I386) || 
        (NTHeader.FileHeader.SizeOfOptionalHeader != 0) &&
        (NTHeader.FileHeader.SizeOfOptionalHeader != sizeof(NTHeader.OptionalHeader)))
    {
        Error = GeneralError;
        return FALSE;
    }

    ImageBase = NTHeader.OptionalHeader.ImageBase;
    ImageSize = NTHeader.OptionalHeader.SizeOfImage;
    FileAlignment = NTHeader.OptionalHeader.FileAlignment;
    EntryPoint = NTHeader.OptionalHeader.AddressOfEntryPoint;
    NumberOfSection = NTHeader.FileHeader.NumberOfSections + 1;
    SectionAlignment = NTHeader.OptionalHeader.SectionAlignment;

    DWORD iSeek = NTHeader.FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER);

    Seek(iSeek, FILE_CURRENT);

    SectionEntrys = new IMAGE_SECTION_HEADER[NumberOfSection];
    SectionOffset = new DWORD[NumberOfSection];

    SectionOffset[0] = PeOffset + sizeof(IMAGE_NT_HEADERS) - SECTION_SIZE;
    memset(&SectionEntrys[0], 0, SECTION_SIZE);
    memcpy(SectionEntrys[0].Name, "Header\0\0", 8);
    SectionEntrys[0].SizeOfRawData = PeOffset + sizeof(IMAGE_NT_HEADERS) + (NumberOfSection-1) * SECTION_SIZE;
    SectionEntrys[0].Misc.VirtualSize = NTHeader.OptionalHeader.SizeOfHeaders;
    // SectionEntrys[0].VirtualAddress = NTHeader.OptionalHeader.ImageBase;

    for (i = 1; i < NumberOfSection; i++)
    {
        Read(&SectionEntrys[i], SECTION_SIZE);
        SectionOffset[i] = SectionOffset[i-1] + SECTION_SIZE;
        // SectionEntrys[i].Misc.VirtualSize = DoAlignment(SectionEntrys[i].Misc.VirtualSize, SectionAlignment) 
        // SectionEntrys[i].SizeOfRawData = DoAlignment(SectionEntrys[i].SizeOfRawData, FileAlignment)
    }

    EntryPointOffset = ConvertRvaToOffset(EntryPoint);
    return TRUE;
}
//------------------------------------------------------------------------------
DWORD BPeFile::ConvertAddressToOffset(DWORD Address)
{
    return ConvertRvaToOffset(Address - ImageBase);
}
//------------------------------------------------------------------------------
DWORD BPeFile::ConvertRvaToOffset(DWORD RVA)
{
    IMAGE_SECTION_HEADER* Section;
    Section = ReadSectionEntryForRVA(RVA);
    return (Section == NULL)? 0 : (RVA - Section->VirtualAddress) + Section->PointerToRawData;
}
//------------------------------------------------------------------------------
IMAGE_SECTION_HEADER* BPeFile::ReadLastSectionEntry()
{
    DWORD MaxOffset = 0, index = 0;
    if ((SectionEntrys == NULL) || NumberOfSection == 0)
        return NULL;

    for (DWORD i = 0; i < NumberOfSection; i++)
    {
        if (SectionEntrys[i].PointerToRawData > MaxOffset)
        {
            index = i;
            MaxOffset = SectionEntrys[i].PointerToRawData;
        }
    }
    return &SectionEntrys[index];
}
//------------------------------------------------------------------------------
IMAGE_SECTION_HEADER* BPeFile::ReadSectionEntryForOffset(DWORD Offset)
{
    DWORD Start, End;
    for (DWORD i = 0; i < NumberOfSection; i++)
    {
        Start = SectionEntrys[i].PointerToRawData;
        End   = SectionEntrys[i].PointerToRawData + DoAlignment(SectionEntrys[i].SizeOfRawData, FileAlignment);
        if (Offset >= Start && Offset < End)
            return &SectionEntrys[i];
    }
    return NULL;
}
//------------------------------------------------------------------------------
IMAGE_SECTION_HEADER* BPeFile::ReadSectionEntryForRVA(DWORD RVA)
{
    DWORD Start, End;
    for (DWORD i = 0; i < NumberOfSection; i++)
    {
        Start = SectionEntrys[i].VirtualAddress;
        End   = SectionEntrys[i].VirtualAddress + DoAlignment(SectionEntrys[i].Misc.VirtualSize, SectionAlignment);
        if (RVA >= Start && RVA < End)
            return &SectionEntrys[i];
    }
    return NULL;
}
//------------------------------------------------------------------------------
#if defined(Behpad) || defined(Zeynali)
BOOL BPeFile::ZeroBlockEndSection(DWORD Offset)
{
    IMAGE_SECTION_HEADER* SectionEntry = ReadSectionEntryForOffset(Offset);

    if (SectionEntry == NULL)
        return FALSE;

    DWORD Size = SectionEntry->PointerToRawData + DoAlignment(SectionEntry->SizeOfRawData, FileAlignment) - Offset; // Todo
    Seek(Offset);
    if (WriteZero(Size) != Size)
        return FALSE;
    
    return TRUE;
}
//------------------------------------------------------------------------------
BOOL BPeFile::ZeroSection(DWORD Offset)
{
    IMAGE_SECTION_HEADER* SectionEntry = ReadSectionEntryForOffset(Offset);
    DWORD index = (SectionEntrys - SectionEntry);
    DWORD Size = DoAlignment(SectionEntry->SizeOfRawData, FileAlignment); // Todo

    Seek(SectionEntry->PointerToRawData);
    if (WriteZero(Size) != Size)
        return FALSE;
    
    Seek(SectionOffset[index]);
    if (WriteZero(SECTION_SIZE) != SECTION_SIZE)
        return FALSE;

    memset(SectionEntry, 0, SECTION_SIZE);
    return TRUE;
}
//------------------------------------------------------------------------------
ErrorMessage BPeFile::DeleteSection(DWORD Offset)
{
    void* p = NULL;
    DWORD NumberOfSectionOffset = PeOffset + (DWORD)&(((IMAGE_NT_HEADERS*)p)->FileHeader.NumberOfSections);
    DWORD ImageSizeOffset       = PeOffset + (DWORD)&(((IMAGE_NT_HEADERS*)p)->OptionalHeader.SizeOfImage);

    IMAGE_SECTION_HEADER* SectionEntry = ReadSectionEntryForOffset(Offset);
    DWORD index = (SectionEntry - SectionEntrys);
    DWORD Size = 0, ReadOffset = 0;
    BYTE* Buffer;

    if (index == 0 || Offset == 0) // Todo
        return DisInfectedIncomplete;

    // Delete Section
    ReadOffset = SectionEntry->PointerToRawData + DoAlignment(SectionEntry->SizeOfRawData, FileAlignment); // Todo
    Size = GetFileSize() - ReadOffset;
    
    if (Size > 0)
    {
        Buffer = new BYTE[Size];
        if (Buffer == NULL)
            return BufferNonAllocated;

        Seek(ReadOffset);
        if (Read(Buffer, Size) != Size)
            return NotRead;
    
        Seek(SectionEntry->PointerToRawData);
        if (Write(Buffer, Size) != Size)
            return NotWrite;

        delete []Buffer;
    }

    Truncate(SectionEntry->PointerToRawData + Size);

    // Delete SectionEntry
    Seek(SectionOffset[index]);
    if (WriteZero(SECTION_SIZE) != SECTION_SIZE)
        return NotWrite;

    // Decrement NumberOfSections
    if (index == NumberOfSection-1)
    {
        NumberOfSection--;
        Seek(NumberOfSectionOffset);
        WORD Temp = (WORD)(NumberOfSection - 1);
        Write(&Temp, sizeof(WORD));
    }

    // Modify ImageSize
    ImageSize -= SectionEntry->Misc.VirtualSize;
    Seek(ImageSizeOffset);
    Write(&ImageSize, sizeof(ImageSize));
    
    memset(SectionEntry, 0, SECTION_SIZE);
    return NoError;
}
//------------------------------------------------------------------------------
ErrorMessage BPeFile::DeleteBlockFromSection(DWORD Offset, DWORD Size)
{
    void* p = NULL;
    DWORD NumberOfSectionOffset = PeOffset + (DWORD)&(((IMAGE_NT_HEADERS*)p)->FileHeader.NumberOfSections);
    DWORD ImageSizeOffset       = PeOffset + (DWORD)&(((IMAGE_NT_HEADERS*)p)->OptionalHeader.SizeOfImage);
    IMAGE_SECTION_HEADER* SectionEntry = ReadSectionEntryForOffset(Offset);
    DWORD index = (SectionEntry - SectionEntrys);
    int   ReadSize = 0;
    DWORD WriteSize = 0;
    BYTE* Buffer;
    
    if (index == 0 || Offset == 0) // Todo
        return DisInfectedIncomplete;
    // Delete Block From Section
    ReadSize = GetFileSize() - (Offset + Size);
    
    if (ReadSize > 0)
    {
        Buffer = new BYTE[ReadSize];
        if (Buffer == NULL)
            return BufferNonAllocated;

        Seek(Offset + Size);
        if (Read(Buffer, ReadSize) != ReadSize)
            return NotRead;
    
        Seek(Offset);
        WriteSize = SectionEntry->PointerToRawData + DoAlignment(SectionEntry->SizeOfRawData, FileAlignment) - (Offset + Size); // Todo
        if (Write(Buffer, WriteSize) != WriteSize)
            return NotWrite;

        Truncate(Offset + WriteSize);
        Truncate(DoAlignment(Offset + WriteSize, FileAlignment));

        if (Write(Buffer + WriteSize, ReadSize - WriteSize) != ReadSize - WriteSize)
            return NotWrite;

        delete []Buffer;
    }
    else
    {
        Truncate(Offset);
        Truncate(DoAlignment(Offset, FileAlignment));
    }

    // Modify SectionEntry
    SectionEntry->SizeOfRawData = DoAlignment(Offset - SectionEntry->PointerToRawData, FileAlignment); // Todo
    SectionEntry->Misc.VirtualSize = DoAlignment(Offset - SectionEntry->PointerToRawData, SectionAlignment);

    Seek(SectionOffset[index]);
    if (Write(SectionEntry, SECTION_SIZE) != SECTION_SIZE)
        return NotWrite;

    // Modify ImageSize
    ImageSize = SectionEntry->VirtualAddress + SectionEntry->Misc.VirtualSize;
    Seek(ImageSizeOffset);
    if (Write(&ImageSize, sizeof(ImageSize)) != sizeof(ImageSize))
        return NotWrite;
    
    return NoError;
}
//------------------------------------------------------------------------------
ErrorMessage BPeFile::DeleteBlockFromEndOfSection(DWORD Offset)
{
    IMAGE_SECTION_HEADER* SectionEntry = ReadSectionEntryForOffset(Offset);
    if (SectionEntry == NULL)
        return GeneralError;

    if (Offset == SectionEntry->PointerToRawData)
        return DeleteSection(Offset);
    else
        return DeleteBlockFromSection(Offset, SectionEntry->PointerToRawData + SectionEntry->SizeOfRawData - Offset); // Todo Align
}
//------------------------------------------------------------------------------
ErrorMessage BPeFile::ChangeEntryPoint(DWORD OriginalEntryPoint)
{
    void* p = NULL;
    DWORD EntryPointOffset = PeOffset + (DWORD)&(((IMAGE_NT_HEADERS*)p)->OptionalHeader.AddressOfEntryPoint);
    Seek(EntryPointOffset);
    if (Write(&OriginalEntryPoint, 4) != 4)
        return NotWrite;
    return NoError;
}
//------------------------------------------------------------------------------
ErrorMessage BPeFile::WriteEntryPoint(PVOID Buffer, UINT Size)
{
    Seek(EntryPointOffset);
    if (Write(Buffer, Size) != Size)
        return NotWrite;
    return NoError;
}
//------------------------------------------------------------------------------
BOOL BPeFile::CleanEndOfFile ()
{
    DWORD Size, i;
    BYTE *Buffer;
    DWORD EndPeFile;
    IMAGE_SECTION_HEADER* SectionEntry = ReadLastSectionEntry();
    if (SectionEntry == NULL)
        return FALSE;

    EndPeFile = SectionEntry->PointerToRawData + DoAlignment(SectionEntry->SizeOfRawData, FileAlignment);
    if (GetFileSize() <= EndPeFile)
        return FALSE;

    Size = GetFileSize() - EndPeFile;
    Buffer = new BYTE[Size];

    if (Buffer == NULL)
        return FALSE;

    Seek(EndPeFile);
    if (Read(Buffer, Size) < Size)
        return FALSE;

    for (i = 0; i < Size; i++)
        if (Buffer[i] != 0)
            break;

    if (i != Size)
        return FALSE;

    Truncate(EndPeFile);
    return TRUE;
}
#endif
//------------------------------------------------------------------------------