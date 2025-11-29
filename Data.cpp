#include "string.h"

#include "Data.h"
#include "Scan.h"
#include "BPeFile.h"
#include "Function.h"
#include "BMemoryManager.h"
#include "DisasmbleTable.h"

extern WORD GrpPrefix[4];
extern BYTE FS_Segment[FS_SEGMENT_SIZE];
extern BPeFile* PeFile;
extern BMemoryManager* MemoryManager;

bool FlagEndBuf = false;
DWORD EIP;
DWORD ThresholdOfBufferShouldBeCached; // Threshold of caching in our memory manager

extern BYTE  Stack[5000];
extern PBYTE TopStack;
//------------------------------------------------------------------------------
int BufferIsEnd ()
{
    return FlagEndBuf;
}
//------------------------------------------------------------------------------
void BufferEnd()
{
    FlagEndBuf = true;
}
//------------------------------------------------------------------------------
void BufferInit()
{
    FlagEndBuf = false;
    ThresholdOfBufferShouldBeCached = 2048;
}
//------------------------------------------------------------------------------
void SetThresholdOfBufferShouldBeCached(DWORD Threshold)
{
    ThresholdOfBufferShouldBeCached = Threshold;
}
//------------------------------------------------------------------------------
void* BufferGet (DWORD Address)
{
    EmulReadError = 0;

    // we should consider a buffer for FS & SS
    // later ...

    if (Address > DefaultESP - STACK_SIZE && Address < DefaultESP)
    {
        return END_OF_STACK - (DefaultESP - Address);
    }

    if (Address < PeFile->ImageBase || Address > PeFile->ImageBase + PeFile->ImageSize)
    {
         return (PVOID)&EmulReadError;
    }

    // we should consider a buffer for FS & SS
    // later ...

    if (SReg[1] == DefaultFS && GrpPrefix[1] == 0) // DS
    {
        GrpPrefix[1] = ID_FS;
    }

    for (int i = 0; i < NUMBER_OF_ARRAY(SReg) && GrpPrefix[1] != ID_FS; i++)
    {
        if ((SReg[i] == DefaultFS) && (GrpPrefix[1] == ID_ES + i))
        {
            GrpPrefix[1] = ID_FS;
            break;
        }
    }

    if (GrpPrefix[1] == ID_FS) // dont operate for fs:[0000]
    { 
        if (Address < FS_SEGMENT_SIZE)
        {
            return FS_Segment + Address;
        }
        else
        {
            return (PVOID)&EmulReadError;
        }
    }

    if (*(PWORD)b == 0x15ff)
    {
        return (PVOID)&EmulReadError;
    }

    if (MemoryManager->GetValue(Address, (PBYTE)&gMemoryManagerMemEntry.Value, 4) == 0)
    {
        return (PVOID)&EmulReadError;
    }

    if ((DWORD)labs((unsigned)EIP - (unsigned)Address) < ThresholdOfBufferShouldBeCached)
    {
        gMemoryManagerMemEntry.Address = Address;
    }

    EmulReadError = 0;
    return &gMemoryManagerMemEntry.Value;
    // return &EmulReadError;
}
//------------------------------------------------------------------------------
void BufferSeek(DWORD Address)
{
    DWORD FilePointer;
    FilePointer = PeFile->ConvertAddressToOffset(Address);
    if (FilePointer <= PeFile->GetFileSize())
        EIP = Address;
    else
        BufferEnd();
}
//------------------------------------------------------------------------------
int BufferRead(int count, PBYTE buffer)
{
    int Read;
    if (count > 6)
    {
        memset(buffer, 0x90, 6);  // fill with "NOP" command
        BufferEnd();
        return 0;
    }

    memset(buffer, 0x90, count);  // fill with "NOP" command

    Read = MemoryManager->GetValue(EIP, buffer, count);
    EIP += Read;

    if (Read < count)
    {
        BufferEnd();
    }

    return Read;
}