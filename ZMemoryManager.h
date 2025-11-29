#ifndef ZMemoryManagerH
#define ZMemoryManagerH

#include "windows.h" 
#include "ZPeFile.h" 

#define ShiftOfBlockSize    (6)
#define BLOCK_ENTRY_SIZE    (1 << ShiftOfBlockSize)
#define MAX_MEM_BLOCK_ENTRY (1024)

typedef struct _MemBlockEntry
{
   DWORD Address;
   BYTE  Value[BLOCK_ENTRY_SIZE];
} MemBlockEntry, *PMemBlockEntry;

class ZMemoryManager
{
private:
    ZPeFile *mPeFile;
    MemBlockEntry MemBlock[MAX_MEM_BLOCK_ENTRY];
    int TopEntry;
private:
    int SearchBlock(DWORD Address);
    DWORD ReadPeFile(DWORD Address, PBYTE Buff);
public:
    ~ZMemoryManager();
    ZMemoryManager(ZPeFile* PeFile);
    int GetValue(DWORD Address, PBYTE Value, DWORD Len);
    int SetValue(DWORD Address, PBYTE Value, DWORD Len);
};

extern MemBlockEntry gMemoryManagerMemEntry;
#endif // MemoryMangerH
