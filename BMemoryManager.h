#ifndef BMemoryManagerH
#define BMemoryManagerH

#include "windows.h" 
#include "BPeFile.h" 

#define ShiftOfBlockSize    (6)
#define BLOCK_ENTRY_SIZE    (1 << ShiftOfBlockSize)
#define MAX_MEM_BLOCK_ENTRY (1024)

typedef struct _MemBlockEntry
{
   DWORD Address;
   BYTE  Value[BLOCK_ENTRY_SIZE];
} MemBlockEntry, *PMemBlockEntry;

class BMemoryManager
{
private:
    BPeFile *mPeFile;
    MemBlockEntry MemBlock[MAX_MEM_BLOCK_ENTRY];
    int TopEntry;
private:
    int SearchBlock(DWORD Address);
    DWORD ReadPeFile(DWORD Address, PBYTE Buff);
public:
    ~BMemoryManager();
    BMemoryManager(BPeFile* PeFile);
    int GetValue(DWORD Address, PBYTE Value, DWORD Len);
    int SetValue(DWORD Address, PBYTE Value, DWORD Len);
};

extern MemBlockEntry gMemoryManagerMemEntry;
#endif // MemoryMangerH
