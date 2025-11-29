#include "stdio.h"
#include "string.h"

#include "ZMemoryManager.h"
#include "ZPeFile.h"
#include "ZFile.h"
#include "Type.h"

MemBlockEntry gMemoryManagerMemEntry;

ZMemoryManager::ZMemoryManager(ZPeFile* PeFile)
{
    mPeFile = PeFile;
    TopEntry = 0;
    memset(MemBlock,0,sizeof(MemBlock));
}
ZMemoryManager::~ZMemoryManager()
{
}
//-------------------------------------------------------------------------------------------
int ZMemoryManager::GetValue(DWORD Address, PBYTE Value, DWORD Len)
{
    DWORD ofs, rel;
    DWORD Len1, Len2, Len3;
    int   entry;
    DWORD cbRead;
    BYTE  Buffer[BLOCK_ENTRY_SIZE];

    ofs = Address &   (0xffffffff << ShiftOfBlockSize);
    rel = Address & (~(0xffffffff << ShiftOfBlockSize));

    Len1 = MIN ((BLOCK_ENTRY_SIZE - rel), Len);
    Len2 = Len - Len1;

    entry = SearchBlock(ofs);

    if (entry >= TopEntry)
    {
        if ((cbRead = ReadPeFile(ofs, Buffer)) == 0)
            return 0;
        if (cbRead < Len1)
        {
            Len2 = 0;
            Len1 = cbRead;
        }
        memcpy(Value, Buffer + rel, Len1);

        memcpy(&(MemBlock[entry].Value), Buffer, cbRead);
        MemBlock[entry].Address = ofs;
        TopEntry++;
    }
    else
    {
        memcpy(Value, (PBYTE)&(MemBlock[entry].Value) + rel, Len1);
    }

    while (Len2 > 0)
    {
        Len3 = MIN(Len2, BLOCK_ENTRY_SIZE);
        ofs += BLOCK_ENTRY_SIZE;
        entry = SearchBlock(ofs);

        if (entry >= TopEntry)
        {
            if ((cbRead = ReadPeFile(ofs, Buffer)) == 0)
                return Len1;
            if (cbRead < Len3) 
            {
                Len2 = cbRead;
                Len3 = cbRead;
            }
            memcpy(Value + Len1, Buffer, Len3);
            memcpy(&(MemBlock[entry].Value), Buffer, cbRead);
            MemBlock[entry].Address = ofs;
            TopEntry++;
        }
        else
        {
            memcpy(Value + Len1, &(MemBlock[entry].Value), Len3);
        }

        Len1 += Len3;
        Len2 -= Len3;
    }

    return Len1;
}

//-------------------------------------------------------------------------------------------
int ZMemoryManager::SetValue(DWORD Address, PBYTE Value, DWORD Len)
{
    DWORD ofs, rel;
    DWORD Len1, Len2, Len3;
    int   entry;
    DWORD cbRead;
    BYTE  Buffer[BLOCK_ENTRY_SIZE];

    ofs = Address &   (0xffffffff << ShiftOfBlockSize);
    rel = Address & (~(0xffffffff << ShiftOfBlockSize));

    Len1 = MIN ((BLOCK_ENTRY_SIZE - rel), Len);
    Len2 = Len - Len1;

    if ((entry = SearchBlock(ofs)) >= MAX_MEM_BLOCK_ENTRY)
    {
        return 0;
    }
    if (entry >= TopEntry)
    {
        if ((cbRead = ReadPeFile(ofs, Buffer)) == 0)
        {
            return 0;
        }
        memset(&(MemBlock[entry].Value), 0, BLOCK_ENTRY_SIZE);
        memcpy(&(MemBlock[entry].Value), Buffer, cbRead);
        memcpy((PBYTE)&(MemBlock[entry].Value) + rel, Value, Len1);
        MemBlock[entry].Address = ofs;
        TopEntry++;
    }
    else
    {
        memcpy((PBYTE)&(MemBlock[entry].Value)+rel, Value, Len1);
    }

    while (Len2 > 0)
    {
        ofs += BLOCK_ENTRY_SIZE;
        Len3 = MIN(Len2, BLOCK_ENTRY_SIZE);

        if ((entry = SearchBlock(ofs)) >= MAX_MEM_BLOCK_ENTRY)
        {
            return Len1;
        }

        if (entry >= TopEntry)
        {
            if ((cbRead = ReadPeFile(ofs, Buffer)) == 0)
            {
                return 0;
            }
            memset(&(MemBlock[entry].Value), 0, BLOCK_ENTRY_SIZE);
            memcpy(&(MemBlock[entry].Value), Buffer, cbRead);
            memcpy(&(MemBlock[entry].Value), Value + Len1, Len3);
            MemBlock[entry].Address = ofs;
            TopEntry++;
        }
        else
        {
            memcpy(&(MemBlock[entry].Value), Value + Len1, Len3);
        }

        Len1 += Len3;
        Len2 -= Len3;
    }
    return Len1;
}

//-------------------------------------------------------------------------------------------
int ZMemoryManager::SearchBlock(DWORD Address)
{
    for (int i = 0; i < TopEntry; i++)
    {
        if (MemBlock[i].Address == Address)
            return i;
    }
    return TopEntry;
}
//-------------------------------------------------------------------------------------------
DWORD ZMemoryManager::ReadPeFile(DWORD Address, PBYTE Buffer)
{
    DWORD bytes;
    DWORD FilePointer;

    FilePointer = mPeFile->ConvertAddressToOffset(Address);
    if (FilePointer > mPeFile->GetFileSize())
        return 0;

    mPeFile->Seek(FilePointer);
    if ((bytes = mPeFile->Read(Buffer, BLOCK_ENTRY_SIZE)) < 1)
        return 0;

    return bytes;
}