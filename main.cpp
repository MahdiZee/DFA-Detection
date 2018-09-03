#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "BPeFile.h"
#include "BMemoryManager.h"
#include "Scan.h"
#include "ScanGeneral.h"
#include "FullDetect.h"

BPeFile* PeFile;
BMemoryManager* MemoryManager;
//---------------------------------------------------------------------------------------------------------------------
BOOL APIENTRY DllMain (HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    return TRUE;
}
//---------------------------------------------------------------------------------------------------------------------
__declspec(dllexport) DWORD HasPolyMorphicInfection (TCHAR* FileName, BehpadOpertionType OpertionType, void* Result)
{
    if (Result == NULL)
        return ResultNonValid;

    PeFile = new BPeFile();
    if (PeFile == NULL || PeFile->Open (FileName) == FALSE)
    {
        delete PeFile;
        return PeFile->Error;
    }

    MemoryManager = new BMemoryManager(PeFile);
    if (MemoryManager == NULL)
    {
        delete PeFile;
        delete MemoryManager;
        return GeneralError;
    }

    Scan(PeFile->EntryPoint + PeFile->ImageBase, OpertionType, (InfectionResult*)Result);
    
    delete PeFile;
    delete MemoryManager;
    return NoError;
}
//---------------------------------------------------------------------------------------------------------------------
__declspec(dllexport) DWORD HasPolyMorphicInfectionEOF (TCHAR* FileName, BehpadOpertionType OpertionType, void* Result)
{
    InfectionResult* result = (InfectionResult*)Result;
    if (Result == NULL)
        return ResultNonValid;

    PeFile = new BPeFile();
    if (PeFile == NULL || PeFile->Open (FileName) == FALSE)
    {
        delete PeFile;
        return PeFile->Error;
    }

    MemoryManager = new BMemoryManager(PeFile);
    if (MemoryManager == NULL)
    {
        delete PeFile;
        delete MemoryManager;
        return GeneralError;
    }

    result->State = VIRUSFREE;

    for (int i = 0; i < NUMBER_OF_ARRAY(ListVirutClean); i++)
        if (DetectVirutEOF (ListVirutClean + i, OpertionType, result) != NO_INFECTION)
            break;
    
    delete PeFile;
    delete MemoryManager;
    return NoError;
}
#if defined(Behpad) || defined(Zeynali)
//---------------------------------------------------------------------------------------------------------------------
ErrorMessage DisInfectVirus (BPeFile* PeFile, DWORD OffsetInfection, DWORD OffsetStub)
{
    IMAGE_SECTION_HEADER* InfectionSection = NULL;
    IMAGE_SECTION_HEADER* StubSection = NULL;
    ErrorMessage Error = NoError;

    if (OffsetStub == 0 || OffsetInfection == OffsetStub)
        return PeFile->DeleteBlockFromEndOfSection(OffsetInfection);

    InfectionSection = PeFile->ReadSectionEntryForOffset(OffsetInfection);
    StubSection = PeFile->ReadSectionEntryForOffset(OffsetStub);
    if (StubSection == InfectionSection)
        return PeFile->DeleteBlockFromEndOfSection(OffsetStub);

    Error = PeFile->DeleteBlockFromEndOfSection(OffsetInfection);
    if (Error != NoError)
        return Error;
    
    if(PeFile->ZeroBlockEndSection(OffsetStub) == FALSE)
        return NotWrite;

    return NoError;
}
#endif
//---------------------------------------------------------------------------------------------------------------------
#if defined(Behpad) || defined(Zeynali)
__declspec(dllexport) DWORD DisInfectReparableOverWrite (TCHAR* FileName, void* Result)
{
    BPeFile* PeFile = NULL;
    InfectionResult* result = (InfectionResult*)Result;
    ErrorMessage Error = NoError;

    if (Result == NULL)
        return ResultNonValid;

    if (result->State != INFECTED || result->Method != ReparableOverWrite)
        return NoError;

    PeFile = new BPeFile();
    if (PeFile == NULL)
        return BufferNonAllocated;

    if (PeFile->Open (FileName, AccessReadWrite) == FALSE)
    {
        delete PeFile;
        return PeFile->Error;
    }
    
    Error = PeFile->WriteEntryPoint(result->Row.EntryPointOwerWrite, result->Row.EntryPointOwerWriteLenght);
    if (Error !=  NoError)
    {
        delete PeFile;
        return Error;
    }

    Error = PeFile->DeleteBlockFromEndOfSection(result->StartInfection);
    if (Error != NoError)
    {
        delete PeFile;
        return Error;
    }

    delete PeFile;
    return NoError;
}
#endif
//---------------------------------------------------------------------------------------------------------------------
#if defined(Behpad) || defined(Zeynali)
__declspec(dllexport) DWORD DisInfectChangedEntryPoint (TCHAR* FileName, void* Result)
{
    BPeFile* PeFile = NULL;
    InfectionResult* result = (InfectionResult*)Result;
    ErrorMessage Error = NoError;

    if (Result == NULL)
        return ResultNonValid;

    if (result->State != INFECTED || result->Method != ChangedEntryPoint)
        return NoError;

    PeFile = new BPeFile();
    if (PeFile == NULL)
        return BufferNonAllocated;

    if (PeFile->Open (FileName, AccessReadWrite) == FALSE)
    {
        delete PeFile;
        return PeFile->Error;
    }

    Error = PeFile->ChangeEntryPoint(result->Che.OrignalEntryPoint);
    if (Error != NoError)
    {
        delete PeFile;
        return Error;
    }

    Error = DisInfectVirus(PeFile, result->StartInfection, result->StartStub);
    if (Error != NoError)
    {
        delete PeFile;
        return Error;
    }

    delete PeFile;
    return NoError;
}
#endif
//---------------------------------------------------------------------------------------------------------------------
#if defined(Behpad) || defined(Zeynali)
__declspec(dllexport) DWORD DisInfectChangedRoutin (TCHAR* FileName, void* Result)
{
    BPeFile* PeFile = NULL;
    InfectionResult* result = (InfectionResult*)Result;
    ErrorMessage Error = NoError;

    if (Result == NULL)
        return ResultNonValid;

    if (result->State != INFECTED || result->Method != ChangedRoutin)
        return NoError;

    PeFile = new BPeFile();
    if (PeFile == NULL)
        return BufferNonAllocated;

    if (PeFile->Open (FileName, AccessReadWrite) == FALSE)
    {
        delete PeFile;
        return PeFile->Error;
    }

    if (result->Chr.OffsetInfection != 0)
    {
        PeFile->Seek(result->Chr.OffsetInfection);
        if (PeFile->Write(result->Chr.RoutinOwerWrite, result->Chr.RoutinOwerWriteLenght) != result->Chr.RoutinOwerWriteLenght)
        {
            delete PeFile;
            return NotWrite;
        }
    }

    Error = DisInfectVirus(PeFile, result->StartInfection, result->StartStub);
    if (Error != NoError)
    {
        delete PeFile;
        return Error;
    }

    delete PeFile;
    return NoError;
}
#endif
//---------------------------------------------------------------------------------------------------------------------
#if defined(Behpad) || defined(Zeynali)
__declspec(dllexport) DWORD DisInfectWithOutEntryPoint (TCHAR* FileName, void* Result)
{
    BPeFile* PeFile = NULL;
    InfectionResult* result = (InfectionResult*)Result;
    ErrorMessage Error = NoError;

    if (Result == NULL)
        return ResultNonValid;

    if (result->State != INFECTED || result->Method != WithOutEntryPoint)
        return NoError;

    PeFile = new BPeFile();
    if (PeFile == NULL)
        return BufferNonAllocated;

    if (PeFile->Open (FileName, AccessReadWrite) == FALSE)
    {
        delete PeFile;
        return PeFile->Error;
    }
    
    if (PeFile->Truncate(result->StartInfection) == FALSE)
    {
        delete PeFile;
        return Error;
    }

    delete PeFile;
    return NoError;
}
#endif
//---------------------------------------------------------------------------------------------------------------------
#if defined(Behpad) || defined(Zeynali)
__declspec(dllexport) DWORD CleanEndOfFile (TCHAR* FileName)
{
    BPeFile* PeFile = NULL;
    ErrorMessage Error = NoError;

    PeFile = new BPeFile();
    if (PeFile == NULL)
        return BufferNonAllocated;

    if (PeFile->Open (FileName, AccessReadWrite) == FALSE)
    {
        delete PeFile;
        return PeFile->Error;
    }

    PeFile->CleanEndOfFile();

    delete PeFile;
    return NoError;
}
#endif
//---------------------------------------------------------------------------------------------------------------------
