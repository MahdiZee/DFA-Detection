#include "windows.h"
#include "stdio.h"
#include "ScanGeneral.h"

char *InfectionMethodMessage[4] =
{
    "che",
    "row",
    "chr",
    "woe"
};

typedef DWORD (*DllHasPolyMorphicInfection)(TCHAR*,BehpadOpertionType, void*);
typedef DWORD (*DllCleanEndOfFile)(TCHAR*);
typedef DWORD (*DllDisInfect)(TCHAR* FileName, void* Result);

bool ScanPath(LPCTSTR Path, bool Dir = false);
DllHasPolyMorphicInfection HasPolyMorphicInfection = NULL;
DllHasPolyMorphicInfection HasPolyMorphicInfectionEOF = NULL;
DllDisInfect DisInfectReparableOverWrite = NULL;
DllDisInfect DisInfectChangedEntryPoint = NULL;
DllDisInfect DisInfectWithOutEntryPoint = NULL;
DllDisInfect DisInfectChangedRoutin = NULL;
DllCleanEndOfFile CleanEndOfFile = NULL;
InfectionResult result;

int main(int argc, char* argv[])
{
    HMODULE hModule = LoadLibrary("DetectPolyVirus.dll");
    if (hModule == NULL)
        return 1;

    HasPolyMorphicInfection     = (DllHasPolyMorphicInfection)GetProcAddress(hModule, "?HasPolyMorphicInfection@@YAKPADW4BehpadOpertionType@@PAX@Z");
    HasPolyMorphicInfectionEOF  = (DllHasPolyMorphicInfection)GetProcAddress(hModule, "?HasPolyMorphicInfectionEOF@@YAKPADW4BehpadOpertionType@@PAX@Z");
    DisInfectReparableOverWrite = (DllDisInfect)GetProcAddress(hModule, "?DisInfectReparableOverWrite@@YAKPADPAX@Z");
    DisInfectChangedEntryPoint  = (DllDisInfect)GetProcAddress(hModule, "?DisInfectChangedEntryPoint@@YAKPADPAX@Z");
    DisInfectWithOutEntryPoint  = (DllDisInfect)GetProcAddress(hModule, "?DisInfectWithOutEntryPoint@@YAKPADPAX@Z");
    DisInfectChangedRoutin      = (DllDisInfect)GetProcAddress(hModule, "?DisInfectChangedRoutin@@YAKPADPAX@Z");
    CleanEndOfFile              = (DllCleanEndOfFile)GetProcAddress(hModule, "?CleanEndOfFile@@YAKPAD@Z");

    if (HasPolyMorphicInfection     == NULL || 
        HasPolyMorphicInfectionEOF  == NULL || 
        DisInfectReparableOverWrite == NULL || 
        DisInfectChangedEntryPoint  == NULL ||
        DisInfectWithOutEntryPoint  == NULL ||
        DisInfectChangedRoutin      == NULL ||
        CleanEndOfFile              == NULL
       )
    {
        DWORD Error = GetLastError();
        printf("%d", Error);
        FreeLibrary(hModule);
        return 1;
    }
    ScanPath("D:\\Virus\\Test\\");
    FreeLibrary(hModule); 
    return 0;
}
//------------------------------------------------------------------------------------------
bool ScanPath(LPCTSTR Path, bool Dir)
{
    static int      NumberOfVirus = 0;
    static int      NumberOfFileScan = 0;
    HANDLE          hFoundFile;
    TCHAR           TempPath [MAX_PATH];
    WIN32_FIND_DATA FindFileData;
    int             aFileVirus;

    SetCurrentDirectory (Path);
    hFoundFile  = FindFirstFile ("*.*", &FindFileData);

    if (hFoundFile == INVALID_HANDLE_VALUE)
        return false;

    __try
    {
        do
        {
            lstrcpy (TempPath, Path);
            if (FindFileData.cFileName[0] == '.')
                continue;

            if ((lstrlen (TempPath) + lstrlen (FindFileData.cFileName)) > MAX_PATH)
                continue;
            else
                lstrcat (TempPath, FindFileData.cFileName);

            if ( FindFileData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY )
            {
                if ((lstrlen (TempPath) + lstrlen ("\\")) > MAX_PATH)
                    continue;
                else
                    lstrcat (TempPath, "\\");
                
                if (ScanPath (TempPath, true))
                    SetCurrentDirectory ("..");
            }
            else
            {
                bool IsVirus = false;
                NumberOfFileScan++;
                aFileVirus = 0;
                do
                {
                    memset(&result, 0, sizeof(result));
                    HasPolyMorphicInfection (FindFileData.cFileName, DisInfect, &result);
                    if (result.State != VIRUSFREE)
                    {
                        IsVirus = true;
                        NumberOfVirus++;
                        aFileVirus++;
                        int a = 50 - (strlen(Path) + strlen(FindFileData.cFileName));

                        if (aFileVirus == 1)
                            printf("%s%s%*d.%s%s", Path, FindFileData.cFileName, a, 
                                    result.VirusNo, 
                                    InfectionMethodMessage[result.Method], 
                                    (result.State==SUSPICIOUS)?".hure":"");
                        else
                            printf(" %d.%s%s", result.VirusNo, InfectionMethodMessage[result.Method], (result.State==SUSPICIOUS)?".hure":"");

                        if (DisInfectReparableOverWrite (FindFileData.cFileName, &result) != NoError)
                            break;
                        if (DisInfectChangedEntryPoint (FindFileData.cFileName, &result) != NoError)
                            break;
                        if (DisInfectChangedRoutin (FindFileData.cFileName, &result) != NoError)
                            break;
                    }
                }while (result.State == INFECTED);

                do
                {
                    memset(&result, 0, sizeof(result));
                    HasPolyMorphicInfectionEOF (FindFileData.cFileName, DisInfect, &result);
                    if (result.State == INFECTED)
                    {
                        IsVirus = true;
                        aFileVirus++;
                        int a = 50 - (strlen(Path) + strlen(FindFileData.cFileName));
                        if (aFileVirus == 1)
                            printf("%s%s%*d.%s%s", Path, FindFileData.cFileName, a, 
                                    result.VirusNo, 
                                    InfectionMethodMessage[result.Method], 
                                    (result.State==SUSPICIOUS)?".hure":"");
                        else
                            printf(" %d.%s%s", result.VirusNo, InfectionMethodMessage[result.Method], (result.State==SUSPICIOUS)?".hure":"");

                        if (DisInfectWithOutEntryPoint (FindFileData.cFileName, &result) != NoError)
                            break;
                    }
                }while (result.State == INFECTED || result.State == SUSPICIOUS);

                if (IsVirus)
                    CleanEndOfFile(FindFileData.cFileName);

                if (aFileVirus > 0)
                    printf("\n");
            }
        }
        while ((FindNextFile (hFoundFile, &FindFileData)));
    }
    __finally
    {
        printf ("Number Of File Scan : %d\n", NumberOfFileScan);
        printf ("Number Of Virus : %d\n", NumberOfVirus);
        FindClose (hFoundFile);
    }

    if (Dir)
        SetCurrentDirectory ("..");

    return true;
}
