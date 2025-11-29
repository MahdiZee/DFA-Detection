#include "Stochastic.h"
#include "ScanGeneral.h"
#include "Message.h"
#include "ZFile.h"
#include "ZPeFile.h"
#include "stdlib.h"

extern ZFile* File;
extern ZPeFile* PeFile;

DWORD FindCallerBranch2(PDWORD CalledRVA, 
                        BYTE CallOrJmpInst, 
                        PHeuristicCallBack HeuristicInitial, 
                        DWORD StartSearch, 
                        IMAGE_SECTION_HEADER* EIPSectionEntry, 
                        IMAGE_SECTION_HEADER* LastSectionEntry);

// Searching non-regular pattern in input buffer
// Note : Patterns must be sorted array
// Sunday 87-12-4
// Mahdi Zeynali

int StochasticCompare(PBYTE p1, PStochasticPattern p2)
{
    int i;

    for (i = 0; i < p2->PatternLen; i++)
    {
        if ((p1[i] & p2->Mask[i]) != p2->Pattern[i])
            return (int)(p1[i] - p2->Pattern[i]);
    }

    return 0;
}

DWORD StochasticPatternSearch(StochasticPattern* Pattern, DWORD PatternsPart, PBYTE Buffer, DWORD LenBuffer)
{
    int i, j;
    WORD SumOfParts = 0, MatchedParts = 0;
    PStochasticPattern pStochasticPattern;
    BYTE PatternOccurance[32];

    if (sizeof(PatternOccurance) < (BYTE)PatternsPart)
    {
        DebugMessage("StochasticPatternSearch: size of PatternOccurance is too low !");
        return 0;
    }

    for (i = 0; i < (int)PatternsPart; i++)
    {
        PatternOccurance[i] = Pattern[i].PatternOccurance;
        SumOfParts         += Pattern[i].PatternOccurance;
    }

    MatchedParts = 0;
    for (i = 0; (DWORD)i < LenBuffer && MatchedParts < SumOfParts; i++)
    {
        pStochasticPattern = (PStochasticPattern) bsearch (Buffer+i, Pattern, PatternsPart, sizeof(StochasticPattern), (fptr)StochasticCompare);
        if (pStochasticPattern == NULL)
            continue;

        j = pStochasticPattern - Pattern;
        if (PatternOccurance[j] != 0)
        {
            PatternOccurance[j]--;
            MatchedParts++;
        }

        for (j = 0; pStochasticPattern->Dependency[j] != END_STOCHASTIC_PATTERN; j++)
        {
            if (PatternOccurance[pStochasticPattern->Dependency[j]] != 0)
            {
                PatternOccurance[pStochasticPattern->Dependency[j]]--;
                MatchedParts++;
            }
        }
    }

    return (UINT)(100*((float)MatchedParts/(float)SumOfParts));
}

//----------------------------------------------------------------------------------------------------
DWORD DetectPolyPart()
{
    int i, index;
    BOOL fMatch = FALSE;
    DWORD CallerFileOffset, JumpedRVA;
    IMAGE_SECTION_HEADER* EIPSectionEntry;
    IMAGE_SECTION_HEADER* LastSectionEntry;

    HeuristicStochastic ArrHeuristicCallBack_AC_Ab[] =
    {
        {{Win32_Virut_AC, DetectVirut_AC, 0, 0, Continue, NULL, NULL}, Virut_AB_Patt2}, 
        {{Win32_Virut_AB, DetectVirut_Z2, 0, 0, Continue, NULL, NULL}, Virut_AC_Patt }
    };

    HeuristicStochastic ArrHeuristicCallBack_AI[] =
    {
        {{Win32_Virut_AI, DetectVirut_AI, 0, 0, Continue, NULL, NULL}, Virut_AI_Patt }
    };

    HeuristicCallBack arrHeuristic[] =
    {
        {0, NULL, 0, 0, Continue, NULL, NULL }, 
        {0, NULL, 0, 0, Continue, NULL, NULL }
    };

    PolyPart arrPolyPart[] =
    {
        {0x4000, 0x4500, 0x650,  ArrHeuristicCallBack_AC_Ab, NUMBER_OF_ARRAY (ArrHeuristicCallBack_AC_Ab)}, 
        {0x4200, 0x4F00, 0x1000, ArrHeuristicCallBack_AI,    NUMBER_OF_ARRAY (ArrHeuristicCallBack_AI)}
    };


    if ((LastSectionEntry = PeFile->ReadLastSectionEntry()) == NULL)
    {
        return 0;
    }

    if ((EIPSectionEntry = PeFile->ReadSectionEntryForRVA(PeFile->EntryPoint)) == NULL)
    {
       return 0;
    }

    //for (i = 0; i < NUMBER_OF_ARRAY(arrPolyPart); i++)
    //{
    //    if ((VirusNo = DetectPolyPartEOS()) != NO_INFECTION)
    //    {
    //        if ((VirusNo & IsLikeVir) == 0) return VirusNo;
    //            TmpVirusNo = VirusNo;
    //    }
    //}

    for (i = 0; i < NUMBER_OF_ARRAY(arrPolyPart); i++)
    {
        index = DetectPolyPartEOF(arrPolyPart + i);
        if (index != (DWORD)-1)
            break;
    }
    if (index != (DWORD)-1)
    {
        arrHeuristic[0] = arrPolyPart[i].VirusHeuristicStochastic[index].VirusHeuristicInitial;
        CallerFileOffset = PeFile->EntryPoint;
        do
        {
            CallerFileOffset = FindCallerBranch2((PDWORD) &JumpedRVA, 0xe9, arrHeuristic, CallerFileOffset, EIPSectionEntry, LastSectionEntry);
            if (((PStructVirut_Z_AB_AC)(arrHeuristic[0].FullDetectArgument))->EntryPoint - PeFile->ImageBase - EIPSectionEntry->VirtualAddress + EIPSectionEntry->PointerToRawData == CallerFileOffset - 1)
                fMatch = TRUE;
        }
        while (fMatch == FALSE && CallerFileOffset != 0);

        if (CallerFileOffset == 0)
        {
            // IsLikeVir
            // State = VIRALSTATE::SUSPICIOUS;
            return arrPolyPart[i].VirusHeuristicStochastic[index].VirusHeuristicInitial.VirusNo;
        }

        if (CallerFileOffset == 0)
            return false;  //Link
#ifdef Zeynali
        PoloyPartInitClean(arrPolyPart[i].VirusHeuristicStochastic[index].VirusHeuristicInitial.FullDetectArgument);
#endif
    }
    return true;  // Todo
}
//----------------------------------------------------------------------------------------------------
DWORD DetectPolyPartEOF(PPolyPart This)
{
    BYTE* DecodersPartBuffer;
    IMAGE_SECTION_HEADER* SectionEntry;
    DWORD FilePtr;
    UINT Percent = 0;
    DWORD i;
    DWORD LastValidOffset = OffsetNotFound;

#if defined(_DEBUG) && defined(Test)
    char FullPathName[0x104];
    extern char f_name[];
#endif

    DecodersPartBuffer = new BYTE[2*This->DecoderPartLen];
    if (DecodersPartBuffer == NULL)
    {
        return (DWORD)-1;
    }

    if ((SectionEntry = PeFile->ReadLastSectionEntry()) == NULL)
    {
        delete[] DecodersPartBuffer;
        return (DWORD)-1;
    }

    if (SectionEntry->SizeOfRawData <= This->MinLen)
    {
        delete[] DecodersPartBuffer;
        return (DWORD)-1;
    }

    // ignores "0"s at the end of last section
    if (LastValidOffset == OffsetNotFound)
    {
        LastValidOffset = PeFile->MianDoSefr(SectionEntry->PointerToRawData + VIRUT_AC_PART2_MIN_LEN, 
                                             SectionEntry->SizeOfRawData - VIRUT_AC_PART2_MIN_LEN,
                                             0);
    }

    FilePtr = LastValidOffset;
    if (FilePtr == OffsetNotFound)
    {
        FilePtr = SectionEntry->PointerToRawData + SectionEntry->SizeOfRawData - 1;
    }

    if (FilePtr < (DWORD)This->MaxLen)
    {
        delete[] DecodersPartBuffer;
        return (DWORD)-1;
    }

    FilePtr -= (DWORD)This->MaxLen;

    PeFile->Seek (FilePtr);
    if (PeFile->Read((PBYTE)(DecodersPartBuffer + This->MaxLen), This->MaxLen) < This->MaxLen)
    {
        delete[] DecodersPartBuffer;
        return (DWORD)-1;
    }

    if (FilePtr < (DWORD)(This->MaxLen - This->DecoderPartLen))
    {
        delete[] DecodersPartBuffer;
        return (DWORD)-1;
    }
    FilePtr -= (DWORD)(This->MaxLen - This->DecoderPartLen);
    if (FilePtr < SectionEntry->PointerToRawData)
    {
        FilePtr = SectionEntry->PointerToRawData;
    }

    PeFile->Seek(FilePtr);
    if ((PeFile->Read((PBYTE)DecodersPartBuffer, This->DecoderPartLen)) < This->DecoderPartLen)
    {
        delete[] DecodersPartBuffer;
        return (DWORD)-1;
    }

    for (i = 0; i < This->CountCallBackEntry && Percent < 100; i++)
    {
        Percent = StochasticPatternSearch(This->VirusHeuristicStochastic->VirusStochasticPattern, NUMBER_OF_ARRAY (This->VirusHeuristicStochastic->VirusStochasticPattern), DecodersPartBuffer, 2*This->DecoderPartLen);
    }

    delete[] DecodersPartBuffer;
    if (i == This->CountCallBackEntry)
        return (DWORD)-1;
    return i;
}
//----------------------------------------------------------------------------------------------------
BOOL PoloyPartInitClean(PVOID Arg)
{
#ifdef AntiVirus
    DWORD CallerFileOffset = 0;
    StructVirut_Z_AB_AC FullDetectArgument = *((StructVirut_Z_AB_AC*)(Arg));

    if (OpertionType == DisInfect)
    {
        if (FullDetectArgument.StartZero == 0)
        {
            // start of part1 that should be wiped is not exist; virus has 1 part
            *(PDWORD)(buff+0)  = FullDetectArgument.StartZero;
        }
        else
        {
            // start of part1 that should be wiped
            *(PDWORD)(buff+0)  = ConvertAddressToOffset(FullDetectArgument.StartZero);
        }

        if (PeFile->ReadSectionEntryForRVA(FullDetectArgument.StartDeCode- ImageBase, (PBYTE)&SectionEntry) == INVALIDSectionEntry)
        {
            return FALSE;
        }

        //*(PDWORD)(buff+4) = FindBlockBetweenZeroBlocksInEndOfSection(&SectionEntry, VIRUT_AC_PART2_MIN_LEN, VIRUT_AC_PART2_MAX_LEN, 8, 0);
        if (*(PDWORD)(buff+4) == OffsetNotFound)
        {
            *(PDWORD)(buff+4) = PeFile->ConvertAddressToOffset(FullDetectArgument.StartDeCode); // start of part2 that should be wiped or truncated
        }
        *(PDWORD)(buff+8) = CallerFileOffset;
        if (FullDetectArgument.MainAPIRVA.dw)
        {
            *(PWORD)(buff+12) = 5;
            *(PDWORD)(buff+14) = FullDetectArgument.MainAPIRVA.s2.dwPart;
            *(PBYTE)(buff+18) = FullDetectArgument.MainAPIRVA.s2.chPart;
        }
        else
        {
            *(PWORD)(buff+12) = 0;
        }
    }
#endif
    return TRUE;
}
//----------------------------------------------------------------------------------------------------
