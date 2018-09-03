#include "BPeFile.h"
#include "Message.h"
#include "FullDetect.h"
#include "Stochastic.h"
#include "BMemoryManager.h"
#include "DisasmbleTable.h"

extern BPeFile* PeFile;
extern BMemoryManager* MemoryManager;

BOOL ComparePattern (PBYTE Src, PBYTE Dst, int Len)
{
    for (int i = 0; i < Len; i++)
        if (Src[i] != Dst[i] && Dst[i] != Dummy)
            return FALSE;

    return TRUE;
}
//---------------------------------------------------------------------------------------------------------------------
#define Sality_DecodeLen (0x6be+0x30)
int FullDetectSality(PVOID objSality, BehpadOpertionType OpertionType, InfectionResult* Result)
{
    BYTE  CodeArray[256], KeyArray [25], DecodeArray[Sality_DecodeLen];
    BYTE  PatternSality[] = { 0x8B, 0xF8, 0x8B, 0x06, 0x39, 0x07, 0x74, 0x02, 0xF3, 0xA4, 0x8D, 0x85 };
    DWORD OfsetDecodeOrginal, AddSality;
    DWORD vImageBase;
    
    int   i;
#if defined(Behpad) || defined(Zeynali)
    int   DiffCodeLenght;
    BYTE* Buffer;
    DWORD OffsetLenght;
    DWORD Lenght;
    DWORD OffsetCode;
    DWORD XorKey;
#endif
    DWORD StartSection = ((StructSality*)objSality)->StartSection;
    DWORD LenghtKey    = ((StructSality*)objSality)->LenghtKey;

    if (Result == NULL)
        return 0;

    for (i = 0; i < 256; i++)
        CodeArray[i] = i;

    if (LenghtKey > sizeof(KeyArray))
        return 0;

    PeFile->Seek(StartSection + 0x1000);
    if ((PeFile->Read(KeyArray, LenghtKey)) < LenghtKey)
        return 0;
    PeFile->Seek(StartSection + 0x1116);
    if ((PeFile->Read(DecodeArray, sizeof(DecodeArray))) < sizeof(DecodeArray))
        return 0;

    recx = 0;
    redx = 0;
    rebx = 0;
    redi = 0;
    reax = 0;
    do
    {
        r_al = CodeArray[recx];
        r_dl += KeyArray[rebx];
        r_dl += r_al;
        r_ah = CodeArray[redx];
        CodeArray[redx] = r_al;
        CodeArray[recx] = r_ah;
        rebx++;
        if (rebx > LenghtKey-1)
            rebx = 0;
        recx++;
    }
    while (recx != 256);

    recx = 0;
    redx = 1;
    rebx = 0;
    redi = 0;
    reax = 0;
    do
    {
        r_bl += CodeArray[redx];
        r_al  = CodeArray[redx];
        r_ch  = CodeArray [rebx];
        CodeArray[rebx] = r_al;
        CodeArray[redx] = r_ch;
        r_al += r_ch;
        r_al  = CodeArray[reax];

        DecodeArray[redi] ^= r_al;
        r_dl++;
        redi++;
    }
    while (redi < Sality_DecodeLen);

    if (memcmp(DecodeArray + 0X158, PatternSality, 12))
        return 0;

    vImageBase         = *(PDWORD)(DecodeArray + 8) - 5;
    OfsetDecodeOrginal = *(PDWORD)(DecodeArray + 0x179);
    OfsetDecodeOrginal = OfsetDecodeOrginal - vImageBase;
    if (OfsetDecodeOrginal == 0x4d0)
    {
        Result->State = INFECTED;
        Result->VirusNo = Win32_Sality_AA;
        AddSality = 0;
    }
    else if (OfsetDecodeOrginal == 0x5DE)
    {
        Result->State = INFECTED;
        Result->VirusNo = Win32_Sality_AB;
        AddSality = 4;
    }
    else if (OfsetDecodeOrginal == 0x6be)
    {
        Result->State = INFECTED;
        Result->VirusNo = Win32_Sality_AE;
        AddSality = 4;
    }
    else
    {
        Result->State = SUSPICIOUS;
        Result->VirusNo = Win32_Sality_AA;
        return 2;
    }

#if defined(Behpad) || defined(Zeynali)

    if (OpertionType != DisInfect)
        return 1;

    // in case of errors, at the f_clean module, we check this value
    Result->Row.EntryPointOwerWriteLenght = 0;

    OffsetLenght = *(PDWORD)(DecodeArray + OfsetDecodeOrginal + AddSality + 0x12);

    if (OfsetDecodeOrginal == 0x6be && *(PWORD)(DecodeArray + OfsetDecodeOrginal + AddSality + 0x1c) == 0xf181)
    {
        // Win32_Sality_AE
        XorKey     = *(PDWORD)(DecodeArray + OfsetDecodeOrginal + AddSality + 0x1e);
        OffsetCode = *(PDWORD)(DecodeArray + OfsetDecodeOrginal + AddSality + 0x24);
    }
    else
    {
        // Win32_Sality_AA, Win32_Sality_AB
        XorKey     = 0;
        OffsetCode = *(PDWORD)(DecodeArray + OfsetDecodeOrginal + AddSality + 0x18);
    }

    OffsetLenght = OffsetLenght - vImageBase;
    OffsetCode   = OffsetCode   - vImageBase;

    if (OffsetLenght > 0xceea || OffsetCode > 0xceea)
    {
        Result->State = SUSPICIOUS;
        return 2;
    }
    if ((Buffer = new BYTE[OffsetLenght - Sality_DecodeLen + 4]) == NULL)
    {
        Result->State = SUSPICIOUS; // returns "like" to prevent file deletion
        return 2;                   // is virus, but has error
    }
    if ((PeFile->Read(Buffer, OffsetLenght - Sality_DecodeLen + 4)) < OffsetLenght - Sality_DecodeLen + 4)
    {
        delete[] Buffer;
        Result->State = SUSPICIOUS; // returns "like" to prevent file deletion
        return 2;                   // is virus, but has error
    }

    redi = 0;
    do
    {
        r_bl += CodeArray[redx];
        r_al  = CodeArray[redx];
        r_ch  = CodeArray [rebx];
        CodeArray[rebx] = r_al;
        CodeArray[redx] = r_ch;
        r_al += r_ch;
        r_al  = CodeArray[reax];

        Buffer[redi] ^= r_al;
        r_dl++;
        redi++;
    }
    while (redi < OffsetLenght - Sality_DecodeLen + 4);

    Lenght =  *(PDWORD)(Buffer + OffsetLenght - Sality_DecodeLen);
    if (Result->VirusNo == Win32_Sality_AE)
    {
        if (Lenght <= 1)
            Lenght = 500;
        else
            Lenght ^= XorKey;
    }
    
    if (Lenght >= 0x0000ffff)
    {
        delete[] Buffer;
        Result->State = SUSPICIOUS; // returns "like" to prevent file deletion
        return 2;                   // is virus, but has error
    }

    DiffCodeLenght = OffsetCode - OffsetLenght - 4;
    if (DiffCodeLenght >= 0)
    {
        delete[] Buffer;
        if ((Buffer = new BYTE[Lenght +  DiffCodeLenght]) == NULL)
        {
            Result->State = SUSPICIOUS; // returns "like" to prevent file deletion
            return 2;                   // is virus, but has error
        }

        if ((PeFile->Read(Buffer, Lenght + DiffCodeLenght)) < Lenght + DiffCodeLenght)
        {
            delete[] Buffer;
            Result->State = SUSPICIOUS; // returns "like" to prevent file deletion
            return 2;                   // is virus, but has error
        }

        redi = 0;
        do
        {
            r_bl += CodeArray[redx];
            r_al  = CodeArray[redx];
            r_ch  = CodeArray [rebx];
            CodeArray[rebx] = r_al;
            CodeArray[redx] = r_ch;
            r_al += r_ch;
            r_al  = CodeArray[reax];

            Buffer[redi] ^= r_al;
            r_dl++;
            redi++;
        }
        while (redi < Lenght + DiffCodeLenght);
    }
    else
    {
        DiffCodeLenght = OffsetCode - Sality_DecodeLen;
    }

    Result->Method = ReparableOverWrite;
    Result->Row.EntryPointOwerWriteLenght = Lenght;
    Result->StartInfection = StartSection;

    if (Lenght >= MaxBuffSize)
    {
        DebugMessage("Error in cleaning of sality.q virus.\nLen. of first part is greater than 4096");
        Lenght = MaxBuffSize;
    }

    memcpy(Result->Row.EntryPointOwerWrite, Buffer + DiffCodeLenght, Lenght);
    delete[] Buffer;
#endif
    return 1;
}
//---------------------------------------------------------------------------------------------------------------------
int FullDetectSality_AC(PVOID objSality, BehpadOpertionType OpertionType, InfectionResult* Result)
{
    BYTE CodeArray[256], KeyArray [24], DecodeArray [0x38];
    BYTE PatternSality_V[] =
    {
        0x66, 0x69, 0xC1, Dummy, Dummy, 0xD1, 0xE9, 0x2B, 0xC1, 0xD1, 0xE1, 0x66, 
        0x31, 0x84, 0x0D, Dummy, Dummy, 0x00, 0x00, 0x41, 0x41, 0x3B, 0xCA, 0x74
    };
    int i;
    BYTE* SrcPtr, *DestPtr;
    
#if defined(Behpad) || defined(Zeynali)
    DWORD LenDeCode;
    DWORD OffsetCode;
    PBYTE OrginalDecode, Buffer;
    DWORD Lenght;
    WORD MulKey;
#endif
    if (Result == NULL)
        return 0;
    DWORD StartSection = ((StructSality*)objSality)->StartSection;
    DWORD LenghtKey    = ((StructSality*)objSality)->LenghtKey;

    for (i = 0; i <256; i++)
        CodeArray[i] = i;

    if (LenghtKey > sizeof(KeyArray))
        return 0;

    PeFile->Seek(StartSection+0x1000);
    if ((PeFile->Read(KeyArray, LenghtKey)) < LenghtKey)
        return 0;

    PeFile->Seek(StartSection+0x1116);
    if ((PeFile->Read(DecodeArray, sizeof(DecodeArray))) < sizeof(DecodeArray))
        return 0;

    reax = 0;
    rebx = 0;
    recx = 0;
    redx = 0;
    redi = 0;

    do
    {
        r_al = CodeArray[recx];
        r_dl += KeyArray[rebx];
        r_dl += r_al;
        r_ah = CodeArray[redx];
        CodeArray[redx] = r_al;
        CodeArray[recx] = r_ah;
        rebx++;
        if (rebx > LenghtKey - 1)
            rebx = 0;
        recx++;
    }
    while (recx != 256);
    
    reax = 0; 
    rebx = 0; 
    redx = 1;
    r_cl = 0x38;
    do
    {
        r_bl += CodeArray[redx];
        r_al = CodeArray[redx];
        r_ch = CodeArray [rebx];
        CodeArray [rebx] = r_al;
        CodeArray[redx] = r_ch;
        r_al += r_ch;
        r_al =  CodeArray[reax];
        DecodeArray [redi] ^= r_al;
        r_dl++;
        redi++;
        r_cl--;
    }
    while (r_cl > 0);

    SrcPtr  = (PBYTE)DecodeArray + 9;
    DestPtr = (PBYTE)PatternSality_V;
    if (ComparePattern(SrcPtr, DestPtr, sizeof(PatternSality_V)) == FALSE)
        return 0;

    Result->State = INFECTED;
    Result->VirusNo = Win32_Sality_AC;
#if defined(Behpad) || defined(Zeynali)

    if (OpertionType != DisInfect)
        return 1;

    // in case of errors, at the f_clean module, we check this value
    Result->Row.EntryPointOwerWriteLenght = 0;

    OrginalDecode = DecodeArray + 40;
    MulKey = *(PWORD)(DecodeArray + 0x0c);

    recx = 0;
    do
    {
        r_ax = r_cx * MulKey;
        recx >>= 1;
        reax -=  recx;
        recx <<= 1;
        *(PWORD)(OrginalDecode + recx) ^= r_ax;
        recx +=2;
    }
    while (recx < 0x10);

    OffsetCode =  *(PDWORD)(OrginalDecode + 0x5);
    Lenght     =  *(PDWORD)(OrginalDecode + 0xa);

    if ((LenDeCode = OffsetCode - 0x1116 + Lenght - 0x38) > 0xcfba)
    {
        return 2; // is virus, but has error
    }

    if ((Buffer = new BYTE[DoAlignment(LenDeCode, 2)]) == NULL) // Zeynali : bug fix (1390-04-06)
    {
        return 2; // is virus, but has error
    }
    
    if ((PeFile->Read(Buffer, LenDeCode)) < LenDeCode)
    {
        delete[] Buffer;
        return 2; // is virus, but has error
    }

    do
    {
        r_ax = r_cx * MulKey;
        recx >>= 1;
        reax -=  recx;
        recx <<= 1;
        *(PWORD)(Buffer + recx - 0x10) ^= r_ax;
        recx += 2;
    }
    while (LenDeCode > recx - 0x10);

    Result->Method = ReparableOverWrite;
    Result->Row.EntryPointOwerWriteLenght = Lenght;
    Result->StartInfection = StartSection;
    if (Lenght >= MaxBuffSize)
    {
        DebugMessage("Error in cleaning of sality.v virus.\nLen. of first part is greater than 4096");
        Lenght = MaxBuffSize;
    }
    memcpy(Result->Row.EntryPointOwerWrite, Buffer + LenDeCode - Lenght, Lenght);
    delete[] Buffer;

#endif
    return 1;
}
//---------------------------------------------------------------------------------------------------------------------
#define Sality_Z_DecodeLen (0x6e4+6)
int FullDetectSality_AD(PVOID objSality, BehpadOpertionType OpertionType, InfectionResult* Result)
{
    BYTE  CodeArray[256], KeyArray [24], DecodeArray[Sality_Z_DecodeLen];
    BYTE  PatternSality_Z[] = { 0x8B, 0xF8, 0x8B, 0x06, 0x39, 0x07, 0x74, 0x02, 0xF3, 0xA4, 0x8D, 0x85 };
    int   i;
    
#if defined(Behpad) || defined(Zeynali)
    DWORD OfsetDecodeOrginal;
    DWORD vImageBase;
    int   DiffCodeLenght;
    PBYTE Buffer;
    DWORD OffsetLenght;
    DWORD Lenght, XorKey;
    DWORD OffsetCode;
#endif
    if (Result == NULL)
        return 0;

    PStructSality_Z ArgStruct = (PStructSality_Z)objSality;

    for (i = 0; i < 256; i++)
        CodeArray[i] = i;

    if (ArgStruct->LenghtKey > sizeof(KeyArray))
        return 0;

    PeFile->Seek(ArgStruct->StartSection + 0x1000);
    if ((PeFile->Read(KeyArray, ArgStruct->LenghtKey)) < ArgStruct->LenghtKey)
        return 0;

    PeFile->Seek(ArgStruct->StartSection + 0x1116);
    if ((PeFile->Read(DecodeArray, sizeof(DecodeArray))) < sizeof(DecodeArray))
        return 0;

    for (i = 0; i < (int) ArgStruct->Conuter + 1; i++)
    {
        if (ArgStruct->XorAdd == 0)
            *(PDWORD)(KeyArray + 4*i) += ArgStruct->Key;
        else
            *(PDWORD)(KeyArray + 4*i) ^= ArgStruct->Key;
    }

    recx = 0;
    redx = 0;
    rebx = 0;
    redi = 0;
    reax = 0;
    do
    {
        r_al = CodeArray[recx];
        r_dl += KeyArray[rebx];
        r_dl += r_al;
        r_ah = CodeArray[redx];
        CodeArray[redx] = r_al;
        CodeArray[recx] = r_ah;
        rebx++;
        if (rebx > ArgStruct->LenghtKey-1)
            rebx = 0;
        recx++;
    }
    while (recx != 256);

    recx = 0;
    redx = 1;
    rebx = 0;
    redi = 0;
    reax = 0;
    
    do
    {
        r_bl += CodeArray[redx];
        r_al  = CodeArray[redx];
        r_ch  = CodeArray [rebx];
        CodeArray[rebx] = r_al;
        CodeArray[redx] = r_ch;
        r_al += r_ch;
        r_al  = CodeArray[reax];

        DecodeArray[redi] ^= r_al;
        r_dl++;
        redi++;
    }
    while (redi < Sality_Z_DecodeLen);

    if (memcmp(DecodeArray + 0X158, PatternSality_Z, 12))
        return 0;

    Result->State = INFECTED;
    Result->VirusNo = Win32_Sality_AD;

#if defined(Behpad) || defined(Zeynali)

    if (OpertionType != DisInfect)
        return 1;

    // in case of errors, at the f_clean module, we check this value
    Result->Row.EntryPointOwerWriteLenght = 0;

    vImageBase         = *(PDWORD)(DecodeArray + 8) - 5;
    OfsetDecodeOrginal = *(PDWORD)(DecodeArray + 0x179);
    OfsetDecodeOrginal = OfsetDecodeOrginal - vImageBase;

    OffsetLenght = *(PDWORD)(DecodeArray + OfsetDecodeOrginal + 0x16);

    if (*(PWORD)(DecodeArray + OfsetDecodeOrginal + 0x20) == 0xf181)
    {
        XorKey     = *(PDWORD)(DecodeArray + OfsetDecodeOrginal + 0x22);
        OffsetCode = *(PDWORD)(DecodeArray + OfsetDecodeOrginal + 0x22 + 6);
    }
    else
    {
        XorKey     = 0;
        OffsetCode = *(PDWORD)(DecodeArray + OfsetDecodeOrginal + 0x22);
    }

    OffsetLenght = OffsetLenght - vImageBase;
    OffsetCode   = OffsetCode   - vImageBase;

    if (OffsetLenght > 0xceea || OffsetCode > 0xceea)
    {
        return 2; // is virus, but has error
    }

    if ((Buffer = new BYTE[OffsetLenght - Sality_Z_DecodeLen + 4]) == NULL)
    {
        return 2; // is virus, but has error
    }

    if ((PeFile->Read(Buffer, OffsetLenght - Sality_Z_DecodeLen + 4)) < OffsetLenght - Sality_Z_DecodeLen + 4)
    {
        delete[] Buffer;
        return 2; // is virus, but has error
    }

    redi = 0;
    do
    {
        r_bl += CodeArray[redx];
        r_al  = CodeArray[redx];
        r_ch  = CodeArray [rebx];
        CodeArray[rebx] = r_al;
        CodeArray[redx] = r_ch;
        r_al += r_ch;
        r_al  = CodeArray[reax];

        Buffer[redi] ^= r_al;
        r_dl++;
        redi++;
    }
    while (redi < OffsetLenght - Sality_Z_DecodeLen + 4);
    Lenght = *(PDWORD)(Buffer + OffsetLenght - Sality_Z_DecodeLen);
    if (Lenght <= 1)
    {
        Lenght = 500;
        // delete[] Buffer;
        // Result->VirusNo = Win32_Sality_AD;
        // Result->State = SUSPEND;
        // return 2;
    }
    else
    {
        Lenght ^= XorKey;
    }

    DiffCodeLenght = OffsetCode - OffsetLenght - 4;
    if (DiffCodeLenght >= 0)
    {
        delete[] Buffer;
        if ((Buffer = new BYTE[Lenght +  DiffCodeLenght]) == NULL)
        {
            return 2; // is virus, but has error
        }
        if ((PeFile->Read(Buffer, Lenght + DiffCodeLenght)) < Lenght + DiffCodeLenght)
        {
            delete[] Buffer;
            return 2; // is virus, but has error
        }
        redi = 0;
        do
        {
            r_bl += CodeArray[redx];
            r_al  = CodeArray[redx];
            r_ch  = CodeArray[rebx];
            CodeArray[rebx] = r_al;
            CodeArray[redx] = r_ch;
            r_al += r_ch;
            r_al  = CodeArray[reax];

            Buffer[redi] ^= r_al;
            r_dl++;
            redi++;
        }
        while (redi < Lenght + DiffCodeLenght);
    }
    else
    {
        DiffCodeLenght = OffsetCode - Sality_Z_DecodeLen;
    }

    Result->Method = ReparableOverWrite;
    Result->Row.EntryPointOwerWriteLenght = Lenght;
    Result->StartInfection = ArgStruct->StartSection;

    if (Lenght >= MaxBuffSize)
    {
        DebugMessage("Error in cleaning of sality.z virus.\nLen. of first part is greater than 4096");
        Lenght = MaxBuffSize;
    }
    memcpy(Result->Row.EntryPointOwerWrite, Buffer + DiffCodeLenght, Lenght);
    delete[] Buffer;

#endif // #ifdef Behpad
    return 1;
}
//---------------------------------------------------------------------------------------------------------------------
int FullDetectVirutOverWrite(PVOID objVirut, BehpadOpertionType OpertionType, InfectionResult* Result)
{
    StructVirut_F* ArgStruct = (StructVirut_F*)objVirut;
    BYTE  HeaderDecode[0xC1];
    BYTE  tmpKey;
    DWORD SizeOverWrite;
    DWORD DiffFromHeadCode;
    DWORD EBP;
    DWORD LenAfterCall;
    int   i, VirusIndex;
    
#if defined(Behpad) || defined(Zeynali)
    PBYTE OverWriteBuffer;
#endif
    if (Result == NULL)
        return 0;

    PeFile->Seek(PeFile->ConvertRvaToOffset(ArgStruct->StartClean));
    if ((PeFile->Read(HeaderDecode, sizeof(HeaderDecode))) < sizeof(HeaderDecode))
    {
        return 0;
    }

    for (VirusIndex = 0; VirusIndex < NUMBER_OF_ARRAY(ListVirutClean); VirusIndex++)
    {
        ListVirutClean[VirusIndex].TypeDecode = ArgStruct->BTypeDecode;
        if (CheckVirutPattern(ListVirutClean + VirusIndex, HeaderDecode) == TRUE)
        {
            break;
        }
    }

    if (VirusIndex >= NUMBER_OF_ARRAY(ListVirutClean))
    {
        return 0;
    }

    Result->State = INFECTED;
    Result->VirusNo = ListVirutClean[VirusIndex].VirusNo;

    for (i = 0, tmpKey = ListVirutClean[VirusIndex].Key; i < sizeof(HeaderDecode); i++, tmpKey += ListVirutClean[VirusIndex].KeyAdd)
    {
        if (ArgStruct->BTypeDecode == XorVirut)
            HeaderDecode[i] ^= tmpKey;
        else if (ArgStruct->BTypeDecode == SubVirut)
            HeaderDecode[i] -= tmpKey;
    }

    for (i = 0; i < sizeof(ListVirutClean[VirusIndex].Pattern); i++)
        if (ListVirutClean[VirusIndex].Pattern[i] == 0xe8)
            break;

    LenAfterCall = i + 5;

    EBP              = *((PDWORD)(HeaderDecode + ListVirutClean[VirusIndex].EBP)) - *((PDWORD)(HeaderDecode + ListVirutClean[VirusIndex].Base)) + LenAfterCall;
    SizeOverWrite    = *((PDWORD)(HeaderDecode + ListVirutClean[VirusIndex].SizeOverWrite));
    DiffFromHeadCode = *((PDWORD)(HeaderDecode + ListVirutClean[VirusIndex].LenghtSub_DiffFromHeadCode));

    if (SizeOverWrite > 2048)
    {
        Result->State = SUSPICIOUS;
        return 0;
    }

    if (SizeOverWrite == 0)
    {
        Result->Method = ChangedEntryPoint;
#if defined(Behpad) || defined(Zeynali)
        if (OpertionType == DisInfect)
        {
            Result->StartInfection = PeFile->ConvertRvaToOffset(ArgStruct->StartClean);
            Result->StartStub = PeFile->EntryPointOffset;
            Result->Che.OrignalEntryPoint = ArgStruct->StartClean - DiffFromHeadCode + LenAfterCall;
        }
#endif
        return 2;
    }

#if defined(Behpad) || defined(Zeynali)
    if (OpertionType == DisInfect)
    {
        // in case of errors to forec clean function to delete file
        Result->Row.EntryPointOwerWriteLenght = 0;

        if ((OverWriteBuffer = new BYTE[SizeOverWrite]) == NULL)
        {
            return 1;
        }

        PeFile->Seek(PeFile->ConvertRvaToOffset(ArgStruct->StartClean + EBP));
        if ((PeFile->Read(OverWriteBuffer, SizeOverWrite)) < SizeOverWrite)
        {
            delete[] OverWriteBuffer;
            return 1;
        }

        tmpKey = (BYTE)(ListVirutClean[VirusIndex].Key + EBP * ListVirutClean[VirusIndex].KeyAdd);

        for (i = 0; i < (int)SizeOverWrite; i++, tmpKey += ListVirutClean[VirusIndex].KeyAdd)
        {
            if (ArgStruct->BTypeDecode == XorVirut)
                OverWriteBuffer[i] ^= tmpKey;
            else if (ArgStruct->BTypeDecode == SubVirut)
                OverWriteBuffer[i] -= tmpKey;
        }

        Result->Method = ReparableOverWrite;
        Result->StartInfection = PeFile->ConvertRvaToOffset (ArgStruct->StartClean);        
//        Result->Chr.OffsetInfection = PeFile->ConvertRvaToOffset (ArgStruct->StartClean - DiffFromHeadCode + LenAfterCall);
        Result->Row.EntryPointOwerWriteLenght = SizeOverWrite;
        memcpy(Result->Row.EntryPointOwerWrite, OverWriteBuffer, SizeOverWrite);

        delete[] OverWriteBuffer;
    }
#endif

    return 2;
}
//---------------------------------------------------------------------------------------------------------------------
BOOL CheckVirutPattern(PVirutScanCleanStruct This, PBYTE BuffPtr)
{  
    
    This->TypeDecode = CheckPattern (This->Pattern, BuffPtr, sizeof(This->Pattern));
    if (This->TypeDecode == SubVirut)
    {
        This->Key    =  BuffPtr[0] - This->Pattern[0];
        This->KeyAdd = (BuffPtr[1] - This->Pattern[1]) - This->Key;
        return TRUE;
    }

    if (This->TypeDecode == XorVirut)
    {
        This->Key    =  BuffPtr[0] ^ This->Pattern[0];
        This->KeyAdd = (BuffPtr[1] ^ This->Pattern[1]) - This->Key;
        return TRUE;
    }

    This->TypeDecode = NonDetectVirut;
    This->Key        = 0;
    This->KeyAdd     = 0;
    return FALSE;
}
//---------------------------------------------------------------------------------------------------------------------
TypeVirutCode CheckPattern (PBYTE Src, PBYTE Des, int Size)
{
    int i;
    BYTE Key, KeyAdd, tmpKey;

    Key = Des[0] ^ Src[0];
    KeyAdd = (Des[1] ^ Src[1]) - Key;

    for (i = 0, tmpKey = Key; i < Size; i++, tmpKey += KeyAdd)
        if ((Des[i] ^ tmpKey) != Src[i])
            break;

    if (Size == i)
        return XorVirut;

    Key = Des[0] - Src[0];
    KeyAdd = (Des[1] - Src[1]) - Key;

    for (i = 0, tmpKey = Key; i < Size; i++, tmpKey += KeyAdd)
        if ((BYTE)(Des[i] - tmpKey) != Src[i])
            break;

    if (Size == i)
        return SubVirut;

    return NonDetectVirut;
}
//---------------------------------------------------------------------------------------------------------------------
int FullDetectVirut_Z(PVOID objVirut, BehpadOpertionType OpertionType, InfectionResult* Result)
{
    // IMAGE_SECTION_HEADER SectionEntry;
    PStructVirut_Z_AB_AC ArgStruct = (PStructVirut_Z_AB_AC)objVirut;

    if (ArgStruct->MainAPIRVA.dw)
    {
        // was called type, but our heuristic finds it first.
        // then we should return with "IsLikeVir" to detect in other
        // routine that searches from the end of file
        Result->State = SUSPICIOUS;
        return 2;
    }

#ifdef Behpad
    if (OpertionType == DisInfect)
    {
        if (ArgStruct->StartZero == 0)
        {
            // start of part1 that should be wiped is not exist; virus has 1 part
            *(PDWORD)(buff+0) = ArgStruct->StartZero;
        }
        else
        {
            // start of part1 that should be wiped
            *(PDWORD)(buff+0) = PeFile->ConvertAddressToOffset (ArgStruct->StartZero);
        }

        if (PeFile->ReadSectionEntryForRVA(ArgStruct->StartDeCode - ImageBase, (PBYTE)&SectionEntry) == INVALIDSectionEntry)
        {
            Result->State = SUSPICIOUS;
            return 2;
        }
        // *(PDWORD)(buff+4) = FindBlockBetweenZeroBlocksInEndOfSection(&SectionEntry, VIRUT_AC_PART2_MIN_LEN, VIRUT_AC_PART2_MAX_LEN, 8, 0);
        if (*(PDWORD)(buff+4) == OffsetNotFound)
        {
            *(PDWORD)(buff+4) = PeFile->ConvertAdrressToOffset (ArgStruct->StartDeCode); // start of part2 that should be wiped or truncated
        }
        // *(PDWORD)(buff+8) = NewHeaderOffset+0x28; // PE_Header:EntryPointRVA
        *(PWORD)(buff+12) = 4;
        *(PDWORD)(buff+14) = ArgStruct->EntryPoint - ImageBase;  // main entry point
    }

#endif

    Result->State = INFECTED;
    return 1;
}
//---------------------------------------------------------------------------------------------------------------------
BOOL DecodeVirut_Z(DWORD StartDeCode, DWORD Lenght, DWORD Key)
{
    BYTE* Buffer;
    DWORD dwValue;
    
    int i;

    Buffer = new BYTE[Lenght + 4];
    if (Buffer == NULL)
        return FALSE;

    PeFile->Seek(PeFile->ConvertAddressToOffset(StartDeCode));
    if ((PeFile->Read((PBYTE)Buffer, Lenght+4)) < Lenght+4)
    {
        delete[] Buffer;
        return FALSE;
    }

    for (i = (int) Lenght; i >= 0; i -= 4)
    {
        dwValue = *(PDWORD)(Buffer + i) + Key;
        MemoryManager->SetValue(StartDeCode + i, (PBYTE) &dwValue, 4);
    }
    delete[] Buffer;
    return TRUE;
}
//---------------------------------------------------------------------------------------------------------------------
DWORD DetectVirutEOS(PVirutScanCleanStruct This, BehpadOpertionType OpertionType, InfectionResult* Result)
{
    BYTE HeaderDecode [DetectVirutEOS_DecodeLen + 1];
    IMAGE_SECTION_HEADER* SectionEntry;
    DWORD FilePtr;
    DWORD LastValidOffset = OffsetNotFound;

    int Status = 0;

    if ((SectionEntry = PeFile->ReadLastSectionEntry()) == NULL)
        return NO_INFECTION;

    if (SectionEntry->SizeOfRawData <= This->SizeOfBackWard)
        return NO_INFECTION;

    // ignores "0"s at the end of last section
    if (LastValidOffset == OffsetNotFound)
    {
        LastValidOffset = PeFile->MianDoSefr(SectionEntry->PointerToRawData + This->SizeOfBackWard, 
                                             SectionEntry->SizeOfRawData - This->SizeOfBackWard);
    }

    FilePtr = LastValidOffset;
    if (FilePtr == OffsetNotFound)
        return NO_INFECTION;

    FilePtr = PeFile->Seek(FilePtr - This->SizeOfBackWard);
    if ((PeFile->Read(HeaderDecode, sizeof(HeaderDecode))) < sizeof(HeaderDecode))
        return NO_INFECTION;

    Status = DetectVirut_EndFile (This, HeaderDecode, DetectVirutEOS_DecodeLen, FilePtr, OpertionType, Result);

    if (Status == 0)
    {
        FilePtr++;
        Status = DetectVirut_EndFile (This, HeaderDecode + 1, DetectVirutEOS_DecodeLen, FilePtr, OpertionType, Result);
        if (Status == 0)
            return NO_INFECTION;
    }

    Result->State = (Status == 1) ? SUSPICIOUS : INFECTED;
    Result->VirusNo = This->VirusNo;

    return This->VirusNo;
}
//---------------------------------------------------------------------------------------------------------------------
DWORD DetectVirutEOF(PVirutScanCleanStruct This, BehpadOpertionType OpertionType, InfectionResult* Result)
{
    BYTE HeaderDecode [DetectVirutEOS_DecodeLen + 1];
    DWORD FilePtr;
    DWORD LastValidOffset = OffsetNotFound;
    DWORD FileSize = 0;

    int Status = 0;

    if ((FileSize = PeFile->GetFileSize()) == 0)
        return NO_INFECTION;

    if (FileSize <= This->SizeOfBackWard)
        return NO_INFECTION;

    // ignores "0"s at the end of last section
    if (LastValidOffset == OffsetNotFound)
    {
        LastValidOffset = PeFile->MianDoSefr(FileSize - This->SizeOfBackWard, This->SizeOfBackWard);
    }

    FilePtr = LastValidOffset;
    if (FilePtr == OffsetNotFound)
        return NO_INFECTION;

    FilePtr = PeFile->Seek(FilePtr - This->SizeOfBackWard);
    if ((PeFile->Read(HeaderDecode, sizeof(HeaderDecode))) < sizeof(HeaderDecode))
        return NO_INFECTION;

    Status = DetectVirut_EndFile (This, HeaderDecode, DetectVirutEOS_DecodeLen, FilePtr, OpertionType, Result);

    if (Status == 0)
    {
        FilePtr++;
        Status = DetectVirut_EndFile (This, HeaderDecode + 1, DetectVirutEOS_DecodeLen, FilePtr, OpertionType, Result);
        if (Status == 0)
            return NO_INFECTION;
    }

    Result->Method = WithOutEntryPoint;
    Result->State = INFECTED;
    Result->StartInfection = FilePtr & 0xffffff00;
    Result->VirusNo = This->VirusNo;

    return This->VirusNo;
}
//-------------------------------------------------------------------------------------------
// Return Values: 0; if is not detected
//                1; if is like
//           others; is virus
int DetectVirut_EndFile (PVirutScanCleanStruct This,
                         BYTE* HeaderDecode,
                         UINT HeaderDecodeLen,
                         DWORD PhysicalAdd,
                         BehpadOpertionType OpertionType,
                         InfectionResult* Result)
{
    IMAGE_SECTION_HEADER* SectionEntry;
    BYTE TestValue[10];
    DWORD LenghtSub, RVA;
    BYTE  tmpKey;
    DWORD TestAdd;
    DWORD CallerFileOffset;
    DWORD CalledRVA;
    DWORD LenAfterCall;
    
    HeuristicCallBack VirutHeuristicInitial = {Win32_Virut_F, DetectVirut, 0, 0, Continue, NULL, NULL, NULL};
    int i;

    This->TypeDecode = NonDetectVirut;
    if (CheckVirutPattern(This, HeaderDecode) == FALSE)
        return 0;

    for (i = 0, tmpKey = This->Key; i < DetectVirutEOS_DecodeLen; i++, tmpKey += This->KeyAdd)
    {
        if (This->TypeDecode == XorVirut)
            *(HeaderDecode+i) ^= tmpKey;
        else if (This->TypeDecode == SubVirut)
            *(HeaderDecode+i) -= tmpKey;
    }

    if ((SectionEntry = PeFile->ReadSectionEntryForOffset(PhysicalAdd)) == NULL)
        return 1;  // is like

    RVA = SectionEntry->VirtualAddress + (PhysicalAdd - SectionEntry->PointerToRawData);

    LenghtSub = *((PDWORD)(HeaderDecode + This->LenghtSub_DiffFromHeadCode));
    TestAdd = *((PDWORD)(HeaderDecode + This->TestAdd)) - *((PDWORD)(HeaderDecode + This->Base));
    for (i = 0; i < sizeof(This->Pattern); i++)
        if (This->Pattern[i] == 0xe8)
            break;

    LenAfterCall = i + 5;
    TestAdd += LenAfterCall;

    PeFile->Seek(PhysicalAdd + TestAdd);
    if ((PeFile->Read((PBYTE)&TestValue, sizeof(TestValue))) < sizeof(TestValue))
        return 1;  // is like

    tmpKey = (BYTE)(This->Key + TestAdd * This->KeyAdd);

    for (i = 0; i < sizeof(TestValue); i++, tmpKey += This->KeyAdd)
    {
        if (This->TypeDecode == XorVirut)
            TestValue[i] ^= tmpKey;
        else if (This->TypeDecode == SubVirut)
            TestValue[i] -= tmpKey;
    }

    if (*(PDWORD)TestValue & This->CheckCall)
    {
        Result->Method = ChangedRoutin;
#if defined(Behpad) || defined(Zeynali)
        // virus changed an original call to jump into its second part
        if (OpertionType == DisInfect)
        {                     
            CallerFileOffset = FindCallerBranch((PDWORD)&CalledRVA, RVA, 0xe8, &VirutHeuristicInitial, NULL, 0);
            if (CallerFileOffset == 0)
                Result->StartStub = PeFile->ConvertRvaToOffset(RVA) & 0xffffff00;
            else
                Result->StartStub = PeFile->ConvertRvaToOffset(CalledRVA);
                      
            Result->StartInfection = PhysicalAdd; 
            Result->Chr.OffsetInfection = CallerFileOffset;
            Result->Chr.RoutinOwerWriteLenght = 6;
            memcpy(Result->Chr.RoutinOwerWrite, TestValue + 4, 6);
        }
#endif
    }
    else
    {
        Result->Method = ChangedEntryPoint;
#if defined(Behpad) || defined(Zeynali)
        RVA -= LenghtSub - LenAfterCall; // main entry point RVA that should be write
        // at the header
        if (OpertionType == DisInfect)
        {
            Result->StartStub = PeFile->EntryPointOffset;
            Result->Che.OrignalEntryPoint = RVA;
            Result->StartInfection = PhysicalAdd;
        }
#endif
    }

    return 2;
}
//---------------------------------------------------------------------------------------------------------------------
DWORD FindCallerBranch(PDWORD CalledRVA, 
                       DWORD CoreVirutRVA, 
                       BYTE CallOrJmpInst, 
                       PHeuristicCallBack HeuristicInitial, 
                       PVOID pParam, 
                       UINT ParamLen)
{
    DWORD              FilePtr, JumpedRVA;
    BYTE               ByteTemp;
    DWORD              EndOffsetOfCode;
    SIGNED_DWORD       CallParam;
    HeuristicCallBack* objHeuristic;
    BOOL               fMatched = FALSE;
    IMAGE_SECTION_HEADER* EIPSectionEntry;
    IMAGE_SECTION_HEADER* LastSectionEntry;

    HeuristicCallBack arrHeuristic[] =
    {
        {0, NULL, 0, 0, Continue, NULL, NULL, NULL},
        {0, NULL, 0, 0, Continue, NULL, NULL, NULL}
    };

    if (CalledRVA)
        *CalledRVA = (DWORD) 0;

    if ((LastSectionEntry = PeFile->ReadLastSectionEntry()) == NULL)
        return 0;

    if ((EIPSectionEntry = PeFile->ReadSectionEntryForRVA(PeFile->EntryPoint)) == NULL)
        return 0;

    EndOffsetOfCode = EIPSectionEntry->PointerToRawData + EIPSectionEntry->SizeOfRawData - 4;
    
    FilePtr = PeFile->EntryPointOffset;

    PeFile->Seek(FilePtr);

    while (FilePtr < EndOffsetOfCode)
    {
        if ((PeFile->Read(&ByteTemp, 1)) < 1)
            return 0;

        FilePtr++;
        if (ByteTemp != CallOrJmpInst)
            continue;

        if ((PeFile->Read(&CallParam, 4)) < 4)
            return 0;

        if (CallParam < 0)
        {
            PeFile->Seek(FilePtr);
            continue;
        }

        JumpedRVA = FilePtr+4 - EIPSectionEntry->PointerToRawData + EIPSectionEntry->VirtualAddress;
        JumpedRVA += CallParam;
        if (JumpedRVA > (EIPSectionEntry->Misc.VirtualSize + EIPSectionEntry->VirtualAddress) && 
           (JumpedRVA < LastSectionEntry->VirtualAddress || 
            JumpedRVA > LastSectionEntry->VirtualAddress + LastSectionEntry->Misc.VirtualSize))
        {
            // Jumped location is not in EIP section and last section
            PeFile->Seek(FilePtr);
            continue;
        }

        __try
        {
            arrHeuristic[0] = *HeuristicInitial;
            objHeuristic = HeuristicScanVirus(JumpedRVA + PeFile->ImageBase, arrHeuristic);
        }
        __except(1)
        {
            objHeuristic = NULL;
        }

        if (objHeuristic != NULL && objHeuristic->Result == Yes)
        {
            if (objHeuristic->FullDetectArgument != NULL) // In che digeh
            {
                switch(objHeuristic->VirusNo)
                {
                case Win32_Virut_F:
                case Win32_Virut_I:
                case Win32_Virut_J:
                case Win32_Virut_K:
                case Win32_Virut_L:
                case Win32_Virut_M:
                case Win32_Virut_N:
                    if (((PStructVirut_F)(objHeuristic->FullDetectArgument))->StartClean == CoreVirutRVA)
                    {
                        fMatched = TRUE;
                    }
                    break;
                case Win32_Virut_AB:
                case Win32_Virut_AC:
                    if (((PStructVirut_Z_AB_AC)(objHeuristic->FullDetectArgument))->EntryPoint - PeFile->ImageBase - EIPSectionEntry->VirtualAddress + EIPSectionEntry->PointerToRawData == FilePtr - 1)
                    {
                        fMatched = TRUE;
                    }
                    break;
                default:
                    FreeCallbackMems(arrHeuristic);
                    return FilePtr - 1;
                }
            }
        }

        if (fMatched)
        {
            if (CalledRVA)
                *CalledRVA = JumpedRVA;

            if (pParam)
                memcpy(pParam, objHeuristic->FullDetectArgument, ParamLen);

            FreeCallbackMems(arrHeuristic);
            return FilePtr - 1;
        }

        FreeCallbackMems(arrHeuristic);

        if (objHeuristic != NULL && objHeuristic->Result == Like)
        {
            if (CalledRVA)
                *CalledRVA = JumpedRVA;

            return 0;
        }
        PeFile->Seek(FilePtr);
    }

    return 0;
}

//---------------------------------------------------------------------------------------------------------------------
DWORD FindCallerBranch2(PDWORD CalledRVA, 
                        BYTE CallOrJmpInst, 
                        PHeuristicCallBack HeuristicInitial, 
                        DWORD StartSearch, 
                        IMAGE_SECTION_HEADER* EIPSectionEntry, 
                        IMAGE_SECTION_HEADER* LastSectionEntry) 
{
    DWORD              FilePtr, JumpedRVA;
    BYTE               ByteTemp;
    DWORD              EndOffsetOfCode;
    SIGNED_DWORD       CallParam;
    HeuristicCallBack* objHeuristic;
    BOOL               fMatched = FALSE;

    if (CalledRVA)
       *CalledRVA = (DWORD) 0;

    EndOffsetOfCode = EIPSectionEntry->PointerToRawData + EIPSectionEntry->SizeOfRawData - 4;

    FilePtr = StartSearch;

    PeFile->Seek(FilePtr);

    while (FilePtr < EndOffsetOfCode)
    {
        if ((PeFile->Read(&ByteTemp, 1)) < 1)
        {
            return 0;
        }
        FilePtr++;
        if (ByteTemp != CallOrJmpInst)
            continue;

        if ((PeFile->Read(&CallParam, 4)) < 4)
        {
            return 0;
        }
        if (CallParam < 0)
        {
            PeFile->Seek(FilePtr);
            continue;
        }
        JumpedRVA = FilePtr + 4 - EIPSectionEntry->PointerToRawData + EIPSectionEntry->VirtualAddress;
        JumpedRVA += CallParam;
        if (JumpedRVA > (EIPSectionEntry->Misc.VirtualSize + EIPSectionEntry->VirtualAddress) && 
           (JumpedRVA < LastSectionEntry->VirtualAddress || 
            JumpedRVA > LastSectionEntry->VirtualAddress + LastSectionEntry->Misc.VirtualSize))
        {
            PeFile->Seek(FilePtr);
            continue;
        }

        __try
        {
            objHeuristic = HeuristicScanVirus(JumpedRVA, objHeuristic);
        }
        __except(1)
        {
            objHeuristic = NULL;
        }

        if (objHeuristic != NULL && objHeuristic->Result == Yes)
        {
            if (CalledRVA)
                *CalledRVA = JumpedRVA;
            return FilePtr - 1;
        }
        if (objHeuristic != NULL && objHeuristic->Result == Like)
        {
            if (CalledRVA)
                *CalledRVA = JumpedRVA;
            return 0;
        }
        FreeCallbackMems(objHeuristic);
        PeFile->Seek(FilePtr);
    }
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------
#define VIRUT_AB_MAX_FIRST_PART_LEN 0x650
DWORD DetectVirut_AB(void)
{
    IMAGE_SECTION_HEADER* SectionEntry;
    DWORD VirusNo;
    PBYTE DecodersPartBuffer;
    DWORD FilePtr;
    HeuristicCallBack VirutHeuristicInitial = {Win32_Virut_AB, DetectVirut_Z, 0, 0, Continue, NULL, NULL, NULL};
    UINT Percent = 0;
    DWORD LastValidOffsetInEntryPoint = OffsetNotFound;
    
#ifdef Behpad
    DWORD JumpedRVA;
    StructVirut_Z_AB_AC FullDetectArgument;
    DWORD CallerFileOffset;
#endif
    
    VirusNo = NO_INFECTION;

    DecodersPartBuffer = new BYTE[VIRUT_AB_MAX_FIRST_PART_LEN];
    if (DecodersPartBuffer == NULL)
    {
        return VirusNo;
    }

    if ((SectionEntry = PeFile->ReadSectionEntryForRVA(PeFile->EntryPoint)) == NULL)
    {
        delete[] DecodersPartBuffer;
        return VirusNo;
    }

    // ignores "0"s at the end of EIP section
    if (LastValidOffsetInEntryPoint == OffsetNotFound)
    {
        LastValidOffsetInEntryPoint = PeFile->MianDoSefr(PeFile->EntryPointOffset, 
                                                         SectionEntry->SizeOfRawData - (PeFile->EntryPointOffset - SectionEntry->PointerToRawData), 
                                                         0);
    }

    FilePtr = LastValidOffsetInEntryPoint;
    if (FilePtr == OffsetNotFound)
    {
        FilePtr = SectionEntry->PointerToRawData + SectionEntry->SizeOfRawData - 1;
    }

    FilePtr -= min((DWORD) VIRUT_AB_MAX_FIRST_PART_LEN, FilePtr);

    if (FilePtr < PeFile->EntryPointOffset)
    {
        FilePtr = PeFile->EntryPointOffset;
    }

    PeFile->Seek(FilePtr);
    if ((PeFile->Read((PBYTE)DecodersPartBuffer,VIRUT_AB_MAX_FIRST_PART_LEN)) < VIRUT_AB_MAX_FIRST_PART_LEN)
    {
        delete[] DecodersPartBuffer;
        return VirusNo;
    }
    
    //Todo: ????
    //Percent = StochasticPatternSearch(Virut_AB_Patt1, NUMBER_OF_ARRAY (Virut_AB_Patt1), DecodersPartBuffer, VIRUT_AB_MAX_FIRST_PART_LEN);
#if defined(_DEBUG) && defined(Test)
    if (Percent >= 70)
    {
        iGetFullPathName(f_name, FullPathName, sizeof(FullPathName));
        sprintf(buff, "Detect2Virut_AB\t%s\t%d%%\n", FullPathName, Percent);
        WriteIntoLogFile(buff, strlen(buff));
    }
#endif
    if (Percent < 100)// below than 100%
    {
        delete[] DecodersPartBuffer;
        return VirusNo;
    }

#ifdef Behpad
    delete[] DecodersPartBuffer;

    CallerFileOffset = FindCallerBranch((PDWORD) &JumpedRVA, 0, 0xe9, &VirutHeuristicInitial, &FullDetectArgument, sizeof(FullDetectArgument));
    if (CallerFileOffset == 0)
    {
        return VirusNo;
    }

    if (OpertionType == DisInfect)
    {
        if (FullDetectArgument.StartZero == 0)
        {
            // start of part1 that should be wiped is not exist; virus has 1 part
            *(PDWORD)(buff+0) = FullDetectArgument.StartZero;
        }
        else
        {
            // start of part1 that should be wiped
            *(PDWORD)(buff+0) = PeFile->ConvertAddressToOffset(FullDetectArgument.StartZero);
        }
        *(PDWORD)(buff+4) = PeFile->ConvertAddressToOffset(FullDetectArgument.StartDeCode); // start of part2 that should be wiped or truncated
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
    VirusNo = Win32_Virut_AB;
    return VirusNo;
}

//---------------------------------------------------------------------------------------------------------------------
DWORD DetectVirut_AC(void)
{
    BYTE* DecodersPartBuffer;
    IMAGE_SECTION_HEADER* SectionEntry;
    DWORD VirusNo;
    DWORD CallerFileOffset;
    DWORD JumpedRVA;
    DWORD FilePtr;
    HeuristicCallBack Virut_ACHeuristicInitial = {Win32_Virut_AC, DetectVirut_AC, 0, 0, Continue, NULL, NULL};
    HeuristicCallBack Virut_ABHeuristicInitial = {Win32_Virut_AB, DetectVirut_Z2, 0, 0, Continue, NULL, NULL};
    // HeuristicCallBack Virut_AIHeuristicInitial = {Win32_Virut_AI, DetectVirut_AI, 0, 0, Continue, NULL, NULL};
    StructVirut_Z_AB_AC FullDetectArgument;
    UINT Percent = 0;
    DWORD LastValidOffset = OffsetNotFound;

    VirusNo = NO_INFECTION;

    DecodersPartBuffer = new BYTE[VIRUT_AC_DECODER_PARTS_BUFF_LEN];
    if (DecodersPartBuffer == NULL)
    {
        return VirusNo;
    }

    if ((SectionEntry = PeFile->ReadLastSectionEntry()) == NULL)
    {
        delete[] DecodersPartBuffer;
        return VirusNo;
    }

    if (SectionEntry->SizeOfRawData <= VIRUT_AC_PART2_MIN_LEN)
    {
        delete[] DecodersPartBuffer;
        return VirusNo;
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

    if (FilePtr < (DWORD) VIRUT_AC_DECODER_PART_MAX_LEN)
    {
        delete[] DecodersPartBuffer;
        return VirusNo;
    }
    FilePtr -= (DWORD) VIRUT_AC_DECODER_PART_MAX_LEN;

    PeFile->Seek(FilePtr);
    if ((PeFile->Read((PBYTE)(DecodersPartBuffer+VIRUT_AC_DECODER_PART_MAX_LEN), VIRUT_AC_DECODER_PART_MAX_LEN)) < VIRUT_AC_DECODER_PART_MAX_LEN)
    {
        delete[] DecodersPartBuffer;
        return VirusNo;
    }

    if (FilePtr < (DWORD)(VIRUT_AC_PART2_MAX_LEN - VIRUT_AC_DECODER_PART_MAX_LEN))
    {
        delete[] DecodersPartBuffer;
        return VirusNo;
    }
    FilePtr -= (DWORD)(VIRUT_AC_PART2_MAX_LEN - VIRUT_AC_DECODER_PART_MAX_LEN);
    if (FilePtr < SectionEntry->PointerToRawData)
    {
        FilePtr = SectionEntry->PointerToRawData;
    }
    PeFile->Seek(FilePtr);
    if ((PeFile->Read((PBYTE)DecodersPartBuffer, VIRUT_AC_DECODER_PART_MAX_LEN)) < VIRUT_AC_DECODER_PART_MAX_LEN)
    {
        delete[] DecodersPartBuffer;
        return VirusNo;
    }

    // for finding another type of virut.ab
    // Todo: ????
    //Percent = StochasticPatternSearch(Virut_AB_Patt2, NUMBER_OF_ARRAY(Virut_AB_Patt2), DecodersPartBuffer, VIRUT_AC_DECODER_PARTS_BUFF_LEN);
#if defined(_DEBUG) && defined(Test)
    if (Percent >= 70)
    {
        DebugMessage("%s %d",PeFile->mFileName, Percent);
    }
#endif

    if (Percent < 100)
    {
        // Todo: ????
        //Percent = StochasticPatternSearch(Virut_AC_Patt, NUMBER_OF_ARRAY(Virut_AC_Patt), DecodersPartBuffer, VIRUT_AC_DECODER_PARTS_BUFF_LEN);
#if defined(_DEBUG) && defined(Test)
        if (Percent >= 70)
        {
            DebugMessage("%s %d",PeFile->mFileName, Percent);
        }
#endif
        if (Percent < 100) // below than 70%
        {
            delete[] DecodersPartBuffer;
            return VirusNo;

            // Todo: ????
            //Percent = StochasticPatternSearch(Virut_AI_Patt, NUMBER_OF_ARRAY (Virut_AI_Patt), DecodersPartBuffer, VIRUT_AC_DECODER_PARTS_BUFF_LEN);
#if defined(_DEBUG) && defined(Test)
            if (Percent >= 70)
            {
                DebugMessage("%s %d",PeFile->mFileName, Percent);
            }
#endif
            if (Percent < 100) // below than 70%
            { 
                delete[] DecodersPartBuffer;
                return VirusNo;
            }
            else
            {
                VirusNo = Win32_Virut_AI;
            }
        }
        else
        {
            VirusNo = Win32_Virut_AC;
        }
    }
    else
    {
        VirusNo = Win32_Virut_AB;
    }

    delete[] DecodersPartBuffer;

    if (VirusNo == Win32_Virut_AB)
    {
        CallerFileOffset = FindCallerBranch((PDWORD) &JumpedRVA, 0, 0xe9, &Virut_ABHeuristicInitial, &FullDetectArgument, sizeof(FullDetectArgument));
    }
    else if (VirusNo == Win32_Virut_AC)
    {
        CallerFileOffset = FindCallerBranch((PDWORD) &JumpedRVA, 0, 0xe9, &Virut_ACHeuristicInitial, &FullDetectArgument, sizeof(FullDetectArgument));
    }
    /*
    else if (VirusNo == Win32_Virut_AINo)
    {
        CallerFileOffset = FindCallerBranch((PDWORD) &JumpedRVA, 0, 0xe9, &Virut_AIHeuristicInitial, &FullDetectArgument, sizeof(FullDetectArgument));
    }
    */
    else
    {
        CallerFileOffset = 0;
    }

    if (CallerFileOffset == 0)
    {
        // IsLikeVir
        // State = SUSPICIOUS;
        return VirusNo;
    }

#ifdef Behpad
    if (OpertionType == DisInfect)
    {
        if (FullDetectArgument.StartZero == 0)
        {
            // start of part1 that should be wiped is not exist; virus has 1 part
            *(PDWORD)(buff+0) = FullDetectArgument.StartZero;
        }
        else
        {
            // start of part1 that should be wiped
            *(PDWORD)(buff+0) = PeFile->ConvertAddressToOffset(FullDetectArgument.StartZero);
        }

        if (PeFile->ReadSectionEntryForRVA(FullDetectArgument.StartDeCode - ImageBase, (PBYTE)&SectionEntry) == INVALIDSectionEntry)
        {
            VirusNo |= IsLikeVir;
            return VirusNo | IsLikeVir;
        }

        // *(PDWORD)(buff+4) = FindBlockBetweenZeroBlocksInEndOfSection(&SectionEntry, VIRUT_AC_PART2_MIN_LEN, VIRUT_AC_PART2_MAX_LEN, 8, 0);
        if (*(PDWORD)(buff+4) == OffsetNotFound)
        {
            *(PDWORD)(buff+4) = PeFile->ConvertAddressToOffset(FullDetectArgument.StartDeCode);  // start of part2 that should be wiped or truncated
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

    return VirusNo;
}
//---------------------------------------------------------------------------------------------------------------------
#define countDiff 8
DWORD FindVirutCallerCall (PDWORD CalledRVA, DWORD CoreVirutRVA)
{
    DWORD             FilePtr, JumpedRVA; // OffsetEndSection,
    BYTE              ByteTemp;
    DWORD             EndOffsetOfCode;
    SIGNED_DWORD      CallParam;
    IMAGE_SECTION_HEADER* EIPSectionEntry;
    IMAGE_SECTION_HEADER* LastSectionEntry;
    HeuristicCallBack VirutHeuristic[] = 
    {
        {0, NULL, 0, 0, Continue, NULL, NULL},
        {0, NULL, 0, 0, Continue, NULL, NULL}
    };
    HeuristicCallBack VirutHeuristicInitial = {Win32_Virut_F, DetectVirut, 0, 0, Continue, NULL, NULL, NULL};

    if (CalledRVA)
        *CalledRVA = (DWORD) 0;

    if (LastSectionEntry = PeFile->ReadLastSectionEntry())
    {
        return 0;
    }

    if (EIPSectionEntry = PeFile->ReadSectionEntryForRVA(PeFile->EntryPoint))
    {
        return 0;
    }

    EndOffsetOfCode = EIPSectionEntry->PointerToRawData + EIPSectionEntry->SizeOfRawData - 4;
    FilePtr         = PeFile->EntryPointOffset;

    PeFile->Seek (FilePtr);

    while (FilePtr < EndOffsetOfCode)
    {
        if (PeFile->Read (&ByteTemp,1) < 1)
        {
            return 0;
        }
        
        FilePtr++;
        if (ByteTemp != 0xE8)
            continue;

        if (PeFile->Read (&CallParam, 4) < 4)
            return 0;

        if (CallParam < 0)
        {
            PeFile->Seek (FilePtr);
            continue;
        }

        JumpedRVA = FilePtr + 4 - EIPSectionEntry->PointerToRawData + EIPSectionEntry->VirtualAddress;
        JumpedRVA += CallParam;
        if (JumpedRVA > (EIPSectionEntry->Misc.VirtualSize + EIPSectionEntry->VirtualAddress) && 
           (JumpedRVA < LastSectionEntry->VirtualAddress || JumpedRVA > LastSectionEntry->VirtualAddress + LastSectionEntry->Misc.VirtualSize))
        {
            // Jumped location is not in EIP section and last section
            PeFile->Seek (FilePtr);
            continue;
        }

        __try
        {
            VirutHeuristic[0] = VirutHeuristicInitial;
            HeuristicScanVirus(JumpedRVA, VirutHeuristic);
        }
        __except(1)
        {
            VirutHeuristic[0].Result = No;
        }

        if (VirutHeuristic[0].Result == Yes)
        {
            if (VirutHeuristic[0].FullDetectArgument != NULL)
            {
                if (((StructVirut_F*)(VirutHeuristic[0].FullDetectArgument))->StartClean == CoreVirutRVA)
                {
                    FreeCallbackMems(VirutHeuristic);
                    if (CalledRVA)
                        *CalledRVA = JumpedRVA;
                    return FilePtr - 1;
                }
            }
        }

        FreeCallbackMems(VirutHeuristic);

        if (VirutHeuristic[0].Result == Like)
        {
            if (CalledRVA)
                *CalledRVA = JumpedRVA;

            return 0;
        }
        PeFile->Seek (FilePtr);
    }
    return 0;
}
//---------------------------------------------------------------------------------------------------------------------