#include "Scan.h"
#include "Method.h"
#include "Message.h"
#include "Function.h"
#include "Data.h"
#include "ScanGeneral.h"
#include "DisasmbleTable.h"
#include "ZMemoryManager.h"
#include "FullDetect.h"
#include "Pattern.h"
#include "Type.h"

extern ZMemoryManager* MemoryManager;
//-------------------------------------------------------------------------------------------
void FreeCallbackMems(HeuristicCallBack arrHeuristicCallBack[])
{
    int i;

    for (i = 0; arrHeuristicCallBack[i].CallBackFunc; i++)
    {
        if (arrHeuristicCallBack[i].FullDetectArgument != NULL)
        {
            delete arrHeuristicCallBack[i].FullDetectArgument;
            arrHeuristicCallBack[i].FullDetectArgument = NULL;
        }
    }
}
//-------------------------------------------------------------------------------------------
void Scan (DWORD EntryPoint, AntiVirusOpertionType OpertionType, InfectionResult* Result)
{
    Result->State = VIRALSTATE::VIRUSFREE;

    for (int i = 0; i < NUMBER_OF_ARRAY(ListVirutClean); i++)
    {
        if (DetectVirutEOS(ListVirutClean + i, OpertionType, Result) != NO_INFECTION)
        {
            if (Result->State == VIRALSTATE::INFECTED)
                return;
            break;
        }
    }

    DoHeuristic (EntryPoint, OpertionType, Result);
    if (Result->State == VIRALSTATE::INFECTED)
        return;

    // DetectPolyPart();
}
//-------------------------------------------------------------------------------------------
void DoHeuristic (DWORD EntryPoint, AntiVirusOpertionType OpertionType, InfectionResult* Result)
{
    FuncFullDetect pFullDetectSality_AD[] = {FullDetectSality_AD, NULL};
    FuncFullDetect pFullDetectSality[]    = {FullDetectSality, FullDetectSality_AC, NULL};
    FuncFullDetect pFullDetectVirut[]     = {FullDetectVirutOverWrite, NULL};
    FuncFullDetect pFullDetectVirut_Z[]   = {FullDetectVirut_Z, NULL};
    HeuristicCallBack arrHeuristicCallBack[] =
    {
        {Win32_Sality_AD, DetectSality_AD, 0, 0, Continue, NULL, NULL, pFullDetectSality_AD}, // sality.z
        {Win32_Sality_AA, DetectSality,    0, 0, Continue, NULL, NULL, pFullDetectSality},    // sality.q
        {Win32_Virut_F,   DetectVirut,     0, 0, Continue, NULL, NULL, pFullDetectVirut},     // virut.f
        {Win32_Virut_Z,   DetectVirut_Z,   0, 0, Continue, NULL, NULL, pFullDetectVirut_Z},   // virut.z
        {Win32_Virut_Z,   DetectVirut_Z2,  0, 0, Continue, NULL, NULL, pFullDetectVirut_Z},   // virut.z
        {Win32_Virut_AC,  DetectVirut_AC,  0, 0, Continue, NULL, NULL, pFullDetectVirut_Z},   // virut.ac
        {Win32_Virut_AF,  DetectVirut_AF,  0, 0, Continue, NULL, NULL, pFullDetectVirut_Z},   // virut.af
        {Win32_Virut_AI,  DetectVirut_AI,  0, 0, Continue, NULL, NULL, pFullDetectVirut_Z},   // virut.ai
        {0, NULL, 0, 0, Continue, NULL, NULL, NULL}
    };
    HeuristicCallBack* objHeuristic;
    int Status;
    int i;

    __try
    {
        objHeuristic = HeuristicScanVirus(EntryPoint, arrHeuristicCallBack);
    }
    __except(1)
    {
        objHeuristic = NULL;
        DebugMessage("Heuristic Scan Virus Exception");
    }

    if (objHeuristic == NULL)
    {
        FreeCallbackMems(arrHeuristicCallBack);
        return;
    }

    Result->State = VIRALSTATE::SUSPICIOUS;
    Result->VirusNo = objHeuristic->VirusNo;

    if (objHeuristic->Result == Like)
    {
        FreeCallbackMems(arrHeuristicCallBack);
        return;
    }

    for (i = 0; objHeuristic->FullDetect[i]; i++)
    {
        Status = objHeuristic->FullDetect[i](objHeuristic->FullDetectArgument, OpertionType, Result);
        if (Status != 0)
            break;
    }

    // Result->State = VIRALSTATE::INFECTED;
    FreeCallbackMems(arrHeuristicCallBack);
    return;
}
//------------------------------------------------------------------------------
void HeuristicInit (void)
{
    reax = DefaultEAX;
    recx = DefaultECX;
    redx = DefaultEDX;
    rebx = DefaultEBX;
    resp = DefaultESP;
    rebp = DefaultEBP;
    resi = DefaultESI;
    redi = DefaultEDI;
    BufferInit();
    SetInit();
    ZeroPrefix();
}
//-------------------------------------------------------------------------------------------
void (*pFun[16])(void) = {Method0, Method1, Method2, Method3, Method4, Method5, Method6, Method7, 
                          Immediate, Shift, Grp1, Grp2, Group, Prefix, Grp9, Method8};
//-------------------------------------------------------------------------------------------
HeuristicCallBack* HeuristicScanVirus(DWORD EntryPoint, HeuristicCallBack ListHeuristicCallBack[])
{
    CTable t;
    BOOL   AllNoFlag, BreakFlag, PrivateFlag;
    int    i, j;

    HeuristicInit();
    PrivateFlag = FALSE;
    EIP = EntryPoint;

    //.......... get time (for break unwanted loop) ............
    while (!BufferIsEnd())
    {
        // ........ get time ............
        // find diff; if greater than a value (for example then 10 s) break;

        BufferRead (1, &b[0]);
        t = Table[(int)b[0]];
        SetDW();
        if (t.Method >= ID_IMMEDIATE && t.Method <= ID_GRP2)
        {
            BufferRead (1, &b[1]);
            B = *(BitByte1*) &b[1];
            t.Id = TableALL [ t.Method-ID_IMMEDIATE ][ B.reg ];
        }
        else
        {
            if (t.Method == ID_GROUP)
            {
                BufferRead (1, &b1);
                t = Table0F[b1];

                if (t.Method == ID_Grp9)
                {
                    BufferRead (1, &b[1]);
                    B = *(BitByte1*) &b[1];
                    t.Id = GroupTable[8][B.reg];
                }
            }
        }

        if (t.Method != (BYTE)-7 &&  t.Id != (WORD)-7)
        {
            if (t.Method >= NUMBER_OF_ARRAY(pFun) || t.Id >= NUMBER_OF_ARRAY(pfIns))
            {
                BufferEnd();
            }
            else
            {
                gMemoryManagerMemEntry.Address = 0;
                pFun [t.Method]();
                pfIns[t.Id]();
                if (t.Method != ID_PREFIX)
                    ZeroPrefix();

                if (gMemoryManagerMemEntry.Address != 0)
                {
                    if (Parametr[d] == (PDWORD) &gMemoryManagerMemEntry.Value)
                    {
                        MemoryManager->SetValue(gMemoryManagerMemEntry.Address, gMemoryManagerMemEntry.Value, 4);
                    }
                }

                AllNoFlag = TRUE;
                BreakFlag = TRUE;

                for (i = 0; ListHeuristicCallBack[i].CallBackFunc != NULL; i++)
                {
                    if (ListHeuristicCallBack[i].Result == No)
                        continue;

                    AllNoFlag = FALSE;

                    ListHeuristicCallBack[i].Result = ListHeuristicCallBack[i].CallBackFunc(t.Id, b, ListHeuristicCallBack + i);
                    BreakFlag = BreakFlag && (ListHeuristicCallBack[i].Result == No);

                    if (ListHeuristicCallBack[i].Result == LikeAndPrivateContinue && PrivateFlag == FALSE)
                    {
                        PrivateFlag = TRUE;
                        for (j = 0; ListHeuristicCallBack[j].CallBackFunc != NULL; j++)
                        {
                            if (i != j)
                            {
                                ListHeuristicCallBack[j].Result = No;
                            }
                        }
                    }

                    if (ListHeuristicCallBack[i].Result == Yes || ListHeuristicCallBack[i].Result == Like)
                    {
                        BufferEnd();
                        return ListHeuristicCallBack + i;
                    }
                }
                if (AllNoFlag || BreakFlag)
                {
                    BufferEnd();
                }
            }
        }
        else
        {
            BufferEnd();
        }
    }

    for (i = 0; ListHeuristicCallBack[i].CallBackFunc != NULL; i++)
    {
        if (ListHeuristicCallBack[i].Result == LikeAndContinue || ListHeuristicCallBack[i].Result == LikeAndPrivateContinue)
        {
            ListHeuristicCallBack[i].Result = Like;
            return ListHeuristicCallBack + i;
        }
    }

    return NULL;
}
