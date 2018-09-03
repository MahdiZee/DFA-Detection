#ifndef PatternH
#define PatternH
#include "Type.h"
#include "ScanGeneral.h"

#define END_STOCHASTIC_PATTERN (-1)

typedef enum _TypeVirutCode{ NonDetectVirut, XorVirut, SubVirut } TypeVirutCode;
typedef struct _VirutScanCleanStruct
{
    DWORD VirusNo;
    BYTE Pattern[20];
    DWORD CheckCall;
    DWORD SizeOfBackWard;
    WORD LenghtSub_DiffFromHeadCode;
    WORD Base;
    WORD EBP;
    WORD SizeOverWrite;
    WORD TestAdd;
    TypeVirutCode TypeDecode;
    BYTE Key;
    BYTE KeyAdd;
} VirutScanCleanStruct, *PVirutScanCleanStruct;

typedef struct _HeuristicPattern
{
    BYTE PatternOccurance;
    BYTE PatternLen;
    int  Dependency[2];
    BYTE Pattern[5];
    BYTE Mask[5];
} StochasticPattern, *PStochasticPattern;

extern VirutScanCleanStruct ListVirutClean[6];

#endif