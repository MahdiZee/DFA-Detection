#ifndef StochasticH
#define StochasticH
#include "DfaMachine.h"
#include "Pattern.h"

#define OffsetNotFound (0)
#define VIRUT_AC_PART2_MIN_LEN          0x4000
#define VIRUT_AC_PART2_MAX_LEN          0x4500
#define VIRUT_AC_DECODER_PART_MAX_LEN   0x650
#define VIRUT_AC_DECODER_PARTS_BUFF_LEN (2*VIRUT_AC_DECODER_PART_MAX_LEN)

typedef int (*fptr)(const void*, const void*);

typedef struct _HeuristicStochastic
{
    HeuristicCallBack VirusHeuristicInitial;
    StochasticPattern *VirusStochasticPattern;
} HeuristicStochastic;

typedef struct _PolyPart
{
    DWORD MinLen;
    DWORD MaxLen;
    DWORD DecoderPartLen;
    HeuristicStochastic *VirusHeuristicStochastic;
    DWORD CountCallBackEntry;
}PolyPart, *PPolyPart;

extern StochasticPattern Virut_AB_Patt1[];
extern StochasticPattern Virut_AB_Patt2[];
extern StochasticPattern Virut_AC_Patt[];
extern StochasticPattern Virut_AI_Patt[];

int StochasticCompare(PBYTE p1, PStochasticPattern p2);
DWORD StochasticPatternSearch(StochasticPattern* Pattern, DWORD PatternsPart, PBYTE Buffer, DWORD LenBuffer);
DWORD DetectPolyPartEOF(PPolyPart This);
DWORD DetectPolyPart();
BOOL  PoloyPartInitClean(PVOID Arg);

#endif