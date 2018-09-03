#ifndef FullDetectH
#define FullDetectH
#include "Scan.h"

#define DetectVirutEOS_DecodeLen (0x164)
#define Dummy (0xAA)

BOOL  ComparePattern (PBYTE Src, PBYTE Dst, int Len);
DWORD FindCallerBranch (PDWORD CalledRVA, DWORD CoreVirutRVA, BYTE CallOrJmpInst, PHeuristicCallBack HeuristicInitial, PVOID pParam, UINT ParamLen);
DWORD FindVirutCallerCall (PDWORD CalledRVA, DWORD CoreVirutRVA);
//---------------------------------------------------------------------------------------------------------------------
DWORD DetectVirutEOF (PVirutScanCleanStruct This, BehpadOpertionType OpertionType, InfectionResult* Result);
DWORD DetectVirutEOS (PVirutScanCleanStruct This, BehpadOpertionType OpertionType, InfectionResult* Result);
int   DetectVirut_EndFile (PVirutScanCleanStruct This, BYTE* HeaderDecode, UINT HeaderDecodeLen, DWORD PhysicalAdd, BehpadOpertionType OpertionType, InfectionResult* Result);
BOOL  CheckVirutPattern (PVirutScanCleanStruct This, PBYTE BuffPtr);
TypeVirutCode CheckPattern (PBYTE Src, PBYTE Des, int Size);
//---------------------------------------------------------------------------------------------------------------------
int FullDetectSality         (PVOID objSality, BehpadOpertionType OpertionType, InfectionResult* Result);
int FullDetectSality_AC      (PVOID objSality, BehpadOpertionType OpertionType, InfectionResult* Result);
int FullDetectSality_AD      (PVOID objSality, BehpadOpertionType OpertionType, InfectionResult* Result);
int FullDetectVirut_Z        (PVOID objVirut,  BehpadOpertionType OpertionType, InfectionResult* Result);
int FullDetectVirutOverWrite (PVOID objVirut,  BehpadOpertionType OpertionType, InfectionResult* Result);
//---------------------------------------------------------------------------------------------------------------------
BOOL  DecodeVirut_Z (DWORD StartDeCode, DWORD Lenght, DWORD Key);
DWORD DetectVirut_AB (void);
DWORD DetectVirut_AC (void);

#endif