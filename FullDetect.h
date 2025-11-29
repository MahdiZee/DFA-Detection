#ifndef FullDetectH
#define FullDetectH
#include "Scan.h"

#define DetectVirutEOS_DecodeLen (0x164)
#define Dummy (0xAA)

BOOL  ComparePattern (PBYTE Src, PBYTE Dst, int Len);
DWORD FindCallerBranch (PDWORD CalledRVA, DWORD CoreVirutRVA, BYTE CallOrJmpInst, PHeuristicCallBack HeuristicInitial, PVOID pParam, UINT ParamLen);
DWORD FindVirutCallerCall (PDWORD CalledRVA, DWORD CoreVirutRVA);
//---------------------------------------------------------------------------------------------------------------------
DWORD DetectVirutEOF (PVirutScanCleanStruct This, AntiVirusOpertionType OpertionType, InfectionResult* Result);
DWORD DetectVirutEOS (PVirutScanCleanStruct This, AntiVirusOpertionType OpertionType, InfectionResult* Result);
int   DetectVirut_EndFile (PVirutScanCleanStruct This, BYTE* HeaderDecode, UINT HeaderDecodeLen, DWORD PhysicalAdd, AntiVirusOpertionType OpertionType, InfectionResult* Result);
BOOL  CheckVirutPattern (PVirutScanCleanStruct This, PBYTE BuffPtr);
TypeVirutCode CheckPattern (PBYTE Src, PBYTE Des, int Size);
//---------------------------------------------------------------------------------------------------------------------
int FullDetectSality         (PVOID objSality, AntiVirusOpertionType OpertionType, InfectionResult* Result);
int FullDetectSality_AC      (PVOID objSality, AntiVirusOpertionType OpertionType, InfectionResult* Result);
int FullDetectSality_AD      (PVOID objSality, AntiVirusOpertionType OpertionType, InfectionResult* Result);
int FullDetectVirut_Z        (PVOID objVirut,  AntiVirusOpertionType OpertionType, InfectionResult* Result);
int FullDetectVirutOverWrite (PVOID objVirut,  AntiVirusOpertionType OpertionType, InfectionResult* Result);
//---------------------------------------------------------------------------------------------------------------------
BOOL  DecodeVirut_Z (DWORD StartDeCode, DWORD Lenght, DWORD Key);
DWORD DetectVirut_AB (void);
DWORD DetectVirut_AC (void);

#endif