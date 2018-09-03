#include <windows.h>
#include "ScanGeneral.h"
#include "DfaMachine.h"

#define b0 b[0]
#define b1 b[1]
#define b2 b[2]

void FreeCallbackMems(HeuristicCallBack arrHeuristicCallBack[]);
void Scan (DWORD EntryPoint, BehpadOpertionType OpertionType, InfectionResult* Result);
void DoHeuristic (DWORD EntryPoint, BehpadOpertionType OpertionType, InfectionResult* Result);
HeuristicCallBack* HeuristicScanVirus(DWORD EntryPoint, HeuristicCallBack ListHeuristicCallBack[]);
