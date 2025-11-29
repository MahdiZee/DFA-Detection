#ifndef DfaMachineH
#define DfaMachineH
#include "Type.h"
#include "Pattern.h"

enum {SALITY_ST_START = 0, SALITY_ST_CALL0, SALITY_ST_POP_REG, SALITY_ST_STACK, SALITY_ST_ADD_REG, SALITY_ST_FIRST_PUSH_REG, SALITY_ST_SECOND_PUSH_REG, SALITY_ST_JMP_REG, SALITY_ST_RET, SALITY_ST_MOV_PUSH, SALITY_ST_PUSH_ECX, SALITY_ST_PUSH_EAX, SALITY_ST_PUSH_EAX1, SALITY_ST_POP_ESI, SALITY_ST_SUB_ADD_ESI_EDX, SALITY_ST_SUB_ADD_ESI_EDX2, SALITY_ST_SUB, SALITY_ST_XOR, SALITY_ST_CMP, SALITY_ST_JNZ, SALITY_ST_JMP2};
enum {Virut_START = 0, Virut_MOV_EBP_ESP, Virut_XOR, Virut_PUSH_XXXX, Virut_CALL_API, Virut_MOV_XCHG_1, Virut_CALL_Down, Virut_SUB_ADD, Virut_CALL_X, Virut_POP, Virut_OP_Size, Virut_XOR_SUB, Virut_MOV_XCHG_2, Virut_RET_JMP, Virut_JMP};
enum {Virut_Z_START = 0, Virut_Z_START2, Virut_Z_JMP1, Virut_Z_ADD, Virut_Z_JMP2, Virut_Z_SUB, Virut_Z_JMP3, Virut_Z_JNC, Virut_Z_JMP4, Virut_Z_CALL, Virut_Z_PUSHA, Virut_Z_MOV_EBX, Virut_Z_ADD_EntryPoint, Virut_Z_CMP_M, Virut_Z_JNZ, Virut_Z_CMP_Z, Virut_Z_JZ1, Virut_Z_CALL1, Virut_Z_CALL2, Virut_Z_CALL3, Virut_Z_TEST, Virut_Z_JZ2, Virut_Z_MOV1, Virut_Z_MOV2 };
enum {Virut_Z2_START = 0, Virut_Z2_JMP1, Virut_Z2_PUSHA, Virut_Z2_ADD_MOV_EBX, Virut_Z2_ADD_EntryPoint, Virut_Z2_CMP_M, Virut_Z2_JNZ, Virut_Z2_CMP_Z, Virut_Z2_JZ1, Virut_Z2_CALL1, Virut_Z2_CALL2, Virut_Z2_CALL3, Virut_Z2_TEST, Virut_Z2_JZ2, Virut_Z2_MOV1, Virut_Z2_MOV2 };
enum {VirutAC_START = 0, VirutAC_START2, VirutAC_PUSHA, VirutAC_MOV_EBP, VirutAC_XCHG, VirutAC_MOV_EBX, VirutAC_MOV_EAX, VirutAC_XOR_Z, VirutAC_JNZ, VirutAC_XOR_M, VirutAC_JZ1, VirutAC_CALL1, VirutAC_CALL2, VirutAC_CALL3, VirutAC_TEST, VirutAC_JZ2, VirutAC_MOV1, VirutAC_MOV2 };
enum {VirutAF_START = 0, VirutAF_START2, VirutAF_PUSHA, VirutAF_MOV_EBP, VirutAF_XCHG, VirutAF_MOV_EBX, VirutAF_MOV_EAX, VirutAF_PUSH_EntryPoint, VirutAF_POP_EntryPoint, VirutAF_SUB_Z, VirutAF_JNZ, VirutAF_SUB_M, VirutAF_JZ1, VirutAF_CALL1, VirutAF_CALL2, VirutAF_CALL3, VirutAF_TEST, VirutAF_JZ2, VirutAF_MOV1, VirutAF_MOV2 };
enum {VirutAI_START = 0, VirutAI_START2, VirutAI_PUSHA, VirutAI_LEA_EBX, VirutAI_SUB_EBP, VirutAI_SUB_Z, VirutAI_PUSH2, VirutAI_JNZ, VirutAI_SUB_K, VirutAI_JZ1, VirutAI_CALL1, VirutAI_CALL2, VirutAI_OR, VirutAI_JZ2, VirutAI_MOV1, VirutAI_MOV2 };

typedef enum _ScanResult {Continue, No, Yes, Like, LikeAndContinue, LikeAndPrivateContinue} ScanResult;

typedef struct _StructSality
{
    DWORD StartSection;
    DWORD LenghtKey;
} StructSality, *PStructSality;

typedef struct _StructSality_Z
{
    DWORD StartSection;
    DWORD LenghtKey;
    DWORD XorAdd;
    DWORD Key;
    DWORD Conuter;
} StructSality_Z, *PStructSality_Z;

typedef struct _StructVirut_F
{
    DWORD         StartClean;
    TypeVirutCode BTypeDecode;
} StructVirut_F, *PStructVirut_F;

typedef struct _StructVirut_Z_AB_AC
{
    DWORD StartZero;
    DWORD StartDeCode;
    DWORD EntryPoint;
    union
    {
        DWORD dw;
        struct
        {
            BYTE  chPart;
            DWORD dwPart;
        } s1;
        struct
        {
            DWORD dwPart;
            BYTE  chPart;
        } s2;
        BYTE b[6];
    } MainAPIRVA;
} StructVirut_Z_AB_AC, *PStructVirut_Z_AB_AC;

typedef int (*FuncFullDetect)(PVOID, AntiVirusOpertionType, InfectionResult*);

typedef struct _HeuristicCallBack
{
    DWORD      VirusNo;
    ScanResult (*CallBackFunc)(WORD, PBYTE, _HeuristicCallBack*);
    DWORD      InstructionCounter;
    DWORD      State;
    ScanResult Result;
    PVOID      FullDetectArgument; 
    DWORD      MaxOfInstructionCounter;
    FuncFullDetect *FullDetect;
} HeuristicCallBack, *PHeuristicCallBack;

ScanResult DetectSality    (WORD, PBYTE, HeuristicCallBack*);
ScanResult DetectSality_AD (WORD, PBYTE, HeuristicCallBack*);
ScanResult DetectVirut     (WORD, PBYTE, HeuristicCallBack*);
ScanResult DetectVirut_Z   (WORD, PBYTE, HeuristicCallBack*);
ScanResult DetectVirut_Z2  (WORD, PBYTE, HeuristicCallBack*);
ScanResult DetectVirut_AA  (WORD, PBYTE, HeuristicCallBack*);
ScanResult DetectVirut_AC  (WORD, PBYTE, HeuristicCallBack*);
ScanResult DetectVirut_AD  (WORD, PBYTE, HeuristicCallBack*);
ScanResult DetectVirut_AF  (WORD, PBYTE, HeuristicCallBack*);
ScanResult DetectVirut_AI  (WORD, PBYTE, HeuristicCallBack*);

#endif