#include <stdlib.h>
#include <string.h>    

#include "DisasmbleTable.h"
#include "Function.h"
#include "Data.h"
#include "DfaMachine.h"
#include "BMemoryManager.h"
#include "BPeFile.h"

extern __Flag Flag;
extern BPeFile* PeFile;

extern void X86Emul_RetWithNumber(SIGNED_DWORD Number);
extern void JMP(void); 

BOOL DecodeVirut_Z(DWORD StartDeCode, DWORD Lenght, DWORD Key);
//--------------------------------------------------------------------------------------
ScanResult DetectSality(WORD Ins, PBYTE OpCode, HeuristicCallBack* This)
{
    static BYTE SalityReg;
    static DWORD InstructionCounterSave;

    switch (This->State)
    {
    case SALITY_ST_START:
        InstructionCounterSave = (DWORD)0;
        if (Ins == ID_PUSHA)
            This->State = SALITY_ST_CALL0;
        else
            return No;
        break;
    case SALITY_ST_CALL0:
        if (Ins == ID_CALL && *OpCode == 0xE8 && *(PDWORD)(OpCode+1) == 0)
        {
            This->InstructionCounter = InstructionCounterSave;
            This->State = SALITY_ST_POP_REG;
        }
        break;
    case SALITY_ST_POP_REG:
        if (Ins == ID_POP && (*OpCode | 0x07) == 0x5f)
        {
            SalityReg = *OpCode & 0x07;
            This->State = SALITY_ST_ADD_REG;
        }
        else if (Ins == ID_PUSH)
        {
            This->State = SALITY_ST_STACK;
        }
            break;
    case SALITY_ST_STACK:
        if (Ins == ID_POP || (Ins == ID_CALL && (*OpCode == 0xff) && *(OpCode+1) == 0x15))
        {
            This->State = SALITY_ST_POP_REG;
        }
        break;
    case SALITY_ST_ADD_REG:
        if (Ins == ID_ADD && *OpCode == 0x81  && Parametr[0] == &Reg[SalityReg].ex)
        {
            This->State = SALITY_ST_FIRST_PUSH_REG;
            This->InstructionCounter = InstructionCounterSave;
        }
        else
            This->State = SALITY_ST_POP_REG;
        break;
    case SALITY_ST_FIRST_PUSH_REG:
        if (Ins == ID_PUSH && (*OpCode | 0x07) == 0x57 && Parametr[0] == &Reg[SalityReg].ex)
        {
            This->State = SALITY_ST_SECOND_PUSH_REG;
            This->InstructionCounter = InstructionCounterSave;
        }
        break;
    case SALITY_ST_SECOND_PUSH_REG:
        if (Ins == ID_PUSH && (*OpCode | 0x07) == 0x57 && Parametr[0] == &Reg[SalityReg].ex)
        {
            This->State = SALITY_ST_JMP_REG;
            This->InstructionCounter = InstructionCounterSave;
        }
        else if (Ins == ID_POP && (*OpCode | 0x07) == 0x5f && Parametr[0] == &Reg[SalityReg].ex)
        {
            InstructionCounterSave = This->InstructionCounter;
            This->State = SALITY_ST_FIRST_PUSH_REG;
        }
        break;
    case SALITY_ST_JMP_REG:
        if (Ins == ID_POP && (*OpCode | 0x07) == 0x5f && Parametr[0] == &Reg[SalityReg].ex)
        {
            InstructionCounterSave = This->InstructionCounter;
            This->State = SALITY_ST_SECOND_PUSH_REG;
        }
        else if (Ins == ID_JMP && (*OpCode == 0xff) && Parametr[0] == &Reg[SalityReg].ex)
        {
            This->InstructionCounter = 0;
            This->State = SALITY_ST_MOV_PUSH;
            if (This->FullDetectArgument == NULL)
            {
                This->FullDetectArgument = new StructSality;
                if (This->FullDetectArgument == NULL) 
                    return Like;
                memset(This->FullDetectArgument, 0, sizeof(StructSality));
            }
            ((PStructSality)(This->FullDetectArgument))->StartSection = PeFile->ConvertAddressToOffset(EIP);
        }
        else if (Ins == ID_PUSH && (*OpCode | 0x07) == 0x57 && Parametr[0] == &Reg[SalityReg].ex)
        {
            This->State = SALITY_ST_RET;
        }
        break;
    case SALITY_ST_RET:
        if (Ins == ID_RET && (*OpCode == 0xc3))
        {
            This->InstructionCounter = 0;
            This->State = SALITY_ST_MOV_PUSH;
            if (This->FullDetectArgument == NULL)
            {
                This->FullDetectArgument = new StructSality;
                if (This->FullDetectArgument == NULL)
                    return Like;
                memset(This->FullDetectArgument, 0, sizeof(StructSality));
            }
            ((PStructSality)(This->FullDetectArgument))->StartSection = PeFile->ConvertAddressToOffset(EIP);
        }
        else if (Ins == ID_POP && (*OpCode | 0x07) == 0x5f && Parametr[0] == &Reg[SalityReg].ex)
        {
            This->State = SALITY_ST_JMP_REG;
        }
        break;
    case SALITY_ST_MOV_PUSH:
        if (Ins == ID_MOV && (*OpCode == 0x89) && (*(OpCode+3) == 0x0c))
        {
            ((StructSality*)(This->FullDetectArgument))->LenghtKey = *(TopStack+8);
            return Yes;
        }
        else if (Ins == ID_PUSH && (*OpCode == 0x56) && (END_OF_STACK - TopStack == 0x40))
            This->State = SALITY_ST_PUSH_ECX;
        break;
    case SALITY_ST_PUSH_ECX :
        if (Ins == ID_PUSH && (*OpCode == 0x51) && (END_OF_STACK - TopStack) == 0x44)
            This->State = SALITY_ST_PUSH_EAX;

        break;
    case SALITY_ST_PUSH_EAX :
        if (Ins == ID_PUSH && (*OpCode == 0x50) && (END_OF_STACK - TopStack) == 0x48)
        {
            ((StructSality*)(This->FullDetectArgument))->LenghtKey = *(TopStack+20);
            return Yes;
        }
        break;
    }
    if (Ins == ID_CALL && *OpCode == 0xE8 && *(PDWORD)(OpCode+1) != 0)
        return No;

    (This->InstructionCounter)++;

    if (This->State < SALITY_ST_MOV_PUSH  && This->InstructionCounter < 150)
    {
        return Continue;
    }

    if (This->State >= SALITY_ST_MOV_PUSH)
    {
        if (This->InstructionCounter < 1000)
            return LikeAndContinue;
        else
            return Like;
    }
    return No;
}
//--------------------------------------------------------------------------------------
#define Sality_Z_Max_Decode_Counter 0x400
ScanResult DetectSality_AD(WORD Ins, PBYTE OpCode, HeuristicCallBack* This)
{
    static BYTE SalityReg;
    static BOOL _Flag;
    static int  DecodeCounter;
    static DWORD InstructionCounterSave;

    switch (This->State)
    {
    case SALITY_ST_START:
        _Flag = TRUE;
        InstructionCounterSave = 0;
        if (Ins == ID_PUSHA)
        {
            This->State = SALITY_ST_CALL0;
        }
        else
            return No;
        break;
    case SALITY_ST_CALL0:
        if (Ins == ID_CALL && *OpCode == 0xE8 && *(PDWORD)(OpCode+1) != 0)
        {
            This->InstructionCounter = InstructionCounterSave;
            This->State = SALITY_ST_POP_REG;
        }
        break;
    case SALITY_ST_POP_REG:
        if (Ins == ID_POP && (*OpCode | 0x07) == 0x5f && (END_OF_STACK - TopStack == 0x24))
        {
            SalityReg = *OpCode & 0x07;
            This->State = SALITY_ST_ADD_REG;
        }
        else if (Ins == ID_RET && _Flag == TRUE)
        {
            This->State = SALITY_ST_CALL0;
        }
        else
        {
            _Flag = FALSE;
        }
        break;
    case SALITY_ST_ADD_REG:
        if (Ins == ID_ADD && *OpCode == 0x81 && Parametr[0] == &Reg[SalityReg].ex)
        {
            This->State = SALITY_ST_FIRST_PUSH_REG;
            This->InstructionCounter = InstructionCounterSave;
        }
        break;
    case SALITY_ST_FIRST_PUSH_REG:
        if (Ins == ID_PUSH && (*OpCode | 0x07) == 0x57 && (END_OF_STACK - TopStack == 0x28))
        {
            This->State = SALITY_ST_SECOND_PUSH_REG;
            This->InstructionCounter = InstructionCounterSave;
        }
        break;
    case SALITY_ST_SECOND_PUSH_REG:
        if (Ins == ID_PUSH && (*OpCode | 0x07) == 0x57 && (END_OF_STACK - TopStack == 0x2c))
        {
            This->State = SALITY_ST_JMP_REG;
            This->InstructionCounter = InstructionCounterSave;
        }
        else if (Ins == ID_POP && (*OpCode | 0x07) == 0x5f && (END_OF_STACK - TopStack == 0x24))
        {
            InstructionCounterSave = This->InstructionCounter;
            This->State = SALITY_ST_FIRST_PUSH_REG;
        }
        break;
    case SALITY_ST_JMP_REG:
        if (Ins == ID_JMP && (*OpCode == 0xff))
        {
            This->InstructionCounter = 0;
            This->State = SALITY_ST_SUB;
            if (This->FullDetectArgument == NULL)
            {
                This->FullDetectArgument = new StructSality_Z;
                if (This->FullDetectArgument == NULL) 
                    return Like;
                memset(This->FullDetectArgument, 0, sizeof(StructSality_Z));
            }
            ((PStructSality_Z)(This->FullDetectArgument))->StartSection = PeFile->ConvertAddressToOffset(EIP);
        }
        else if (Ins == ID_PUSH && (*OpCode | 0x07) == 0x57 && (END_OF_STACK - TopStack == 0x30))
        {
            This->State = SALITY_ST_RET;
        }
        else if (Ins == ID_POP && (*OpCode | 0x07) == 0x5f && (END_OF_STACK - TopStack == 0x28))
        {
            InstructionCounterSave = This->InstructionCounter;
            This->State = SALITY_ST_SECOND_PUSH_REG;
        }
        break;
    case SALITY_ST_RET:
        if (Ins == ID_RET && (*OpCode == 0xc3))
        {
            This->InstructionCounter = 0;
            This->State = SALITY_ST_SUB;
            if (This->FullDetectArgument == NULL)
            {
                This->FullDetectArgument = new StructSality_Z;
                if (This->FullDetectArgument == NULL) 
                    return Like;
                memset(This->FullDetectArgument, 0, sizeof(StructSality_Z));
            }
            ((PStructSality_Z)(This->FullDetectArgument))->StartSection = PeFile->ConvertAddressToOffset(EIP);
        }
        else if (Ins == ID_POP && (*OpCode | 0x07) == 0x5f && (END_OF_STACK - TopStack == 0x2c))
        {
            This->State = SALITY_ST_JMP_REG;
        }
        break;
    case SALITY_ST_SUB:
        if (Ins == ID_SUB && Parametr[0] == &Reg[SalityReg].ex)
        {
            DecodeCounter = 0;
            SetThresholdOfBufferShouldBeCached(*Parametr[1]+0x200);
            This->State = SALITY_ST_XOR;
        }
        else
            This->State = SALITY_ST_MOV_PUSH;
        break;
    case SALITY_ST_MOV_PUSH:
        if (Ins == ID_PUSH && (*OpCode == 0x56) && (END_OF_STACK - TopStack == 0x40))
            This->State = SALITY_ST_PUSH_ECX;
        break;
    case SALITY_ST_XOR:
        if (Ins == ID_XOR && ((*(PWORD)OpCode & 0xf8ff) == 0xf081 || *OpCode == 0x35))
        {
            This->State = SALITY_ST_CMP;
        }
        break;
    case SALITY_ST_CMP:
        if (Ins == ID_CMP && ((*(PWORD)OpCode & 0xf8ff) == 0xf881 || *OpCode == 0x3d))
            This->State = SALITY_ST_JNZ;
        break;
    case SALITY_ST_JNZ:
        if (Ins == ID_JNZ)
        {
            This->InstructionCounter = 0;
            DecodeCounter++;
            if ((! Flag.Z) && DecodeCounter <= Sality_Z_Max_Decode_Counter)
            {
                JMP();
                This->State = SALITY_ST_CMP;
            }
            else
            {
                This->State = SALITY_ST_JMP2;
            }
        }
        else
            This->State = SALITY_ST_MOV_PUSH;
        break;
    case SALITY_ST_JMP2:
        if (Ins == ID_JMP && Parametr[0] == &Reg[SalityReg].ex)
        {
            ((PStructSality_Z)(This->FullDetectArgument))->StartSection = PeFile->ConvertAddressToOffset(EIP);
            This->InstructionCounter = 0;
            This->State = SALITY_ST_MOV_PUSH;
        }
        break;
    case SALITY_ST_PUSH_ECX:
        if (Ins == ID_PUSH && (*OpCode == 0x51) && (END_OF_STACK - TopStack) == 0x44)
            This->State = SALITY_ST_PUSH_EAX;
        break;
    case SALITY_ST_PUSH_EAX:
        if (Ins == ID_PUSH && (*OpCode == 0x50) && (END_OF_STACK - TopStack) == 0x48)
        {
            ((PStructSality_Z)(This->FullDetectArgument)) ->LenghtKey = *(TopStack+20);
            This->State = SALITY_ST_PUSH_EAX1;
        }
        break;
    case SALITY_ST_PUSH_EAX1:
        if (Ins == ID_PUSH && *OpCode == 0xff && *(OpCode+1) == 0x30)
        {
            This->State = SALITY_ST_POP_ESI;
        }
        else if (Ins == ID_MOV && *(PWORD)OpCode == 0x308b)
        {
            This->State = SALITY_ST_SUB_ADD_ESI_EDX;
        }
        break;
    case SALITY_ST_POP_ESI:
        if (Ins == ID_POP && *OpCode == 0x5e)
        {
            This->State = SALITY_ST_SUB_ADD_ESI_EDX;
        }
        break;
    case SALITY_ST_SUB_ADD_ESI_EDX:
        if (Ins == ID_SUB && (*(OpCode+1) & 0xc7) == 6)
        {
            ((PStructSality_Z)(This->FullDetectArgument))->Conuter = 0;
            ((PStructSality_Z)(This->FullDetectArgument))->XorAdd  = 0;
            ((PStructSality_Z)(This->FullDetectArgument))->Key     = -(SIGNED_DWORD)(*Parametr[1]);
            This->State = SALITY_ST_SUB_ADD_ESI_EDX2;
        }
        else if (Ins == ID_ADD && (*(OpCode+1) & 0xc7) == 6)
        {
            ((PStructSality_Z)(This->FullDetectArgument))->Conuter = 0;
            ((PStructSality_Z)(This->FullDetectArgument))->XorAdd  = 0;
            ((PStructSality_Z)(This->FullDetectArgument))->Key     = *Parametr[1];
            This->State = SALITY_ST_SUB_ADD_ESI_EDX2;
        }
        else if (Ins == ID_XOR && (*(OpCode+1) & 0xc7) == 6)
        {
            ((PStructSality_Z)(This->FullDetectArgument))->Conuter = 0;
            ((PStructSality_Z)(This->FullDetectArgument))->XorAdd = 1;
            ((PStructSality_Z)(This->FullDetectArgument))->Key = *Parametr[1];
            This->State = SALITY_ST_SUB_ADD_ESI_EDX2;
        }
        break;
    case SALITY_ST_SUB_ADD_ESI_EDX2:
        if (Ins == ID_ADD && *OpCode == 0x02 && (*(OpCode+1) & 0xc0) == 0)
        {
            return Yes;
        }
        else if (Ins == ID_SUB && (*(PWORD)(OpCode)&0xc0FC) == 0x0028)
        {
            ((PStructSality_Z)(This->FullDetectArgument))->Conuter++;
        }
        else if (Ins == ID_ADD && (*(PWORD)(OpCode)&0xc0FC) == 0x0000)
        {
            ((PStructSality_Z)(This->FullDetectArgument))->Conuter++;
        }
        else if (Ins == ID_XOR && (*(PWORD)(OpCode)&0xc0FC) == 0x0030)
        {
            ((PStructSality_Z)(This->FullDetectArgument))->Conuter++;
        }

        break;
    }

    if (This->State > SALITY_ST_PUSH_EAX && Ins == ID_JL)
    {
        JMP();
    }
    if (Ins == ID_CALL && *OpCode == 0xE8 && *(PDWORD)(OpCode+1) == 0)
        return No;

    (This->InstructionCounter)++;

    if (This->State < SALITY_ST_MOV_PUSH  && This->InstructionCounter < 150)
    {
        return Continue;
    }

    if (This->State >= SALITY_ST_MOV_PUSH)
    {
        if (This->InstructionCounter < 1400)
            return LikeAndContinue;
        else
            return Like;
    }

    return No;
}

//--------------------------------------------------------------------------------------
ScanResult DetectVirut(WORD Ins, PBYTE OpCode, HeuristicCallBack* This)
{
    static BYTE VirutReg;
    static DWORD InstructionCounterSave;

    if (This->State != Virut_CALL_API && Ins == ID_CALL && *(PWORD)OpCode == 0x15FF)
        return No;

    if (This->State != Virut_MOV_XCHG_1 && Ins == ID_CALL && *OpCode == 0xE8 && (*(PDWORD)(TopStack) > EIP || (EIP - *(PDWORD)(TopStack)) > 255))
        return No;

    switch (This->State)
    {
    case Virut_START:
        InstructionCounterSave = (DWORD) 0;
#ifdef MyVersion
        This->MaxOfInstructionCounter = 0;
#endif
        if (Ins == ID_PUSHA || (Ins == ID_CALL && *OpCode == 0xE8))
            This->State = Virut_XOR;
        else 
        if (Ins == ID_SUB || *(PWORD)OpCode == 0xC029)
            This->State = Virut_XOR;
        else 
        if (Ins == ID_PUSH && *OpCode == 0x55)
            This->State = Virut_MOV_EBP_ESP;
        else
        if (Ins == ID_CLD || Ins == ID_STC || Ins == ID_CMC || Ins == ID_CLC || Ins == ID_NOP ||
            (Ins == ID_JMP  && *(OpCode+1) == 0) ||
            (Ins == ID_XCHG && Parametr[0] == Parametr[1]) ||
            (Ins == ID_MOV  && Parametr[0] == Parametr[1])
           )
        {
            This->State = Virut_START;
        }
        else
        {
            return No;
        }
        break;
    case Virut_MOV_EBP_ESP:
        This->InstructionCounter = 0;
        if (Ins == ID_MOV && *(PWORD)(OpCode) == 0xEC8B)
            This->State = Virut_XOR;
        else
            return No;
        break;
    case Virut_XOR :
        if (Ins == ID_XOR && Parametr[0] == Parametr[1])
        {
            VirutReg = Parametr[0] - (PDWORD)Reg;
            This->State = Virut_PUSH_XXXX;
            InstructionCounterSave =  This->InstructionCounter;
        }
        else
            if (Ins == ID_CALL && *OpCode == 0xE8)
            {
                This->State = Virut_POP;
            }
            break;
    case Virut_PUSH_XXXX  :
        if (Ins == ID_PUSH && Parametr[0] == &Reg[VirutReg].ex)
        {
            This->State = Virut_CALL_API;
        }
        else
            if (Ins == ID_PUSH && *OpCode == 0x68)
            {
                This->State = Virut_CALL_API;
            }
            else
                if (Ins == ID_CALL && *OpCode == 0xE8)
                {
                    This->State = Virut_POP;
                }
                else
                {
                    This->InstructionCounter = InstructionCounterSave;
                    This->State = Virut_XOR;
                }
                break;
    case Virut_CALL_API :
        if (Ins == ID_CALL && *(PWORD)OpCode == 0x15FF)
        {
            This->State = Virut_CALL_X;
            This->InstructionCounter = InstructionCounterSave;
        }
        else
            if (Ins == ID_PUSH && Parametr[0] == &Reg[VirutReg].ex)
            {
                This->State = Virut_CALL_API;
            }
            else if (Ins == ID_PUSH && *OpCode == 0x68)
            {
                This->State = Virut_CALL_API;
            }
            else if (Ins == ID_CALL && *OpCode == 0xE8)
            {
                This->State = Virut_POP;
            }
            else
            {
                This->InstructionCounter = InstructionCounterSave;
                This->State = Virut_XOR;
            }
            break;
    case Virut_CALL_X:
        if (Ins == ID_CALL && *OpCode == 0xE8)
        {
            This->State = Virut_POP;
        }
        else
            if (Ins == ID_XOR && Parametr[0] == Parametr[1])
            {
                VirutReg = Parametr[0] - (PDWORD)Reg;
                This->State = Virut_PUSH_XXXX;
                InstructionCounterSave =  This->InstructionCounter;
            }
            break;
    case Virut_POP:
        if (Ins == ID_POP && (*OpCode | 0x07) == 0x5f)
        {
            VirutReg = *OpCode & 0x07;
            This->State = Virut_SUB_ADD;
        }
        else
        {
            This->State = Virut_CALL_X;
        }
        break;
    case Virut_SUB_ADD:
        if ((Ins == ID_SUB || Ins == ID_ADD) && Parametr[0] == &Reg[VirutReg].ex)
        {
            This->State = Virut_MOV_XCHG_1;
            This->InstructionCounter = 0;

            if (This->FullDetectArgument == NULL) 
            {
                (This->FullDetectArgument) = new StructVirut_F;
                if (This->FullDetectArgument == NULL) 
                    return No;
                memset(This->FullDetectArgument, 0, sizeof(StructVirut_F));
            }
            ((PStructVirut_F)(This->FullDetectArgument))->StartClean = *Parametr[0] - PeFile->ImageBase;
        }
        break;
    case Virut_MOV_XCHG_1:
        if ((Ins == ID_MOV && (*OpCode == 0x88 || *OpCode == 0x8A)) || (Ins == ID_XCHG && *OpCode == 0x86))
            This->State = Virut_OP_Size;
        else if (Ins == ID_CALL && *OpCode == 0xE8)
            This->State = Virut_CALL_Down;
        break;
    case Virut_CALL_Down:
        This->VirusNo = Win32_Virut_I;
        if ((Ins == ID_MOV && (*OpCode == 0x88 || *OpCode == 0x8A)) || (Ins == ID_XCHG && *OpCode == 0x86))
            This->State = Virut_OP_Size;
        break;
    case Virut_OP_Size  :
        if (Ins == ID_OPSIZE && *OpCode == 0x66)
            This->State = Virut_XOR_SUB;
        break;
    case Virut_XOR_SUB  :
        if ((Ins == ID_XOR && *OpCode == 0x31))
        {
            ((StructVirut_F*)(This->FullDetectArgument))->BTypeDecode = XorVirut;
            This->State = Virut_MOV_XCHG_2;

        }
        else if (Ins == ID_SUB && *OpCode == 0x29)
        {
            ((StructVirut_F*)(This->FullDetectArgument))->BTypeDecode = SubVirut;
            This->State = Virut_MOV_XCHG_2;
        }
        else
        {
            This->State = Virut_OP_Size;
        }
        break;
    case Virut_MOV_XCHG_2  :
        if ((Ins == ID_MOV && (*OpCode == 0x88 || *OpCode == 0x8A)) || (Ins == ID_XCHG && *OpCode == 0x86))
        {
            This->State = Virut_RET_JMP;
            This->InstructionCounter = 0;
        }
        break;
    case Virut_RET_JMP :
        if (Ins == ID_RET && *OpCode == 0xc3 && This->VirusNo == Win32_Virut_I)
            This->State = Virut_JMP;
        else if (Ins == ID_JMP && (*OpCode == 0xff) && Parametr[0] == &Reg[VirutReg].ex)
        {
            return Yes;
        }
        break;
    case Virut_JMP :
        if (Ins == ID_JMP && (*OpCode == 0xff) && Parametr[0] == &Reg[VirutReg].ex)
        {
            return Yes;
        }
        break;
    }

    if (Ins == ID_JZ && *(PWORD)OpCode == 0x0474)
    {
        JMP();
    }

    // dont increment InstructionCounter for NULL instructions
    if (!(Ins == ID_CLD || Ins == ID_STC || Ins == ID_CMC ||
        Ins == ID_CLC || Ins == ID_NOP ||
        (Ins == ID_JMP  && *(OpCode+1) == 0) ||
        (Ins == ID_XCHG && Parametr[0] == Parametr[1]) ||
        (Ins == ID_MOV  && Parametr[0] == Parametr[1]))
       )
    {
        (This->InstructionCounter)++;
    }

#ifdef MyVersion
    This->MaxOfInstructionCounter = MAX(This->MaxOfInstructionCounter, This->InstructionCounter);
#endif

    if (This->InstructionCounter < 45)
        return Continue;

    return No;
}

//--------------------------------------------------------------------------------------
ScanResult DetectVirut_Z(WORD Ins, PBYTE OpCode, HeuristicCallBack* This)
{
    static BYTE  VirutReg;
    static DWORD Key;
    static DWORD Lenght;
    static DWORD SaveEIP;
    static DWORD MinEIP;

    if (This->State <= Virut_Z_JMP4 && (Ins == ID_CALL || Ins == ID_PUSH || Ins == ID_POP || Ins == ID_RET || Ins == ID_PUSHA || Ins == ID_POPA))
        return No;

    switch (This->State)
    {
    case Virut_Z_START:
        MinEIP = EIP;
        This->State = Virut_Z_START2;
        //break; we dont use break, because we want to go to
        //       next state immediately
    case Virut_Z_START2:
        if (Ins == ID_MOV && ((*OpCode)&0xB8) == 0xB8 && *Parametr[1] >= 0x4000 && *Parametr[1] < 0x4500)
        {
            Key = 0;
            Lenght = 0;
            SaveEIP = 0;
            VirutReg = (*OpCode) & 0x07;
            This->State = Virut_Z_JMP1;
        }
        break;
    case Virut_Z_JMP1:
        if (Ins == ID_JMP && (*OpCode == 0xE9 || *OpCode == 0xEB))
        {
            SaveEIP = EIP;
            MinEIP = MIN(MinEIP, EIP);
            This->InstructionCounter = 0;
            This->State = Virut_Z_ADD;
        }
        break;
    case Virut_Z_ADD:
        if (Ins == ID_ADD && *OpCode == 0x81 && (*(OpCode+1)&0x80) == 0x80 && (*(OpCode+1)&7) == VirutReg)
        {
            if (This->FullDetectArgument == NULL)
            {
                (This->FullDetectArgument) = new StructVirut_Z_AB_AC;
                if (This->FullDetectArgument == NULL) 
                    return No;
                memset(This->FullDetectArgument, 0, sizeof(StructVirut_Z_AB_AC));
            }
            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode = *(PDWORD)(OpCode+2);
            Key = *Parametr[1];
            Lenght = Reg[VirutReg].ex;
            This->State = Virut_Z_JMP2;
        }
        break;
    case Virut_Z_JMP2:
        if (Ins == ID_JMP && (*OpCode == 0xE9 || *OpCode == 0xEB))
        {
            MinEIP = MIN(MinEIP, EIP);
            This->InstructionCounter = 0;
            This->State = Virut_Z_SUB;
        }
        break;
    case Virut_Z_SUB:
        if (Ins == ID_SUB && *OpCode == 0x83 && (*(OpCode+1)&0xF8) == 0xE8 && (*(OpCode+1)&7) == VirutReg  && *Parametr[1] == 4)
        {
            This->State = Virut_Z_JMP3;
        }
        else
            if (Ins == ID_ADD && *OpCode == 0x83 && (*(OpCode+1)&0xF8) == 0xC0 && (*(OpCode+1)&7) == VirutReg  && *Parametr[1] == (DWORD) -4)
            {
                This->VirusNo = Win32_Virut_AE;
                This->State   = Virut_Z_JMP3;
            }
            break;
    case Virut_Z_JMP3:
        if (Ins == ID_JMP && (*OpCode == 0xE9 || *OpCode == 0xEB))
        {
            MinEIP = MIN(MinEIP, EIP);
            This->InstructionCounter = 0;
            This->State = Virut_Z_JNC;
        }
        break;
    case Virut_Z_JNC:
        if (Ins == ID_JNC && SaveEIP == *Parametr[0])
        {
            This->State = Virut_Z_JMP4;
        }
        else
            if (Ins == ID_JC && SaveEIP == *Parametr[0])
            {
                if (This->VirusNo != Win32_Virut_AE)
                {
                    return Like;
                }

                This->State = Virut_Z_JMP4;
            }

            break;
    case Virut_Z_JMP4:
        if (Ins == ID_JMP && *OpCode == 0xE9)
        {
            This->InstructionCounter = 0;
            if (!DecodeVirut_Z(((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode, Lenght, Key))
                return Like;

            This->State = Virut_Z_CALL;
        }
        break;
    case Virut_Z_CALL:
        if (Ins == ID_CALL && *(PDWORD)(OpCode+1) <= 0x000000ff)
        {
            This->State = Virut_Z_PUSHA;
        }
        break;
    case Virut_Z_PUSHA:
        if (Ins == ID_PUSHA)
        {
            This->InstructionCounter = 0;
            This->State = Virut_Z_MOV_EBX;
        }
        break;
    case Virut_Z_MOV_EBX:
        // below lines should be here as is
        // we want to find "mov", but if not found should find "add"
        if (Ins == ID_ADD && *(PDWORD)(OpCode) == 0x20244481)
        {
            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.dw = 0;
            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartZero     = MinEIP;
            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->EntryPoint    = *Parametr[0];
            return Yes;
        }

        if (Ins == ID_MOV && *(PBYTE)(OpCode) == 0x8b)
        {
            if (*(PBYTE)(OpCode+1) == 0x1d)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.dwPart = 0x15ff;
                *(PDWORD)(((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.b+2) = *(PDWORD)(OpCode+2);
                This->State = Virut_Z_ADD_EntryPoint;
                This->InstructionCounter = 0;
            }
            else if (*(PBYTE)(OpCode+1) == 0x5c)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.dw = 0;
                This->State = Virut_Z_ADD_EntryPoint;
                This->InstructionCounter = 0;
            }
        }
        break;
    case Virut_Z_ADD_EntryPoint:
        if (Ins == ID_ADD && *(PDWORD)(OpCode) == 0x20244481 ||
            Ins == ID_XOR && *(PDWORD)(OpCode) == 0x20247481)
        {
            if (Ins == ID_XOR && This->VirusNo != Win32_Virut_AE)
            {
                return Like;
            }

            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->EntryPoint = *Parametr[0];
            This->InstructionCounter = 0;
            This->State = Virut_Z_CMP_M;
        }
        break;
    case Virut_Z_CMP_M:
        if (Ins == ID_CMP && (*(PBYTE)(Parametr[1]) == 'M' || *(PBYTE)(Parametr[1]) == 'Z'))
        {
            This->State = Virut_Z_JNZ;
        }
        break;
    case Virut_Z_JNZ:
        if (Ins == ID_JNZ)
        {
            This->InstructionCounter = 0;
            This->State = Virut_Z_CMP_Z;
        }
        break;
    case Virut_Z_CMP_Z:
        if (Ins == ID_CMP && (*(PBYTE)(Parametr[1]) == 'M' || *(PBYTE)(Parametr[1]) == 'Z'))
        {
            This->State = Virut_Z_JZ1;
        }
        break;
    case Virut_Z_JZ1:
        if (Ins == ID_JZ)
        {
            JMP();
            This->State = Virut_Z_CALL1;
            This->InstructionCounter = 0;
        }
        break;
    case Virut_Z_CALL1:
        if (Ins == ID_CALL)
        {
            SaveEIP = EIP;
            X86Emul_RetWithNumber(4);
            This->State = Virut_Z_CALL2;
            This->InstructionCounter = 0;
        }
        break;
    case Virut_Z_CALL2:
        if (Ins == ID_CALL && SaveEIP == EIP)
        {
            X86Emul_RetWithNumber(4);
            This->State = Virut_Z_CALL3;
            This->InstructionCounter = 0;
        }
        break;
    case Virut_Z_CALL3:
        if (Ins == ID_CALL)
        {
            X86Emul_RetWithNumber(0);
            This->State = Virut_Z_TEST;
            This->InstructionCounter = 0;
        }
        break;
    case Virut_Z_TEST:
        if (Ins == ID_TEST && *(PWORD)(OpCode) == 0xC085)
        {
            This->State = Virut_Z_JZ2;
            This->InstructionCounter = 0;
        }
        break;
    case Virut_Z_JZ2:
        if (Ins == ID_JZ)
        {
            JMP();
            This->State = Virut_Z_MOV1;
            This->InstructionCounter = 0;
        }
        break;
    case Virut_Z_MOV1:
        if (Ins == ID_RET)
        {
            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartZero = MinEIP;
            return Yes;
        }
        if (Ins == ID_MOV)
        {
            if (*(PBYTE)OpCode == 0xC6)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s1.chPart = *(PBYTE)Parametr[1];
                This->State = Virut_Z_MOV2;
                This->InstructionCounter = 0;
            }
            else
                if (*(PBYTE)OpCode == 0xC7)
                {
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.dwPart = *Parametr[1];
                    This->State = Virut_Z_MOV2;
                    This->InstructionCounter = 0;
                }
        }
        break;
    case Virut_Z_MOV2:
        if (Ins == ID_MOV)
        {
            if (*(PBYTE)OpCode == 0xC6)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.chPart = *(PBYTE)Parametr[1];
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartZero = MinEIP;
                return Yes;
            }
            else
                if (*(PBYTE)OpCode == 0xC7)
                {
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s1.dwPart = *Parametr[1];
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartZero = MinEIP;
                    return Yes;
                }
        }
        break;
    }

    // dont increment InstructionCounter for NULL instructions
    if (!  (Ins == ID_CLC || Ins == ID_STC ||
        Ins == ID_CLD || Ins == ID_CMC ||
        Ins == ID_NOP || Ins == ID_WAIT ||
        Ins == ID_CWD || Ins == ID_CBW ||
        (Ins == ID_XCHG && Parametr[0] == Parametr[1]) ||
        (Ins == ID_MOV  && Parametr[0] == Parametr[1]))
       )
    {
        (This->InstructionCounter)++;
    }

    if (This->State >= Virut_Z_CALL2)
    {
        return (This->InstructionCounter < 25) ? LikeAndPrivateContinue : Like;
    }

    if (This->InstructionCounter < 25)
        return Continue;

    if (This->State >= Virut_Z_JMP4)
        return Like;

    return No;
}

//--------------------------------------------------------------------------------------
ScanResult DetectVirut_Z2(WORD Ins, PBYTE OpCode, HeuristicCallBack* This)
{
    static DWORD MinEIP;
    static DWORD SaveEIP;

    // to find minimum range of jumped location.
    // later, we should put this function outside of our state machines to calculate
    // min or max range of jumped location for all virus
    if (Ins == ID_JMP)
    {
        MinEIP = MIN(MinEIP, EIP);
    }

    switch (This->State)
    {
    case Virut_Z2_START:

        MinEIP = EIP;

        if (Ins == ID_CALL && *(PDWORD)(OpCode+1) < 0xff)
        {
            This->State = Virut_Z2_JMP1;
        }
        break;
    case Virut_Z2_JMP1:
        if (Ins == ID_JMP && (*OpCode == 0xE9 || *OpCode == 0xEB))
        {
            This->InstructionCounter = 0;
            This->State = Virut_Z2_PUSHA;
        }
        break;
    case Virut_Z2_PUSHA:
        if (Ins == ID_PUSHA)
        {
            This->State = Virut_Z2_ADD_MOV_EBX;
        }
        break;
    case Virut_Z2_ADD_MOV_EBX:
        if (Ins == ID_MOV && *(PBYTE)(OpCode) == 0x8b)
        {
            if (This->FullDetectArgument == NULL)
            {
                (This->FullDetectArgument) = new StructVirut_Z_AB_AC;
                if (This->FullDetectArgument == NULL) 
                    return No;
                memset(This->FullDetectArgument, 0, sizeof(StructVirut_Z_AB_AC));
            }
            if (*(PBYTE)(OpCode+1) == 0x1d)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.dwPart = 0x15ff;
                *(PDWORD)(((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.b+2) = *(PDWORD)(OpCode+2);
                This->State = Virut_Z2_ADD_EntryPoint;
                This->InstructionCounter = 0;
            }
            else if (*(PBYTE)(OpCode+1) == 0x5c)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.dw = 0;
                This->State = Virut_Z2_ADD_EntryPoint;
                This->InstructionCounter = 0;
            }
        }
        break;
    case Virut_Z2_ADD_EntryPoint:
        if (Ins == ID_ADD && *(PDWORD)(OpCode) == 0x20244481 ||
            Ins == ID_XOR && *(PDWORD)(OpCode) == 0x20247481)
        {
            if (Ins == ID_XOR)
            {
                This->VirusNo = Win32_Virut_AE;
            }

            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->EntryPoint = *Parametr[0];
            This->InstructionCounter = 0;
            This->State = Virut_Z2_CMP_M;
        }
        break;
    case Virut_Z2_CMP_M:
        if (Ins == ID_CMP && (*(PBYTE)(Parametr[1]) == 'M' || *(PBYTE)(Parametr[1]) == 'Z'))
        {
            This->State = Virut_Z2_JNZ;
        }
        break;
    case Virut_Z2_JNZ:
        if (Ins == ID_JNZ)
        {
            This->InstructionCounter = 0;
            This->State = Virut_Z2_CMP_Z;
        }
        break;
    case Virut_Z2_CMP_Z:
        if (Ins == ID_CMP && (*(PBYTE)(Parametr[1]) == 'M' || *(PBYTE)(Parametr[1]) == 'Z'))
        {
            This->State = Virut_Z2_JZ1;
        }
        break;
    case Virut_Z2_JZ1:
        if (Ins == ID_JZ)
        {
            JMP();
            This->State = Virut_Z2_CALL1;
            This->InstructionCounter = 0;
        }
        break;
    case Virut_Z2_CALL1:
        if (Ins == ID_CALL)
        {
            SaveEIP = EIP;
            X86Emul_RetWithNumber(4);
            This->State = Virut_Z2_CALL2;
            This->InstructionCounter = 0;
        }
        break;
    case Virut_Z2_CALL2:
        if (Ins == ID_CALL && SaveEIP == EIP)
        {
            X86Emul_RetWithNumber(4);
            This->State = Virut_Z2_CALL3;
            This->InstructionCounter = 0;
        }
        break;
    case Virut_Z2_CALL3:
        if (Ins == ID_CALL)
        {
            X86Emul_RetWithNumber(0);
            This->State = Virut_Z2_TEST;
            This->InstructionCounter = 0;
        }
        break;
    case Virut_Z2_TEST:
        if (Ins == ID_TEST && *(PWORD)(OpCode) == 0xC085)
        {
            This->State = Virut_Z2_JZ2;
            This->InstructionCounter = 0;
        }
        break;
    case Virut_Z2_JZ2:
        if (Ins == ID_JZ)
        {
            JMP();
            This->State = Virut_Z2_MOV1;
            This->InstructionCounter = 0;
        }
        break;
    case Virut_Z2_MOV1:
        if (Ins == ID_RET)
        {
            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode = MinEIP;
            return Yes;
        }
        if (Ins == ID_MOV)
        {
            if (*(PBYTE)OpCode == 0xC6)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s1.chPart = *(PBYTE)Parametr[1];
                This->State = Virut_Z2_MOV2;
                This->InstructionCounter = 0;
            }
            else
                if (*(PBYTE)OpCode == 0xC7)
                {
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.dwPart = *Parametr[1];
                    This->State = Virut_Z2_MOV2;
                    This->InstructionCounter = 0;
                }
        }
        break;
    case Virut_Z2_MOV2:
        if (Ins == ID_MOV)
        {
            if (*(PBYTE)OpCode == 0xC6)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.chPart = *(PBYTE)Parametr[1];
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode = MinEIP;
                return Yes;
            }
            else
                if (*(PBYTE)OpCode == 0xC7)
                {
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s1.dwPart = *Parametr[1];
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode = MinEIP;
                    return Yes;
                }
        }
        break;
    }

    // dont increment InstructionCounter for NULL instructions
    if (!  (Ins == ID_CLC || Ins == ID_STC ||
        Ins == ID_CLD || Ins == ID_CMC ||
        Ins == ID_NOP || Ins == ID_WAIT ||
        Ins == ID_CWD || Ins == ID_CBW ||
        (Ins == ID_XCHG && Parametr[0] == Parametr[1]) ||
        (Ins == ID_MOV  && Parametr[0] == Parametr[1]))
       )
    {
        (This->InstructionCounter)++;
    }

    if (This->State >= Virut_Z2_CALL2)
    {
        return (This->InstructionCounter < 25) ? LikeAndPrivateContinue : Like;
    }

    if (This->InstructionCounter < 25)
        return Continue;

    return No;
}

//--------------------------------------------------------------------------------------
ScanResult DetectVirut_AC(WORD Ins, PBYTE OpCode, HeuristicCallBack* This)
{
    static DWORD MinEIP;
    static DWORD SaveEIP;

    switch (This->State)
    {
    case VirutAC_START:
        MinEIP = EIP;
        This->State = VirutAC_START2;
        //break; we dont use break, because we want to go to
        //       next state immediately
    case VirutAC_START2:
        if (Ins == ID_CALL && *(PDWORD)(OpCode+1) < 0xff)
        {
            This->State = VirutAC_PUSHA;
        }
        break;
    case VirutAC_PUSHA:
        if (Ins == ID_PUSHA)
        {
            This->State = VirutAC_MOV_EBP;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAC_MOV_EBP:
        if (Ins == ID_MOV && *(PBYTE)(OpCode) == 0xBD)
        {
            if (This->FullDetectArgument == NULL)
            {
                (This->FullDetectArgument) = new StructVirut_Z_AB_AC;
                if (This->FullDetectArgument == NULL)
                    return No;
                memset(This->FullDetectArgument, 0, sizeof(StructVirut_Z_AB_AC));
            }
            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->EntryPoint = *Parametr[1];
            This->State = VirutAC_XCHG;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAC_XCHG:
        if (Ins == ID_XCHG && *(PWORD)(OpCode+1) == 0x1c6b)
        {
            This->State = VirutAC_MOV_EBX;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAC_MOV_EBX:
        if (Ins == ID_MOV && *(PBYTE)(OpCode) == 0x8b)
        {
            if (*(PBYTE)(OpCode+1) == 0x1d)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.dwPart = 0x15ff;
                *(PDWORD)(((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.b+2) = *(PDWORD)(OpCode+2);
                This->State = VirutAC_MOV_EAX;
                This->InstructionCounter = 0;
            }
            else if (*(PBYTE)(OpCode+1) == 0x5c)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.dw = 0;
                This->State = VirutAC_MOV_EAX;
                This->InstructionCounter = 0;
            }
        }
        break;
    case VirutAC_MOV_EAX:
        if (Ins == ID_MOV && *(PWORD)(OpCode) == 0x038b)
        {
            This->State = VirutAC_XOR_Z;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAC_XOR_Z:
        if (Ins == ID_XOR && *(PBYTE)(Parametr[1]) == 0x5A)
        {
            This->State = VirutAC_JNZ;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAC_JNZ:
        if (Ins == ID_JNZ)
        {
            This->State = VirutAC_XOR_M;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAC_XOR_M:
        if (Ins == ID_XOR && *(PBYTE)(Parametr[1]) == 0x4D)
        {
            This->State = VirutAC_JZ1;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAC_JZ1:
        if (Ins == ID_JZ)
        {
            JMP();
            This->State = VirutAC_CALL1;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAC_CALL1:
        if (Ins == ID_CALL)
        {
            SaveEIP = EIP;
            X86Emul_RetWithNumber(4);
            This->State = VirutAC_CALL2;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAC_CALL2:
        if (Ins == ID_CALL && SaveEIP == EIP)
        {
            X86Emul_RetWithNumber(4);
            This->State = VirutAC_CALL3;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAC_CALL3:
        if (Ins == ID_CALL)
        {
            X86Emul_RetWithNumber(0);
            This->State = VirutAC_TEST;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAC_TEST:
        if (Ins == ID_TEST && *(PWORD)(OpCode) == 0xC085)
        {
            This->State = VirutAC_JZ2;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAC_JZ2:
        if (Ins == ID_JZ)
        {
            JMP();
            This->State = VirutAC_MOV1;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAC_MOV1:
        if (Ins == ID_RET)
        {
            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode = MinEIP;
            return Yes;
        }
        if (Ins == ID_MOV)
        {
            if (*(PBYTE)OpCode == 0xC6)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s1.chPart = *(PBYTE)Parametr[1];
                This->State = VirutAC_MOV2;
                This->InstructionCounter = 0;
            }
            else
                if (*(PBYTE)OpCode == 0xC7)
                {
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.dwPart = *Parametr[1];
                    This->State = VirutAC_MOV2;
                    This->InstructionCounter = 0;
                }
        }
        break;
    case VirutAC_MOV2:
        if (Ins == ID_MOV)
        {
            if (*(PBYTE)OpCode == 0xC6)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.chPart = *(PBYTE)Parametr[1];
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode = MinEIP;
                return Yes;
            }
            else
                if (*(PBYTE)OpCode == 0xC7)
                {
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s1.dwPart = *Parametr[1];
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode = MinEIP;
                    return Yes;
                }
        }
        break;
    }

    if (Ins == ID_JMP)
        MinEIP = MIN(EIP, MinEIP);

    // dont increment InstructionCounter for NULL instructions
    if (!(Ins == ID_CLC || Ins == ID_STC ||
           Ins == ID_CLD || Ins == ID_CMC ||
           Ins == ID_NOP || Ins == ID_WAIT ||
           Ins == ID_CWD || Ins == ID_CBW ||
          (Ins == ID_XCHG && Parametr[0] == Parametr[1]) ||
          (Ins == ID_MOV  && Parametr[0] == Parametr[1]))
       )
    {
        (This->InstructionCounter)++;
    }

    if (This->State >= VirutAC_CALL2)
    {
        return (This->InstructionCounter < 25) ? LikeAndPrivateContinue : Like;
    }

    if (This->InstructionCounter < 25)
        return Continue;

    return No;
}

//--------------------------------------------------------------------------------------
ScanResult DetectVirut_AF(WORD Ins, PBYTE OpCode, HeuristicCallBack* This)
{
    static DWORD MinEIP;
    static DWORD SaveEIP;

    // to find minimum range of jumped location.
    // later, we should put this function outside of our state machines to calculate
    // min or max range of jumped location for all virus
    if (Ins == ID_JMP)
        MinEIP = MIN(EIP, MinEIP);

    switch (This->State)
    {
    case VirutAF_START:
        MinEIP = EIP;
        This->State = VirutAF_START2;
        //break; we dont use break, because we want to go to
        //       next state immediately
    case VirutAF_START2:
        if (Ins == ID_CALL && *(PDWORD)(OpCode+1) < 0xff)
        {
            This->State = VirutAF_PUSHA;
        }
        break;
    case VirutAF_PUSHA:
        if (Ins == ID_PUSHA)
        {
            This->State = VirutAF_MOV_EBX;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAF_MOV_EBX:
        if (Ins == ID_MOV && *(PBYTE)(OpCode) == 0x8b)
        {
            if (This->FullDetectArgument == NULL)
            {
                (This->FullDetectArgument) = new StructVirut_Z_AB_AC;
                if (This->FullDetectArgument == NULL) 
                    return No;
                memset(This->FullDetectArgument, 0, sizeof(StructVirut_Z_AB_AC));
            }
            if (*(PBYTE)(OpCode+1) == 0x1d)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.dwPart = 0x15ff;
                *(PDWORD)(((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.b+2) = *(PDWORD)(OpCode+2);
                This->State = VirutAF_PUSH_EntryPoint;
                This->InstructionCounter = 0;
            }
            else if (*(PBYTE)(OpCode+1) == 0x5c)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.dw = 0;
                This->State = VirutAF_PUSH_EntryPoint;
                This->InstructionCounter = 0;
            }
        }
        break;
    case VirutAF_PUSH_EntryPoint:
        if (Ins == ID_PUSH && *OpCode == 0x68)
        {
            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->EntryPoint = *Parametr[0];
            This->State = VirutAF_POP_EntryPoint;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAF_POP_EntryPoint:
        if (Ins == ID_POP && *(PDWORD)(OpCode) == 0x2024448F)
        {
            This->State = VirutAF_SUB_Z;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAF_SUB_Z:
        if (Ins == ID_SUB && *(PBYTE)(Parametr[1]) == 'Z')
        {
            This->State = VirutAF_JNZ;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAF_JNZ:
        if (Ins == ID_JNZ)
        {
            This->State = VirutAF_SUB_M;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAF_SUB_M:
        if (Ins == ID_SUB && *(PBYTE)(Parametr[1]) == 'M')
        {
            This->State = VirutAF_JZ1;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAF_JZ1:
        if (Ins == ID_JZ)
        {
            JMP();
            This->State = VirutAF_CALL1;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAF_CALL1:
        if (Ins == ID_CALL)
        {
            MinEIP = MIN(EIP, MinEIP);
            SaveEIP = EIP;
            X86Emul_RetWithNumber(4);
            This->State = VirutAF_CALL2;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAF_CALL2:
        if (Ins == ID_CALL && SaveEIP == EIP)
        {
            MinEIP = MIN(EIP, MinEIP);
            X86Emul_RetWithNumber(4);
            This->State = VirutAF_CALL3;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAF_CALL3:
        if (Ins == ID_CALL)
        {
            MinEIP = MIN(EIP, MinEIP);
            X86Emul_RetWithNumber(0);
            This->State = VirutAF_TEST;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAF_TEST:
        if (Ins == ID_TEST && *(PWORD)(OpCode) == 0xC085)
        {
            This->State = VirutAF_JZ2;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAF_JZ2:
        if (Ins == ID_JZ)
        {
            JMP();
            This->State = VirutAF_MOV1;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAF_MOV1:
        if (Ins == ID_RET)
        {
            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode = MinEIP;
            return Yes;
        }
        if (Ins == ID_MOV)
        {
            if (*(PBYTE)OpCode == 0xC6)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s1.chPart = *(PBYTE)Parametr[1];
                This->State = VirutAF_MOV2;
                This->InstructionCounter = 0;
            }
            else
                if (*(PBYTE)OpCode == 0xC7)
                {
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.dwPart = *Parametr[1];
                    This->State = VirutAF_MOV2;
                    This->InstructionCounter = 0;
                }
        }
        break;
    case VirutAF_MOV2:
        if (Ins == ID_MOV)
        {
            if (*(PBYTE)OpCode == 0xC6)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.chPart = *(PBYTE)Parametr[1];
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode = MinEIP;
                return Yes;
            }
            else
                if (*(PBYTE)OpCode == 0xC7)
                {
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s1.dwPart = *Parametr[1];
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode = MinEIP;
                    return Yes;
                }
        }
        break;
    }

    // dont increment InstructionCounter for NULL instructions
    if (!  (Ins == ID_CLC || Ins == ID_STC ||
        Ins == ID_CLD || Ins == ID_CMC ||
        Ins == ID_NOP || Ins == ID_WAIT ||
        Ins == ID_CWD || Ins == ID_CBW ||
        (Ins == ID_XCHG && Parametr[0] == Parametr[1]) ||
        (Ins == ID_MOV  && Parametr[0] == Parametr[1]))
       )
    {
        (This->InstructionCounter)++;
    }

    if (This->State >= VirutAF_CALL2)
    {
        return (This->InstructionCounter < 25) ? LikeAndPrivateContinue : Like;
    }

    if (This->InstructionCounter < 25)
        return Continue;

    return No;
}

//--------------------------------------------------------------------------------------
ScanResult DetectVirut_AI(WORD Ins, PBYTE OpCode, HeuristicCallBack* This)
{
    static DWORD MinEIP;

    switch (This->State)
    {
    case VirutAI_START:
        MinEIP = EIP;
        This->State = VirutAI_START2;
        //break; we dont use break, because we want to go to
        //       next state immediately
    case VirutAI_START2:
        if (Ins == ID_CALL && *(PDWORD)(OpCode+1) < 0xff)
        {
            This->InstructionCounter = 0;
            This->State = VirutAI_PUSHA;
        }
        break;
    case VirutAI_PUSHA:
        if (Ins == ID_PUSHA)
        {
            This->State = VirutAI_LEA_EBX;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAI_LEA_EBX:
        if (Ins == ID_LEA && *(PDWORD)(OpCode) == 0x0D245C8D)
        {
            This->InstructionCounter = 0;
            This->State = VirutAI_SUB_EBP;
        }
        break;
    case VirutAI_SUB_EBP:
        if (Ins == ID_SUB && *(PWORD)(OpCode) == 0xED81)
        {
            if (This->FullDetectArgument == NULL)
            {
                (This->FullDetectArgument) = new StructVirut_Z_AB_AC;
                if (This->FullDetectArgument == NULL) 
                    return No;
                memset(This->FullDetectArgument, 0, sizeof(StructVirut_Z_AB_AC));
            }
            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->EntryPoint = *Parametr[0];
            This->InstructionCounter = 0;
            This->State = VirutAI_PUSH2;
        }
        break;
    case VirutAI_PUSH2:
        if (Ins == ID_PUSH && *(PBYTE)OpCode == 0xFF)
        {
            if (*(PBYTE)(OpCode+1) == 0x35)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.dwPart = 0x15ff;
                *(PDWORD)(((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.b+2) = *(PDWORD)(OpCode+2);
                This->InstructionCounter = 0;
                This->State = VirutAI_SUB_Z;
            }
            else if (*(PWORD)(OpCode+1) == 0x1773)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.dw = 0;
                This->InstructionCounter = 0;
                This->State = VirutAI_SUB_Z;
            }
        }
        break;
    case VirutAI_SUB_Z:
        if (Ins == ID_SUB && *(PBYTE)(Parametr[1]) == 'Z')
        {
            This->State = VirutAI_JNZ;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAI_JNZ:
        if (Ins == ID_JNZ)
        {
            This->State = VirutAI_SUB_K;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAI_SUB_K:
        if (Ins == ID_SUB && *(PBYTE)(Parametr[1]) == 'K')
        {
            This->State = VirutAI_JZ1;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAI_JZ1:
        if (Ins == ID_JZ)
        {
            JMP();
            This->State = VirutAI_CALL1;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAI_CALL1:
        if (Ins == ID_CALL)
        {
            MinEIP = MIN(EIP, MinEIP);
            X86Emul_RetWithNumber(4);
            This->State = VirutAI_CALL2;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAI_CALL2:
        if (Ins == ID_CALL)
        {
            MinEIP = MIN(EIP, MinEIP);
            X86Emul_RetWithNumber(0);
            This->State = VirutAI_OR;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAI_OR:
        if (Ins == ID_OR && *(PWORD)(OpCode) == 0xC00B)
        {
            This->State = VirutAI_JZ2;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAI_JZ2:
        if (Ins == ID_JZ)
        {
            This->State = VirutAI_MOV1;
            This->InstructionCounter = 0;
        }
        break;
    case VirutAI_MOV1:
        if (Ins == ID_RET)
        {
            ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode = MinEIP;
            return Yes;
        }
        if (Ins == ID_MOV)
        {
            if (*(PBYTE)OpCode == 0xC6)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s1.chPart = *(PBYTE)Parametr[1];
                This->State = VirutAI_MOV2;
                This->InstructionCounter = 0;
            }
            else
                if (*(PBYTE)OpCode == 0xC7)
                {
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.dwPart = *Parametr[1];
                    This->State = VirutAI_MOV2;
                    This->InstructionCounter = 0;
                }
        }
        break;
    case VirutAI_MOV2:
        if (Ins == ID_MOV)
        {
            if (*(PBYTE)OpCode == 0xC6)
            {
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s2.chPart = *(PBYTE)Parametr[1];
                ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode = MinEIP;
                return Yes;
            }
            else
                if (*(PBYTE)OpCode == 0xC7)
                {
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->MainAPIRVA.s1.dwPart = *Parametr[1];
                    ((PStructVirut_Z_AB_AC)(This->FullDetectArgument))->StartDeCode = MinEIP;
                    return Yes;
                }
        }
        break;
    }

    if (Ins == ID_JMP)
        MinEIP = MIN(EIP, MinEIP);

    // dont increment InstructionCounter for NULL instructions
    if (!  (Ins == ID_CLC || Ins == ID_STC ||
        Ins == ID_CLD || Ins == ID_CMC ||
        Ins == ID_NOP || Ins == ID_WAIT ||
        Ins == ID_CWD || Ins == ID_CBW ||
        (Ins == ID_XCHG && Parametr[0] == Parametr[1]) ||
        (Ins == ID_MOV  && Parametr[0] == Parametr[1]))
       )
    {
        (This->InstructionCounter)++;
    }

    if (This->State >= VirutAI_CALL2)
    {
        return (This->InstructionCounter < 30) ? LikeAndPrivateContinue : Like;
    }

    if (This->InstructionCounter < 30)
        return Continue;

    return No;
}

//--------------------------------------------------------------------------------------