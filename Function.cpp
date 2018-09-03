#include "Function.h"

#include <string.h>
#include <windows.h>
#include <stdlib.h>
#include "DisasmbleTable.h"
#include "Data.h"
//------------------------------------------------------------------------------

#define Bit(A, i) ((A>>i)&1)

//------------------------------------------------------------------------------
extern WORD GrpPrefix[4];
BYTE  Stack[STACK_SIZE] = {0, 0, 0, 0};
PBYTE TopStack;

BYTE  FS_Segment[FS_SEGMENT_SIZE];

__Flag Flag;

void SetInit (void)
{
    TopStack = END_OF_STACK;

    Const = 0; // as "RET" value to return to OS; set at the start of program
    Parametr[0] = &Const;
    PUSH();
}

////////////////////////////////////***///////////////////////////////////////
//////////////////////////////////Arithmetic//////////////////////////////////
////////////////////////////////////***///////////////////////////////////////

////////////////////////////////////ADD///////////////////////////////////////
void ADD (void)
{
    SIGNED_DWORD temp = resp;
    if (w == 0)
        *(PBYTE)(Parametr[d]) += *(PBYTE)(Parametr[!d]);
    else
        (*Parametr[d]) += (*Parametr[!d]);
    temp -= resp;
    TopStack -= temp;
}

////////////////////////////////////ADC///////////////////////////////////////
void ADC (void)
{
    SIGNED_DWORD temp = resp;
    if (w == 0)
        *(PBYTE)Parametr[d] += *(PBYTE)(Parametr[!d]+Flag.C);
    else
        *Parametr[d] += (*Parametr[!d]+Flag.C);
    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void SBB (void)
{
    SIGNED_DWORD temp = resp;
    if (w == 0)
        *(PBYTE)Parametr[d] -= *(PBYTE)Parametr[!d];
    else
        *Parametr[d] -= *Parametr[!d];
    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void SUB (void)
{
    SIGNED_DWORD temp = resp;
    if (w == 0)
        *(PBYTE)Parametr[d] -= *(PBYTE)Parametr[!d];
    else
        *Parametr[d] -= *Parametr[!d];
    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void CMP (void)
{
    DWORD a;
    long  s;
    if (w == 0)
    {
        a = *(PBYTE)Parametr[d] - *(PBYTE)Parametr[!d];
        s = (signed char)Parametr[!d];
    }
    else
    {
        a = *Parametr[d] - *Parametr[!d];
        s = (signed long)Parametr[!d];
    }
    Flag.Z = (a == 0);
    Flag.C = (a > 0);
    Flag.S = (s > 0);
}
//------------------------------------------------------------------------------
void DEC (void)
{
    SIGNED_DWORD temp = resp;
    d = 0;
    if (w == 0)
        (*(PBYTE)Parametr[d])--;
    else
        (*Parametr[d])--;

    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void INC (void)
{
    SIGNED_DWORD temp = resp;
    d = 0;
    if (w == 0)
        (*(PBYTE)Parametr[d])++;
    else
        (*Parametr[d])++;
    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void IIMUL (void)
{
}
//------------------------------------------------------------------------------
void NEG (void)
{
    SIGNED_DWORD temp = resp;
    d = 0;
    if (w == 0)
        *(PBYTE)Parametr[d] *= -1;
    else
        (*Parametr[d]) *= -1;
    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void MUL (void)
{
    SIGNED_DWORD temp = resp;
    d = 0;
    if (w == 0)
        r_ah *= *(PBYTE)Parametr[d];
    else
        reax *= *Parametr[d];
    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void IMUL (void)
{
    SIGNED_DWORD temp = resp;
    d = 0;
    if (w == 0)
        r_ah *= *(SIGNED_BYTE *)Parametr[d];
    else
        reax *= *(SIGNED_DWORD *)Parametr[d];
    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void IMUL2 (void)
{
    SIGNED_DWORD temp = resp;
    if (w == 0)
        *(PBYTE)(Parametr[d]) *= *(PBYTE)(Parametr[!d]);
    else
        (*Parametr[d]) *= (*Parametr[!d]);
    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void DIV (void)
{
    SIGNED_DWORD temp = resp;
    d = 0;

    if (w == 0)
    {
        if (*(PBYTE)Parametr[d])
            r_ah /= *(PBYTE)Parametr[d];
    }
    else
    {
        if (*Parametr[d])
            reax /= *Parametr[d];
    }

    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void IDIV (void)
{
    SIGNED_DWORD temp = resp;
    d = 0;

    if (w == 0)
    {
        if (*(PBYTE)Parametr[d])
            r_ah /= *(SIGNED_BYTE*)(Parametr[d]);
    }
    else
    {
        if (*Parametr[d])
            reax /= *(SIGNED_DWORD*)(Parametr[d]);
    }

    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void CBW (void)
{
    *(&r_ax+1) = 0;
}
//------------------------------------------------------------------------------
void CWD (void)
{
    redx = 0;
}
//------------------------------------------------------------------------------
void AAM (void)
{
    if (*(PBYTE)BufferGet(EIP) == 0x0A)
        EIP++;
}
//------------------------------------------------------------------------------
void AAD (void)
{
    if (*(PBYTE)BufferGet(EIP) == 0x0A)
        EIP++;
}
//------------------------------------------------------------------------------
void DAA (void)
{
}
//------------------------------------------------------------------------------
void DAS (void)
{
}
//------------------------------------------------------------------------------
void AAA (void)
{
}
//------------------------------------------------------------------------------
void AAS (void)
{
}

////////////////////////////////////***///////////////////////////////////////
////////////////////////////////Data Transfer/////////////////////////////////
////////////////////////////////////***///////////////////////////////////////
//------------------------------------------------------------------------------
void MOV (void)
{
    SIGNED_DWORD temp = resp;

    if (w == 0)
        *(PBYTE)(Parametr[d]) = *(PBYTE)(Parametr[!d]);
    else
        (*Parametr[d]) = (*Parametr[!d]);

    temp -= resp;
    TopStack -= temp;
}
void MOV_(void)
{
}
//------------------------------------------------------------------------------
void XCHG (void)
{
    SIGNED_DWORD temp = resp;
    DWORD a;

    if (w == 0)
    {
        a = *(PBYTE)(Parametr[d]);
        *(PBYTE)(Parametr[d]) = *(PBYTE)(Parametr[!d]);
        *(PBYTE)(Parametr[!d]) = (BYTE)a;
    }
    else
    {
        a = *Parametr[d];
        *Parametr[d] = *Parametr[!d];
        *Parametr[!d] = a;
    }

    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void LEA (void)
{
    SIGNED_DWORD temp = resp;
    *Parametr[d] = Const;
    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void LES (void)
{

}
//------------------------------------------------------------------------------
void LDS (void)
{

}
//------------------------------------------------------------------------------
void PUSH (void)
{
    SIGNED_DWORD temp = resp;
    if (TopStack < Stack+4 || TopStack > END_OF_STACK)
    {
        BufferEnd();
        return;
    }

    d = 0;
    TopStack -= 4;
    *(PDWORD)TopStack = *Parametr[d];

    TopStack += resp - temp;
}
//------------------------------------------------------------------------------
void POP (void)
{
    if (TopStack < Stack || TopStack > (END_OF_STACK-4))
    {
        BufferEnd();
        return;
    }

    d = 0;
    *Parametr[d] = *(PDWORD)TopStack;
    TopStack += 4;
    resp += 4;
}

//------------------------------------------------------------------------------
void PUSHA (void)
{
    int i;
    d = 0;

    for (i = 0; i < 8 && (!BufferIsEnd()); i++)
    {
        Parametr[d] = (PDWORD)&Reg[i];
        PUSH();
    }
}
//------------------------------------------------------------------------------
void POPA (void)
{
    int i;
    d = 0;

    for (i = 7; i >= 0 && (! BufferIsEnd()); i--)
    {
        Parametr[d] = (PDWORD)&Reg[i];
        POP();
    }
}
//------------------------------------------------------------------------------
void PUSHF (void)
{
    d = 0;
    Parametr[d] = (PDWORD) &Flag;
    PUSH();
}
void POPF (void)
{
    d = 0;
    Parametr[d] = (PDWORD) &Flag;
    POP();
}
void SAHF (void)
{//    AH := SF ZF xx AF xx PF xx CF
    Flag.C = r_ah & 1;
    Flag.P= (r_ah>>2) &1;
    Flag.A= (r_ah>>4) &1;
    Flag.Z= (r_ah>>6) &1;
    Flag.S= (r_ah>>7) &1;
}
//------------------------------------------------------------------------------
void LAHF (void)
{//    AH := SF ZF xx AF xx PF xx CF
    r_ah =(BYTE)(Flag.C + (Flag.P << 2) + (Flag.A << 4) + (Flag.Z << 6) + (Flag.S << 7));
}
//------------------------------------------------------------------------------
void _IN (void)
{

}
//------------------------------------------------------------------------------
void INSB (void)
{
}
//------------------------------------------------------------------------------
void INSW (void)
{
}
//------------------------------------------------------------------------------
void _OUT (void)
{
}
//------------------------------------------------------------------------------
void OUTSB (void)
{
}
//------------------------------------------------------------------------------
void OUTSW (void)
{
}
//------------------------------------------------------------------------------
void XLAT (void)
{
}

////////////////////////////////////***///////////////////////////////////////
//////////////////////////////// Logic ////////////////////////////////////
////////////////////////////////////***///////////////////////////////////////

//------------------------------------------------------------------------------
void TEST (void)
{
    SIGNED_DWORD a;
    if (w == 0)
        a = (*(PBYTE)Parametr[d]) & (*(PBYTE)Parametr[!d]);
    else
        a = (*Parametr[d]) & (*Parametr[!d]);
    if (a == 0)
        Flag.Z = 1;
    else
        Flag.Z = 0;
}
//------------------------------------------------------------------------------
void AND (void)
{
    SIGNED_DWORD temp = resp;
    if (w == 0)
        *(PBYTE)Parametr[d] &= *(PBYTE)Parametr[!d];
    else
        *Parametr[d] &= *Parametr[!d];
    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void XOR (void)
{
    SIGNED_DWORD temp = resp;
    if (w == 0)
        *(PBYTE)Parametr[d] ^= *(PBYTE)Parametr[!d];
    else
        *Parametr[d] ^= *Parametr[!d];
    temp -= resp;
    TopStack -= temp;
}
////////////////////////////////////OR///////////////////////////////////////
void OR (void)
{
    SIGNED_DWORD temp = resp;
    if (w == 0)
        *(PBYTE)Parametr[d] |= *(PBYTE)Parametr[!d];
    else
        *Parametr[d] |= *Parametr[!d];
    temp -= resp;
    TopStack -= temp;
}
///////////////////////////////////////////////////////////////////////////

#if defined(__BORLANDC__)
// Borland C compiler has a bug in the below function.
// beacuse of using ASM & C codes, BCB uses BP register for accessing to local Variables, 
// but does not set BP ath the start of function
// So, I disables all optimizations to overcome this bug
#pragma option push   // push old optimizations
#pragma option -Od    // disabling all optimizations
#endif
void ROL (void)
{
    SIGNED_DWORD temp = resp;
    BYTE ALReg, CLReg;

    if (w == 0)
    {
        CLReg = *(PBYTE)Parametr[!d];
        ALReg = *(PBYTE)Parametr[d];
        __asm mov cl, byte ptr CLReg
        __asm mov al, byte ptr ALReg
        __asm rol al, cl
        __asm mov byte ptr ALReg, al
        *(PBYTE)Parametr[d] = ALReg;
    }
    else
    {
        *Parametr[d] = dwROL(*Parametr[d], *(PBYTE) Parametr[!d]);
    }

    temp -= resp;
    TopStack -= temp;
}
#if defined(__BORLANDC__)
#pragma option pop
//------------------------------------------------------------------------------
// Borland C compiler has a bug in the below function.
// beacuse of using ASM & C codes, BCB uses BP register for accessing to local Variables, 
// but does not set BP ath the start of function
// So, I disables all optimizations to overcome this bug
#pragma option push   // push old optimizations
#pragma option -Od    // disabling all optimizations
#endif
void ROR (void)
{
    SIGNED_DWORD temp = resp;
    BYTE ALReg, CLReg;

    if (w == 0)
    {
        CLReg = *(PBYTE)Parametr[!d];
        ALReg = *(PBYTE)Parametr[d];
        __asm mov cl, byte ptr CLReg
        __asm mov al, byte ptr ALReg
        __asm ror al, cl
        __asm mov byte ptr ALReg, al
        *(PBYTE)Parametr[d] =ALReg;
    }
    else
    {
        *Parametr[d] = dwROR(*Parametr[d], *(PBYTE)Parametr[!d]);
    }

    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void RCL (void)
{
    /*    LableTable.Set (Rcl);
    if (w == 0)
    {
    _CL= (*(PBYTE) Parametr[!d]);
    _AL= (*(PBYTE) Parametr[d]);
    //         asm rcl al, CL
    (*(PBYTE) Parametr[d]) =_AL;
    }
    else
    {
    _CL= (*(PBYTE) Parametr[!d]);
    _AX= (*Parametr[d]);
    //         asm rcl ax, CL
    (*Parametr[d]) =_AX;
    }*/
}
//------------------------------------------------------------------------------
void RCR (void)
{
    /*    LableTable.Set (Rcr);
    if (w == 0)
    {
    _CL= (*(PBYTE) Parametr[!d]);
    _AL= (*(PBYTE) Parametr[d]);
    //         asm rcr al, CL
    (*(PBYTE) Parametr[d]) =_AL;
    }
    else
    {
    _CL= (*(PBYTE) Parametr[!d]);
    _AX= (*Parametr[d]);
    //         asm rcr ax, CL
    (*Parametr[d]) =_AX;
    }*/
}
//------------------------------------------------------------------------------
void SHR (void)
{
    SIGNED_DWORD temp = resp;

    if (w == 0)
    {
        Flag.C = ((*(PBYTE)Parametr[d]) >> (*(PBYTE)Parametr[!d] -1)) &1;
        (*(PBYTE)Parametr[d]) >>= *(PBYTE)Parametr[!d];
    }
    else
    {
        Flag.C= ((*Parametr[d]) >> ((*(PBYTE)Parametr[!d]) -1)) &1;
        *Parametr[d] >>=  *(PBYTE)Parametr[!d];
    }

    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void SHL (void)
{
    SIGNED_DWORD temp = resp;

    if (w == 0)
    {
        Flag.C = ((*(PBYTE)Parametr[d]) << (*(PBYTE)Parametr[!d] -1)) &1;
        (*(PBYTE)Parametr[d]) <<= *(PBYTE)Parametr[!d];
    }
    else
    {
        Flag.C= ((*Parametr[d]) << ((*(PBYTE)Parametr[!d]) -1)) &1;
        *Parametr[d] <<= *(PBYTE)Parametr[!d];
    }

    temp -= resp;
    TopStack -= temp;
}
//------------------------------------------------------------------------------
void SAL (void)
{
    SHL();
}
//------------------------------------------------------------------------------
void SAR (void)
{
    SIGNED_DWORD bit;
    if (w == 0)
        bit= (*Parametr[d]) &0x80;
    else
        bit= (*Parametr[d]) &0x8000;

    SHR();
    (*Parametr[d]) |=bit;

}
//------------------------------------------------------------------------------
void NOT (void)
{
    SIGNED_DWORD temp = resp;
    d = 0;
    if (w == 0)
        (*(PBYTE)Parametr[d]) = ~(*(PBYTE)Parametr[d]);
    else
        (*Parametr[d]) = ~(*Parametr[d]);
    temp -= resp;
    TopStack -= temp;
}

////////////////////////////////////***///////////////////////////////////////
///////////////////////////// Contorol Transfer //////////////////////////////
////////////////////////////////////***///////////////////////////////////////

//------------------------------------------------------------------------------
void JMPT (void)
{
    
    // SIGNED_DWORD t = 1;
    // WORD Temp = *Parametr[0];
    // BufferSeek (*Parametr[0]);
    // for (SIGNED_DWORD i = 0; i < NJmp && t == 1; i++)
    //     t = Anlayz (void);
    // *Parametr[0] = Temp;
    // BufferSeek (*Parametr[0]);
    
}
//------------------------------------------------------------------------------
void JCXZ (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JO (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JNO (void)
{
    JMPT();
}
//--    ----------------------------------------------------------------------------
void JC (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JNC (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JZ (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JNZ (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JBE (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JA (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JS (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JNS (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JPE (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JPO (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JL (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JNL (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JNG (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
void JG (void)
{
    JMPT();
}
//------------------------------------------------------------------------------
extern BOOL Visit;
void JMP (void)
{
    d = 0;
    if (Parametr[d] == NULL || *Parametr[d] == 0)
    {
        BufferEnd();
        return;
    }
    BufferSeek (*Parametr[d]);
}
//------------------------------------------------------------------------------
void CALL (void)
{
    d = 0;
    ////Sality Clean
    if (b[0] == 0xff && b[1] == 0x15)
    {
        TopStack += 4;
        resp += 4;
    }
    else
    {
        PDWORD temp;
        temp = Parametr[d];
        Parametr[d] = &EIP;
        PUSH();
        Parametr[d] = temp;
        JMP();
    }
}
//------------------------------------------------------------------------------
void RET (void)
{
    SIGNED_DWORD  f;

    d = 0;
    f = (Parametr[d] != NULL) ?((SIGNED_DWORD)*Parametr[d]): 0;
    Parametr[d] = &EIP;
    POP();
    JMP();
    resp     += f;
    TopStack += f;
}
//------------------------------------------------------------------------------
void X86Emul_RetWithNumber (SIGNED_DWORD Number)
{
    Const = Number;
    Parametr[0] = &Const;
    RET();
}
//------------------------------------------------------------------------------
void RETF (void)
{
    d = 0;
    Const=EIP;
    Parametr[d]=&EIP;
    POP();
    Parametr[d]=&__CS;
    POP();
    Parametr[d]=&EIP;
    JMP();
}
//------------------------------------------------------------------------------
void IRET (void)
{

}
//------------------------------------------------------------------------------

void _INT (void)
{
}
//------------------------------------------------------------------------------
void BKPT (void)
{
    d = 0;
    Const=3;
    Parametr[d]=&Const;
    _INT();
}
//------------------------------------------------------------------------------
void INTO (void)
{
    d = 0;
    if (Flag.O == 1)
    {
        *Parametr[d]=4;
        _INT();
    }
}
//------------------------------------------------------------------------------
void LOOP (void)
{
    /* Later, we should check the count and the time of loop.
    If the loop is not suitable, we ignore it */

    /*
    recx--;
    if (LableTableSetLable(EIP) == 2)
    {
    JMP();
    }
    */

    recx = 0;
}
//------------------------------------------------------------------------------
void LOOPNZ (void)
{
    if (Flag.Z == 0)
        LOOP();
}
//------------------------------------------------------------------------------
void LOOPZ (void)
{
    if (Flag.Z == 1)
        LOOP();
}
//------------------------------------------------------------------------------
void ENTER (void)
{
    BYTE tmp[3];
    BufferRead(3, (PBYTE)tmp);
}
//------------------------------------------------------------------------------
void LEAVE (void)
{

}
//------------------------------------------------------------------------------
void BOUND (void)
{
}

////////////////////////////////////***///////////////////////////////////////
////////////////////////// String Manipulation ///////////////////////////
////////////////////////////////////***///////////////////////////////////////

//------------------------------------------------------------------------------
void MOVSB (void)
{
    if ((*(PBYTE)BufferGet (EIP - 2)& 0xF7) == 0xF2)
    {
        if (recx >= 256L) recx = 256L; // max of loop is 256
        //    for (; recx > 0L; recx--)
        //        {
        *(PBYTE)BufferGet (redi) = *(PBYTE)BufferGet (resi);
        redi++;
        resi++;
        //      }
        *(PBYTE)BufferGet (EIP - 2) = 0x90;
    }
    else
    {
        *(PBYTE)BufferGet (redi) = *(PBYTE)BufferGet (resi);
        redi++;
        resi++;
    }
}
//------------------------------------------------------------------------------
void MOVSW (void)
{
    if ((*(PBYTE)BufferGet (EIP - 2)& 0xF7) == 0xF2)
    {
        if (recx >= 256L) 
            recx = 256L; // max of loop is 256
        //    for (; recx > 0; recx--)
        //        {
        *(PWORD)BufferGet (redi) = *(PWORD)BufferGet (resi);
        redi+=2;
        resi+=2;
        //        }
        *(PBYTE)BufferGet (EIP - 2) = 0x90;
    }
    else
    {
        *(PWORD)BufferGet (redi) =*(PWORD)BufferGet (resi);
        redi+=2;
        resi+=2;
    }
}
//------------------------------------------------------------------------------
void CMPSB (void)
{
}
//------------------------------------------------------------------------------
void CMPSW (void)
{
}
//------------------------------------------------------------------------------
void SOTSB (void)
{
    //if (rep == 1)
    //    if (recx >= 256L) 
    //        recx = 256L; // max of loop is 256
    //for (;cx>0;cx--)
    //{
    if (BufferGet (redi))
        *(PBYTE)BufferGet (redi) = r_al;
    redi++;
    // *(PBYTE)BufferGet (EIP - 2) = 0x90;
    // }
    // rep=0;
}
//------------------------------------------------------------------------------
void SOTS (void)
{
    //if (rep == 1)
    //    if (recx >= 256L)
    //        recx = 256L; // max of loop is 256
    //for (;cx>0;cx--)
    //{
    if (BufferGet (redi))
        *(PDWORD)BufferGet (redi) = reax;
    redi+=2;
    // *(PBYTE)BufferGet (EIP - 2) = 0x90;
    // }
    // rep=0;
}
//------------------------------------------------------------------------------
void LODSB (void)
{
    //if (rep == 1)
    //    if (recx >= 256L)
    //        recx = 256L; // max of loop is 256
    //for (;cx>0;cx--)
    //{ 
    r_al = *(PBYTE)BufferGet (resi);
    resi++;
    //*(PBYTE)BufferGet (EIP - 2) = 0x90;
    // }
    // rep=0;
    //
}
//------------------------------------------------------------------------------
void LODS (void)
{
    /*    if (rep == 1)
    if (recx >= 256L) 
        recx = 256L; // max of loop is 256
    for (;cx>0;cx--)
    {*/
    reax = *(PWORD)BufferGet (resi);
    resi += 2;
    // *(PBYTE)BufferGet (EIP - 2) = 0x90;
    /*    }
    rep=0; */
}
//------------------------------------------------------------------------------
void SCASB (void)
{

}
//------------------------------------------------------------------------------
void SCAS (void)
{
}
//------------------------------------------------------------------------------
void REPZ (void)
{
    GrpPrefix[0] = ID_REPZ;
    *(PBYTE)BufferGet(EIP-1) = 0xF3;
}
//------------------------------------------------------------------------------
void REPNZ (void)
{
    GrpPrefix[0] = ID_REPNZ;
    *(PBYTE)BufferGet(EIP-1) = 0xF2;
}

////////////////////////////////////***///////////////////////////////////////
/////////////////////////// Processor Contorl ////////////////////////////
////////////////////////////////////***///////////////////////////////////////

//------------------------------------------------------------------------------
void CMC (void)
{
    Flag.C=~Flag.C;
}
//------------------------------------------------------------------------------
void CLS (void)
{
    Flag.S=0;
}
//------------------------------------------------------------------------------
void STS (void)
{
    Flag.S=1;
}
//------------------------------------------------------------------------------
void CLI (void)
{
    Flag.I=0;
}
//------------------------------------------------------------------------------
void STI (void)
{
    Flag.I=1;
}
//------------------------------------------------------------------------------
void CLD (void)
{
    Flag.D=0;
}
//------------------------------------------------------------------------------
void STD (void)
{
    Flag.D=1;
}
//------------------------------------------------------------------------------
void LOCK (void)
{
    GrpPrefix[0] = ID_LOCK;
}
//------------------------------------------------------------------------------
void SMT (void)
{
}
//------------------------------------------------------------------------------
void HLT (void)
{
}
//------------------------------------------------------------------------------
void WAIT (void)
{
}
//------------------------------------------------------------------------------
void ESC (void)
{
}

////////////////////////////////////***///////////////////////////////////////
/////////////////////////// Protection Contorl ////////////////////////////
////////////////////////////////////***///////////////////////////////////////

//------------------------------------------------------------------------------
void LGDT (void)
{
}
//------------------------------------------------------------------------------
void SGDT (void)
{
}
//------------------------------------------------------------------------------
void LIDT (void)
{
}
//------------------------------------------------------------------------------
void SIDT (void)
{
}
//------------------------------------------------------------------------------
void LLDT (void)
{
}
//------------------------------------------------------------------------------
void SLDT (void)
{
}
//------------------------------------------------------------------------------
void LTR (void)
{
}
//------------------------------------------------------------------------------
void STR (void)
{
}
//------------------------------------------------------------------------------
void LMSW (void)
{
}
//------------------------------------------------------------------------------
void SMSW (void)
{
}
//------------------------------------------------------------------------------
void LAR (void)
{
}
//------------------------------------------------------------------------------
void LSL (void)
{
}
//------------------------------------------------------------------------------
void VERR (void)
{
}
//------------------------------------------------------------------------------
void VERW (void)
{
}
//------------------------------------------------------------------------------
void ARPL (void)
{
}

////////////////////////////////////***///////////////////////////////////////
/////////////////////////// Prefix Contorl ///////////////////////////
////////////////////////////////////***///////////////////////////////////////

//------------------------------------------------------------------------------
void ESp (void)
{
    GrpPrefix[1] = ID_ES;
}
//------------------------------------------------------------------------------
void CSp (void)
{
    GrpPrefix[1] = ID_CS;
}
//------------------------------------------------------------------------------
void SSp (void)
{
    GrpPrefix[1] = ID_SS;
}
//------------------------------------------------------------------------------
void DSp (void)
{
    GrpPrefix[1] = ID_DS;
}
//------------------------------------------------------------------------------
void FSp (void)
{
    GrpPrefix[1] = ID_FS;
}
//------------------------------------------------------------------------------
void GSp (void)
{
    GrpPrefix[1] = ID_GS;
}
//------------------------------------------------------------------------------
void OPSIZE (void)
{
    GrpPrefix[2] = ID_OPSIZE;
}
//------------------------------------------------------------------------------
void ADDR (void)
{
    GrpPrefix[3] = ID_ADDR;
}

//------------------------------------------------------------------------------
void NOP (void)
{
}
//------------------------------------------------------------------------------
void SETALC (void)
{
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
void ADDSUB ()
{
}
void ANDN ()
{
}
void BSWAP ()
{
}
void BT ()
{
}
void BTC ()
{
}
void BSF ()
{
}
void BTR ()
{
}
void BSR ()
{
}
void BTS ()
{
}
void CLTS ()
{
}
//------------------------------------------------------------------------------
void CMOVO ()
{
    d = 0;
    if (Flag.O)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVNO ()
{
    d = 0;
    if (!Flag.O)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVC ()
{
    d = 0;
    if (!Flag.C)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVNC ()
{
    d = 0;
    if (!Flag.C)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVZ ()
{
    d = 0;
    if (Flag.Z)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVNZ ()
{
    d = 0;
    if (!Flag.Z)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVBE ()
{
    d = 0;
    if (Flag.C && Flag.Z)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVA ()
{
    d = 0;
    if (!(Flag.C || Flag.Z))
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVS ()
{
    d = 0;
    if (Flag.S)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVNS ()
{
    d = 0;
    if (!Flag.S)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVPE ()
{
    d = 0;
    if (Flag.P)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVPO ()
{
    d = 0;
    if (!Flag.P)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVL ()
{
    d = 0;
    if (Flag.S != Flag.O)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVNL ()
{
    d = 0;
    if (Flag.S == Flag.O)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVNG ()
{
    d = 0;
    if (Flag.Z && Flag.S != Flag.O)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMOVG ()
{
    d = 0;
    if (!Flag.Z && Flag.S == Flag.O)
        *Parametr[d] = *Parametr[!d];
}
//------------------------------------------------------------------------------
void CMPXCH8B ()
{
}
void CMPXCHG ()
{
}
void COMIS ()
{
}
void CPUID ()
{
}
void CVT ()
{
}
void CVTPI2 ()
{
}
void CVTT ()
{
}
void EMMS ()
{
}
void FEMMS ()
{
}
void FXRSTOR ()
{
}
void FXSAVE ()
{
}
void HADDPD ()
{
}
void HSUBPD ()
{
}
void INVD ()
{
}
void INVLPG ()
{
}
void LDDQU ()
{
}
void LDMXCSR ()
{
}
void LFENCE ()
{
}
void LFS ()
{
}
void LGS ()
{
}
void LSS ()
{
}
void MASKMOVQ ()
{
}
void _MAX ()
{
}
void MFENCE ()
{
}
void _MIN ()
{
}
void MMX_UD ()
{
}
void MOVAP ()
{
}
void MOVD ()
{
}
void MOVHPS ()
{
}
void MOVLPS ()
{
}
void MOVMSK ()
{
}
void MOVNTI ()
{
}
void MOVNTP ()
{
}
void MOVNTQ ()
{
}
void MOVSX ()
{
}
void MOVUPS ()
{
}
void MOVZX ()
{
}
void PACKSSDW ()
{
}
void PACKSSWB ()
{
}
void PACKUSWB ()
{
}
void PADDB ()
{
}
void PADDD ()
{
}
void PADDQ ()
{
}
void PADDSB ()
{
}
void PADDSW ()
{
}
void PADDUSB ()
{
}
void PADDUSW ()
{
}
void PADDW ()
{
}
void PADND ()
{
}
void PANDN ()
{
}
void PAVGB ()
{
}
void PCMPEQB ()
{
}
void PCMPEQQ ()
{
}
void PCMPEQW ()
{
}
void PCMPGTB ()
{
}
void PCMPGTD ()
{
}
void PCMPGTW ()
{
}
void PEXTRW ()
{
}
void PINSRW ()
{
}
void PMADDWD ()
{
}
void PMAXSW ()
{
}
void PMAXUB ()
{
}
void PMINSW ()
{
}
void PMINUB ()
{
}
void PMOVMSKB ()
{
}
void PMULHUW ()
{
}
void PMULHW ()
{
}
void PMULLW ()
{
}
void PMULUDQ ()
{
}
void POR ()
{
}
void PREFETCH ()
{
}
void PREFTCH0()
{
}
void PREFTCH1()
{
}
void PREFTCH2()
{
}
void PREFTCHINTA ()
{
}
void PSADBW ()
{
}
void PSHUF ()
{
}
void PSLLD ()
{
}
void PSLLQ ()
{
}
void PSLLW ()
{
}
void PSRAD ()
{
}
void PSRAQ ()
{
}
void PSRAW ()
{
}
void PSRLD ()
{
}
void PSRLQ ()
{
}
void PSRLW ()
{
}
void PSUBB ()
{
}
void PSUBD ()
{
}
void PSUBQ ()
{
}
void PSUBSB ()
{
}
void PSUBSW ()
{
}
void PSUBUSB ()
{
}
void PSUBUSW ()
{
}
void PSUBW ()
{
}
void PUNPCKHBW ()
{
}
void PUNPCKHDQ ()
{
}
void PUNPCKHQDQ ()
{
}
void PUNPCKHWD ()
{
}
void PUNPCKLBW ()
{
}
void PUNPCKLDQ ()
{
}
void PUNPCKLQDQ ()
{
}
void PUNPCKLWD ()
{
}
void PXOR ()
{
}
void RCP ()
{
}
void RDMSR ()
{
}
void RDPMC ()
{
}
void RDTSC ()
{
}
void RSM ()
{
}
void RSQRT ()
{
}
//------------------------------------------------------------------------------
void SETO ()
{
    d = 0;
    *(PBYTE)Parametr[0] = Flag.O;
}
//------------------------------------------------------------------------------
void SETNO ()
{
    d = 0;
    *(PBYTE)Parametr[0] = !Flag.O;
}
//------------------------------------------------------------------------------
void SETC ()
{
    d = 0;
    *(PBYTE)Parametr[0] = Flag.C;
}
//------------------------------------------------------------------------------
void SETNC ()
{
    d = 0;
    *(PBYTE)Parametr[0] = !Flag.C;
}
//------------------------------------------------------------------------------
void SETZ ()
{
    d = 0;
    *(PBYTE)Parametr[0] = Flag.Z;
}
//------------------------------------------------------------------------------
void SETNZ ()
{
    d = 0;
    *(PBYTE)Parametr[0] = !Flag.Z;
}
//------------------------------------------------------------------------------
void SETBE ()
{
    d = 0;
    *(PBYTE)Parametr[0] = Flag.C && Flag.Z;
}
//------------------------------------------------------------------------------
void SETA ()
{
    d = 0;
    *(PBYTE)Parametr[0] = !(Flag.C || Flag.Z);
}
//------------------------------------------------------------------------------
void SETS ()
{
    d = 0;
    *(PBYTE)Parametr[0] = Flag.S;
}
//------------------------------------------------------------------------------
void SETNS ()
{
    d = 0;
    *(PBYTE)Parametr[0] = !Flag.S;
}
//------------------------------------------------------------------------------
void SETPE ()
{
    d = 0;
    *(PBYTE)Parametr[0] = Flag.P;
}
//------------------------------------------------------------------------------
void SETPO ()
{
    d = 0;
    *(PBYTE)Parametr[0] = !Flag.P;
}
//------------------------------------------------------------------------------
void SETL ()
{
    d = 0;
    *(PBYTE)Parametr[0] = Flag.S != Flag.O;
}
//------------------------------------------------------------------------------
void SETNL ()
{
    d = 0;
    *(PBYTE)Parametr[0] = Flag.S == Flag.O;
}
//------------------------------------------------------------------------------
void SETNG ()
{
    d = 0;
    *(PBYTE)Parametr[0] = Flag.Z && Flag.S != Flag.O;
}
//------------------------------------------------------------------------------
void SETG ()
{
    d = 0;
    *(PBYTE)Parametr[0] = !Flag.Z && Flag.S == Flag.O;
}
//------------------------------------------------------------------------------
void SFENCE ()
{
}
void SHLD ()
{
}
void SHRD ()
{
}
void SHUFP ()
{
}
void SQRT ()
{
}
void STMXCSR ()
{
}
void SYSENTER ()
{
}
void UCOMIS ()
{
}
void UD2 ()
{
}
void UNPCKHPS ()
{
}
void UNPCKLPS ()
{
}
void WBINVD ()
{
}
void WRMSR ()
{
}
void XADD ()
{
}
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
void (*pfIns[301])(void) =
{                                                                     
/*0*/  ADD,       OR,        ADC,        SBB,        AND,         SUB,      XOR,      CMP,      MOV,       _IN, 
/*1*/  _OUT,      TEST,      XCHG,       PUSH,       POP,         DAA,      DAS,      AAA,      AAS,       DEC, 
/*2*/  INC,       PUSHA,     POPA,       BOUND,      ARPL,        IIMUL,    INSB,     INSW,     OUTSB,     OUTSW, 
/*3*/  JO,        JNO,       JC,         JNC,        JZ,          JNZ,      JBE,      JA,        JS,       JNS, 
/*4*/  JPE,       JPO,       JL,         JNL,        JNG,         JG,       LEA,      NOP,      CBW,       CWD, 
/*5*/  CALL,      WAIT,      PUSHF,      POPF,       SAHF,        LAHF,     MOVSB,    MOVSW,    CMPSB,     CMPSW, 
/*6*/  SOTSB,     SOTS,      LODSB,      LODS,       SCASB,       SCAS,     RET,      LES,      ENTER,     LEAVE, 
/*7*/  RETF,      BKPT,      _INT,       INTO,       IRET,        AAM,      AAD,      SETALC,   XLAT,      ESC, 
/*8*/  LOOPNZ,    LOOPZ,     LOOP,       JCXZ,       JMP,         LOCK,     SMT,      REPZ,     REPNZ,     HLT, 
/*9*/  CMC,       CLS,       STS,        CLI,        STI,         CLD,      STD,      ROL,      ROR,       RCL, 
/*10*/ RCR,       SHL,       SHR,        SAL,        SAR,         NOT,      NEG,      MUL,      IMUL,      DIV, 
/*11*/ IDIV,      LDS,       ESp,        CSp,        SSp,         DSp,      FSp,      GSp,      OPSIZE,    ADDR, 
/*12*/ LGDT,      SGDT,      LIDT,       SIDT,       LLDT,        SLDT,     LTR,      STR,      LMSW,      SMSW, 
/*13*/ LAR,       LSL,       VERR,       VERW,       CLTS,        INVD,     WBINVD,   UD2,      PREFETCH,  FEMMS, 
/*14*/ MOVUPS,    UNPCKLPS,  UNPCKHPS,   MOVHPS,     MOVLPS,      MOVAP,    CVTPI2,   MOVNTP,   CVTT,      CVT, 
/*15*/ UCOMIS,    COMIS,     WRMSR,      RDTSC,      RDMSR,       RDPMC,    SYSENTER, CMOVO,    CMOVNO,    CMOVC, 
/*16*/ CMOVNC,    CMOVZ,     CMOVNZ,     CMOVBE,     CMOVA,       CMOVS,    CMOVNS,   CMOVPE,   CMOVPO,    CMOVL, 
/*17*/ CMOVNL,    CMOVNG,    CMOVG,      MOVMSK,     SQRT,        RSQRT,    RCP,      ANDN,     _MIN,      _MAX, 
/*18*/ PUNPCKLBW, PUNPCKLWD, PUNPCKLDQ,  PACKSSWB,   PCMPGTB,     PCMPGTW,  PCMPGTD,  PACKUSWB, PUNPCKHBW, PUNPCKHWD, 
/*19*/ PUNPCKHDQ, PACKSSDW,  PUNPCKLQDQ, PUNPCKHQDQ, MOVD,        PSHUF,    PCMPEQB,  PCMPEQW,  PCMPEQQ,   EMMS, 
/*20*/ MMX_UD,    HADDPD,    HSUBPD,     SETO,       SETNO,       SETC,     SETNC,    SETZ,     SETNZ,     SETBE, 
/*21*/ SETA,      SETS,      SETNS,      SETPE,      SETPO,       SETL,     SETNL,    SETNG,    SETG,      CPUID, 
/*22*/ BT,        SHLD,      RSM,        BTS,        SHRD,        CMPXCHG,  LSS,      BTR,      LFS,       LGS, 
/*23*/ MOVZX,     BTC,       BSF,        MOVSX,      XADD,        MOVNTI,   PINSRW,   PEXTRW,   SHUFP,     BSWAP, 
/*24*/ ADDSUB,    PSRLW,     PSRLD,      PSRLQ,      PADDQ,       PMULLW,   PMOVMSKB, PSUBUSB,  PSUBUSW,   PMINUB, 
/*25*/ PADND,     PADDUSB,   PADDUSW,    PMAXUB,     PANDN,       PAVGB,    PSRAW,    PSRAD,    PSRAQ,     PMULHUW, 
/*26*/ PMULHW,    MOVNTQ,    PSUBSB,     PSUBSW,     PMINSW,      POR,      PADDSB,   PADDSW,   PMAXSW,    PXOR, 
/*27*/ LDDQU,     PSLLW,     PSLLD,      PSLLQ,      PMULUDQ,     PMADDWD,  PSADBW,   MASKMOVQ, PSUBB,     PSUBW, 
/*28*/ PSUBD,     PSUBQ,     PADDB,      PADDW,      PADDD,       INVLPG,   FXSAVE,   FXRSTOR,  LDMXCSR,   STMXCSR, 
/*29*/ LFENCE,    MFENCE,    SFENCE,     CMPXCH8B,   PREFTCHINTA, PREFTCH0, PREFTCH1, PREFTCH2, BSR,       MOV_, 
/*30*/ IMUL2
};

//------------------------------------------------------------------------------

WORD RM0() { return (WORD)(r_bx + r_si); }
WORD RM1() { return (WORD)(r_bx + r_di); }
WORD RM2() { return (WORD)(r_bp + r_si); }
WORD RM3() { return (WORD)(r_bp + r_di); }
WORD RM4() { return r_si; }
WORD RM5() { return r_di; }
WORD RM6() { return r_bp; }
WORD RM7() { return r_bx; }
WORD (*pfRM[8])() = { RM0, RM1, RM2, RM3, RM4, RM5, RM6, RM7};

DWORD dwROR(DWORD a, BYTE b)
{
    return a;
}
DWORD dwROL(DWORD a, BYTE b)
{
    return a;
}
