#include "Method.h"
#include "DisasmbleTable.h"
#include "Data.h"

//------------------------------------------------------------------------------
int    reg, temp;
BYTE   b[10];
BitByte1 B, *pB;
BitFiled Bt;
WORD GrpPrefix[4] = {0, 0, 0, 0};

//------------------------------------------------------------------------------
PDWORD CReg(int r)
{
    if (r & 8)
        return &(Reg[r % 8].ex);
    return (PDWORD)&Reg[ r % 4 ].l[ r / 4 ];
}
//------------------------------------------------------------------------------
void SetDW()
{
    w = b[0] & 1;
    d = (b[0] >> 1) & 1;
}
//------------------------------------------------------------------------------
int GetSizeOfRead()
{
    if (w == 0)
        return 1;
    if (GrpPrefix[2] == ID_OPSIZE)
        return 2;
    return 4;
}
//------------------------------------------------------------------------------
void ModRegRM16(BitByte1 B)
{
    int i;
    WORD h;
    switch(B.mod)
    {
    case 0:
        if (B.rm == 6)
        {
            BufferRead(2, b + 2);
            Const = *(PWORD)(b+2);
            Parametr[0] = (PDWORD)BufferGet(Const);
        }
        else
        {
            Const = pfRM[B.rm]();
            Parametr[0] = (PDWORD)BufferGet(Const);
        }
        break;
    case 1:
    case 2:
        b[2] = b[3] = b[4] = b[5] = 0;
        for (i = 0; i < B.mod; i++)
            BufferRead (1, &b[2+i]);

        Const = *(PDWORD)(b + 2);
        h = pfRM[ B.rm ]();
        Const += h;
        Parametr[0] = (PDWORD)BufferGet(Const);
        break;
    case 3:
        reg = B.rm + (w << 3);
        Parametr[0] = CReg(reg);
    }
}
//------------------------------------------------------------------------------
void PwrFunRM(BitFiled Bt)
{
    switch(Bt.rm)
    {
    case 4 :
        BufferRead (1, b + 2);
        Bt = *(BitFiled*)(b + 2);
        Const = Reg[Bt.rm].ex << Bt.pwr;
        if (Bt.rm == 5)
        {
            BufferRead (4, b + 3);
            Const += *(PDWORD)(b + 3);
        }
        else
        {
            Const += Reg[Bt.fun].ex;
        }
        Parametr[0] = (PDWORD)BufferGet(Const);
        break;
    case 5 :
        BufferRead (4, b + 2);
        Const = *(PDWORD)(b + 2);
        Parametr[0] = (PDWORD)BufferGet(Const);
        break;
    default :
        Const = Reg[Bt.rm].ex;
        Parametr[0] = (PDWORD)BufferGet(Const);
    }
}
//------------------------------------------------------------------------------
void ModRegRM32(BitByte1 B)
{
    b[3]=b[4]=b[5]= 0;
    switch(B.mod)
    {
    case 0:
        Bt.rm  = B.rm;
        Bt.fun = B.reg;
        Bt.pwr = B.mod;
        PwrFunRM(Bt);
        break;
    case 1:
    case 2:
        if (B.rm == 4)
        {
            BufferRead (1, b + 2);
            Bt = *(BitFiled*)(b + 2);
            Const = Reg[ Bt.rm ].ex;
            Const += (Bt.fun != 4)? Reg[Bt.fun].ex << Bt.pwr : 0;
            BufferRead (B.mod*B.mod, b + 3);
            Const += *(PDWORD)(b + 3);
        }
        else
        {
            Const = Reg[ B.rm ].ex;
            BufferRead (B.mod*B.mod, b + 2);
            Const += *(PDWORD)(b + 2);
        }
        Parametr[0] = (PDWORD)BufferGet(Const);
        break;
    case 3:
        reg = B.rm + (w << 3);
        Parametr[0] = CReg(reg);
    }
}

void ModRegRM(BitByte1 B)
{
    if (GrpPrefix[3] == ID_ADDR)
        ModRegRM16(B);
    else
        ModRegRM32(B);
}
//////////////////////////////     Method 0     //////////////////////////////
/////////////////////////////format mod.reg.r/m///////////////////////////////
void Method0()
{
    BufferRead(1, b + 1);
    B = *(BitByte1*)(b + 1);
    if ((b[0] & 0xFE) == 0xC4 || b[0] == 0x8d)  //lea lds les
    {
        d = 1;
        w = 1;
    }
    if ((b[0]&0xFE) == 0xC6) // mov
    {
        if (B.reg != 0)
        {
            ZeroPrefix();
            return;
        }
        d = 0;
        ModRegRM(B);
        *(PDWORD)(b+6) = 0L;
        BufferRead ((w+1)*(w+1), b + 6);
        Const = *(PDWORD)(b + 6);
        Parametr[1] = &Const;
    }
    else
    {
        reg = B.reg + (w << 3);
        Parametr[1] = CReg(reg);
        ModRegRM(B);
    }
    ZeroPrefix();
}
/////////////////////////////////   Motod 1   ////////////////////////////////
///////////////////////////////// Accumulator ////////////////////////////////
void Method1()
{
    Parametr[0] = CReg(w << 3);
    *(PDWORD)(b + 1) = 0L;
    switch (b[0] & 0xFC)
    {
    case 0xEC:  // in  & out
        Parametr[0] = __EDX;
        break;
    case 0xA0:  // mov
        BufferRead(4, b + 1);
        Const = *(PDWORD)(b + 1);
        Parametr[1] = (PDWORD)BufferGet(Const);
        break;
    default:
        BufferRead(GetSizeOfRead(), b + 1);
        Const = *(PDWORD)(b + 1);
        Parametr[1] = &Const;
    }
    ZeroPrefix();
}
//////////////////////////////     Motod 2   ///////////////////////////////////
////////////////////////////// Normal Rigster //////////////////////////////////
void  Method2()
{
    BitByte2 B;
    B = *(BitByte2*)&b[0];
    d = 0;
    switch(B.mod)
    {
    case 2:
        Parametr[0] = & Reg[ B.reg ].ex;
        break;
    case 4: // xchag
        Parametr[0] = __EAX;
        Parametr[1] = & Reg [ B.reg ].ex;
        break;
    case 5: // mov
        w = B.r & 1;
        int SizeOfRead = GetSizeOfRead();
        reg = B.reg + (w << 3);
        b[2]=b[3]=b[4]= 0;
        BufferRead(SizeOfRead, b + 1);
        Const = *(PDWORD)(b + 1);
        Parametr[0] = CReg(reg);
        Parametr[1] = &Const;
    }
    ZeroPrefix();
}
//////////////////////////////     Motod 3      ////////////////////////////////////
////////////////////////////// Segment Rigester ////////////////////////////////////
void Method3()
{
    B = *(BitByte1*)&b[0];
    if ((b[0]&0xFC) == 0x8C) //mov
    {
        BufferRead (1, b + 1);
        B = *(BitByte1*) &b[1];
        Parametr[1] = &SReg[B.reg];
        ModRegRM (B);
    }
    else if (b[0] == 0x0f) // PUSH FS, GS  (0x0a)
    {
        BufferRead (1, b + 1);
        Parametr[0] = &SReg[ 4 + (b[1]>>3)&1 ];
    }
    else
    {
        Parametr[0] = &SReg[B.reg ];
    }

    ZeroPrefix();
}
///////////////////////////////    Motod 4   /////////////////////////////////
///////////////////////////////    1 Byte    /////////////////////////////////
void Method4()
{
    Parametr[0] = NULL;
    Const = 0;
    ZeroPrefix();
}
////////////////////////////////   Motod 5    ////////////////////////////////
//////////////////// 2 byte jmp or call or int push //////////////////////////
void Method5()
{
    SIGNED_DWORD c;

    *(PDWORD)(b + 2) = 0L;
    if ((b[0] & 0xFD) == 0x68) // push
    {
        d = !d + 1;
        BufferRead(d*d, b + 1);
        Const = (d == 1) ? (char)b[1] : *(PDWORD)(b + 1);
    }
    else
    {
        if (b[0] == 0xC2) // ret
        {
            BufferRead (2, b + 1);
            Const = *(WORD*)(b+1);;
        }
        else
        {
            if ((b[0] & 0xFD) == 0xCD) // int
            {
                BufferRead (1, &b[1]);
                Const = (WORD)b[1];
            }
            else
            {
                if ((b[0]&0x8F) == 0x8A) // Real (Far) JMP CALL
                {
                    BufferRead (6, b + 1);
                    Const += (DWORD)(*(PDWORD)(b+1)*16 + *(PWORD)(b + 5));
                }
                else
                {
                    if (((b[0]&0xFE) == 0xE8) || ((b[0] == 0x0F) && (b[1]&0xF0) == 0x80)) // Near JMP CALL
                    {
                        BufferRead (4, b+1);
                        c = *(SIGNED_DWORD*)(b+1);
                    }
                    else  // Relative
                    {
                        BufferRead (1, &b[1]);
                        c = (char) b[1]; // Visit Nabod
                    }
                    Const = (c + EIP); // no visit
                }
            }
        }
    }
    Parametr[0] = &Const;
    ZeroPrefix();
}
/////////////////////////////// IMULL 3 /////////////////////////////////
void Method6()
{
    BufferRead (1, &b[1]);
    B = *(BitByte1*)  &b[1];
    Parametr[1] = CReg (B.reg + 8);
    ModRegRM (B);
    d = !w;
    *(PDWORD)(b + 2) = 0L;
    BufferRead (GetSizeOfRead(), b + 2);
    Const = *(PDWORD)(b + 2);
    ZeroPrefix();
}
/////////////////////////////////////////////////////////////////////////
void Method7()
{
    int Read;
    BufferRead (2, b + 2);
    pB = (BitByte1*) &b[2];
    switch (B.mod)
    {
    case 0 :
    case 3 :
        Read = 0;
        break;
    case 1 :
    case 2 :
        Read = B.mod*B.mod;
        break;
    }
    BufferRead (Read, b + 3);
    ZeroPrefix();
}
///////////////////////////////////////////////////////////////////////
void Method8()
{
    BufferRead (1, b + 1);
}
////////////////////////////  Motod All0    //////////////////////////
void Immediate()
{
    int SizeOfRead = GetSizeOfRead();
    ModRegRM (B);
    b[7]=b[8]=b[9]=0;
    BufferRead (1, b + 6);
    if (w == 1 && d == 0)
    {
        BufferRead (SizeOfRead - 1, b + 7);
        Const = (SizeOfRead == 4) ? *(PDWORD)(b + 6) : (DWORD)(*(SIGNED_WORD*)(b + 6));
    }
    else
    {
        Const = (char)b[6];
    }

    Parametr[1] = &Const;
    d = 0;
    ZeroPrefix();
}
////////////////////////////    Motod All1    //////////////////////////
void Shift()
{
    if ((b[0]&0xfe) == 0xc0)
    {
        BufferRead (1, b + 2);
        Const = (DWORD)b[2];
        Parametr[1] = &Const;
    }
    else if (d == 0)
    {
        Const = 1;
        Parametr[1] = &Const;
    }
    else
    {
        Parametr[1] = __CL;
    }
    ModRegRM(B);
    d = 0;
    ZeroPrefix();
}
////////////////////////////   Motod All2    //////////////////////////
void Grp1()
{
    d = 0;
    if ((B.reg == 0) || (B.reg == 1))    //test
    {
        *(PDWORD)(b+2) = 0L;
        BufferRead (GetSizeOfRead(), &b[2]);
        Const = *(PDWORD)(b + 2);
        Parametr [1] = &Const;
    }
    ModRegRM (B);
    ZeroPrefix();
}
////////////////////////////    Motod All3    //////////////////////////
void Grp2()
{
    Bt.rm  = B.rm;
    Bt.fun = B.reg;
    Bt.pwr = B.mod;

    if (!(Bt.fun > 1 && Bt.fun < 6 && w == 0))
        ModRegRM(B);

    ZeroPrefix();
}
////////////////////////////     Group 9    ////////////////////////////
void Grp9()
{
    d = 0;
    int Read = (1 << B.mod) & 0x07;
    if (Read == 0)
        Read = 1;
    BufferRead (Read, b + 2);
    ZeroPrefix();
}
////////////////////////////  Motod Group   ////////////////////////////
void Group()     //0X0F
{
    d = 0;
    ZeroPrefix();
}
////////////////////////////    Prefix     /////////////////////////////
void Prefix()
{
}
////////////////////////////////////////////////////////////////////////
void ZeroPrefix()
{
    GrpPrefix[0] = 0;
    GrpPrefix[1] = 0;
    GrpPrefix[2] = 0;
    GrpPrefix[3] = 0;
}
////////////////////////////////////////////////////////////////////////