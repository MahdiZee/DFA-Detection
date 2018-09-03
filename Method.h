#ifndef MethodH
#define MethodH
#include "Type.h"

typedef struct _BitByte1
{
    BYTE rm  : 3;
    BYTE reg : 3;
    BYTE mod : 2;
} BitByte1;

typedef struct _BitFiled
{
    BYTE rm  : 3;
    BYTE fun : 3;
    BYTE pwr : 2;
} BitFiled;

typedef struct _BitByte2
{
    BYTE reg : 3;
    BYTE r   : 2;
    BYTE mod : 3;
} BitByte2;

void SetDW      ();
void Method0    ();
void Method1    ();
void Method2    ();
void Method3    ();
void Method4    ();
void Method5    ();
void Method6    ();
void Method7    ();
void Method8    ();
void Immediate  ();
void Shift      ();
void Grp1       ();
void Grp2       ();
void Grp9       ();
void Group      ();
void Prefix     ();
void ZeroPrefix ();

extern void (*pFun[16])();
extern BitByte1 B;

#endif
