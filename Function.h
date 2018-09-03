#ifndef FunctionH
#define FunctionH
#include "Type.h"

#define MAX_STACK_ENTRIES (500)
#define STACK_SIZE        (MAX_STACK_ENTRIES*sizeof(DWORD))
#define FS_SEGMENT_SIZE   (0x40)

#define END_OF_STACK  (Stack + STACK_SIZE)
typedef struct
{
    int C  :1;
    int rs1:1;
    int P  :1;
    int rs2:1;
    int A  :1;
    int rs3:1;
    int Z  :1;
    int S  :1;
    int T  :1;
    int I  :1;
    int D  :1;
    int O  :1;
    int rs4:4;
    WORD Reserved16Bit;
} __Flag;

void SetInit(void);

void  InsUnInit(void);
BOOL  TestValue(void);

void  ADD   ();void  OR    ();void  ADC     (); void  SBB   (); void  AND   ();
void  SUB   ();void  XOR   ();void  CMP     (); void  MOV   (); void  _IN   ();
void  _OUT  (); void  TEST  (); void  XCHG  (); void  PUSH  (); void  POP   ();
void  DAA   (); void  DAS   (); void  AAA   (); void  AAS   (); void  DEC   ();
void  INC   (); void  PUSHA (); void  POPA  (); void  BOUND (); void  ARPL  ();
void  IIMUL (); void  INSB  (); void  INSW  (); void  OUTSB (); void  OUTSW ();
void  JO    (); void  JNO   (); void  JC    (); void  JNC   (); void  JZ    ();
void  JNZ   (); void  JBE   (); void  JA    (); void  JS    (); void  JNS   ();
void  JPE   (); void  JPO   (); void  JL    (); void  JNL   (); void  JNG   ();
void  JG    (); void  LEA   (); void  NOP   (); void  CBW   (); void  CWD   ();
void  CALL  (); void  WAIT  (); void  PUSHF (); void  POPF  (); void  SAHF  ();
void  LAHF  (); void  MOVSB (); void  MOVSW (); void  CMPSB (); void  CMPSW ();
void  SOTSB (); void  SOTS  (); void  LODSB (); void  LODS  (); void  SCASB ();
void  SCAS  (); void  RET   (); void  LES   (); void  ENTER (); void  LEAVE ();
void  RETF  (); void  BKPT  (); void  _INT  (); void  INTO  (); void  IRET  ();
void  AAM   (); void  AAD   (); void  SETALC(); void  XLAT  (); void  ESC   ();
void  LOOPNZ(); void  LOOPZ (); void  LOOP  (); void  JCXZ  (); void  JMP   ();
void  LOCK  (); void  SMT   (); void  REPZ  (); void  REPNZ (); void  HLT   ();
void  CMC   (); void  CLS   (); void  STS   (); void  CLI   (); void  STI   ();
void  CLD   (); void  STD   (); void  ROL   (); void  ROR   (); void  RCL   ();
void  RCR   (); void  SHL   (); void  SHR   (); void  SAL   (); void  SAR   ();
void  NOT   (); void  NEG   (); void  MUL   (); void  IMUL  (); void  DIV   ();
void  IDIV  (); void  LDS   (); void  ESp   (); void  CSp   (); void  SSp   ();
void  DSp   (); void  FSp   (); void  GSp   (); void  OPSIZE(); void  ADDR  ();
//------------------------------------------------------------------------------
void  LGDT  (); void  SGDT  (); void  LIDT  (); void  SIDT  (); void  LLDT  ();
void  SLDT  (); void  LTR   (); void  STR   (); void  LMSW  (); void  SMSW  ();
void  LAR   (); void  LSL   (); void  VERR  (); void  VERW  ();
//------------------------------------------------------------------------------
void ADDSUB   (); void ANDN      (); void BSWAP    (); void BT         ();
void BTC      (); void BSF       (); void BTR      (); void BTS        ();
void CLTS     (); void CMOVA     (); void CMOVBE   (); void CMOVC      ();
void CMOVG    (); void CMOVL     (); void CMOVNC   (); void CMOVNG     ();
void CMOVNL   (); void CMOVNO    (); void CMOVNS   (); void CMOVNZ     ();
void CMOVO    (); void CMOVPE    (); void CMOVPO   (); void CMOVS      ();
void CMOVZ    (); void CMPXCH8B  (); void CMPXCHG  (); void COMIS      ();
void CPUID    (); void CVT       (); void CVTPI2   (); void CVTT       ();
void EMMS     (); void FEMMS     (); void FXRSTOR  (); void FXSAVE     ();
void HADDPD   (); void HSUBPD    (); void INVD     (); void INVLPG     ();
void LDDQU    (); void LDMXCSR   (); void LFENCE   (); void LFS        ();
void LGS      (); void LSS       (); void MASKMOVQ (); void _MAX       ();
void MFENCE   (); void _MIN      (); void MMX_UD   (); void MOVAP      ();
void MOVD     (); void MOVHPS    (); void MOVLPS   (); void MOVMSK     ();
void MOVNTI   (); void MOVNTP    (); void MOVNTQ   (); void MOVSX      ();
void MOVUPS   (); void MOVZX     (); void PACKSSDW (); void PACKSSWB   ();
void PACKUSWB (); void PADDB     (); void PADDD    (); void PADDQ      ();
void PADDSB   (); void PADDSW    (); void PADDUSB  (); void PADDUSW    ();
void PADDW    (); void PADND     (); void PANDN    (); void PAVGB      ();
void PCMPEQB  (); void PCMPEQQ   (); void PCMPEQW  (); void PCMPGTB    ();
void PCMPGTD  (); void PCMPGTW   (); void PEXTRW   (); void PINSRW     ();
void PMADDWD  (); void PMAXSW    (); void PMAXUB   (); void PMINSW     ();
void PMINUB   (); void PMOVMSKB  (); void PMULHUW  (); void PMULHW     ();
void PMULLW   (); void PMULUDQ   (); void POR      (); void PREFETCH   ();
void PREFTCH0 (); void PREFTCH1  (); void PREFTCH2 (); void PREFTCHINTA();
void PSADBW   (); void PSHUF     (); void PSLLD    (); void PSLLQ      ();
void PSLLW    (); void PSRAD     (); void PSRAQ    (); void PSRAW      ();
void PSRLD    (); void PSRLQ     (); void PSRLW    (); void PSUBB      ();
void PSUBD    (); void PSUBQ     (); void PSUBSB   (); void PSUBSW     ();
void PSUBUSB  (); void PSUBUSW   (); void PSUBW    (); void PUNPCKHBW  ();
void PUNPCKHDQ(); void PUNPCKHQDQ(); void PUNPCKHWD(); void PUNPCKLBW  ();
void PUNPCKLDQ(); void PUNPCKLQDQ(); void PUNPCKLWD(); void PXOR       ();
void RCP      (); void RDMSR     (); void RDPMC    (); void RDTSC      ();
void RSM      (); void RSQRT     (); void SETA     (); void SETBE      ();
void SETC     (); void SETG      (); void SETL     (); void SETNC      ();
void SETNG    (); void SETNL     (); void SETNO    (); void SETNS      ();
void SETNZ    (); void SETO      (); void SETPE    (); void SETPO      ();
void SETS     (); void SETZ      (); void SFENCE   (); void SHLD       ();
void SHRD     (); void SHUFP     (); void SQRT     (); void STMXCSR    ();
void SYSENTER (); void UCOMIS    (); void UD2      (); void UNPCKHPS   ();
void UNPCKLPS (); void WBINVD    (); void WRMSR    (); void XADD       ();
void BSR      ();

void  JMPT  (); void  JMPF  ();

extern PBYTE TopStack;
extern BYTE  Stack[];  // should be "Stack[]" not "*Stack" (for DOS Ver.) I dont know WHY ???

extern void (*pfIns[301])(void);

DWORD dwROR(DWORD a, BYTE b);
DWORD dwROL(DWORD a, BYTE b);
#endif
