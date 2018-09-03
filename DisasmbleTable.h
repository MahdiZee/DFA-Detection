#ifndef DisasmbleTableH
#define DisasmbleTableH

#include "Type.h"

#define  ID_ADD     0
#define  ID_OR      1
#define  ID_ADC     2
#define  ID_SBB     3
#define  ID_AND     4
#define  ID_SUB     5
#define  ID_XOR     6
#define  ID_CMP     7
#define  ID_MOV     8
#define  ID_IN      9

#define  ID_OUT     10
#define  ID_TEST    11
#define  ID_XCHG    12
#define  ID_PUSH    13
#define  ID_POP     14
#define  ID_DAA     15
#define  ID_DAS     16
#define  ID_AAA     17
#define  ID_AAS     18
#define  ID_DEC     19

#define  ID_INC     20
#define  ID_PUSHA   21
#define  ID_POPA    22
#define  ID_BOUND   23
#define  ID_ARPL    24
#define  ID_IIMUL   25
#define  ID_INSB    26
#define  ID_INSW    27
#define  ID_OUTSB   28
#define  ID_OUTSW   29

#define  ID_JO      30
#define  ID_JNO     31
#define  ID_JC      32
#define  ID_JNC     33
#define  ID_JZ      34
#define  ID_JNZ     35
#define  ID_JBE     36
#define  ID_JA      37
#define  ID_JS      38
#define  ID_JNS     39

#define  ID_JPE     40
#define  ID_JPO     41
#define  ID_JL      42
#define  ID_JNL     43
#define  ID_JNG     44
#define  ID_JG      45
#define  ID_LEA     46
#define  ID_NOP     47
#define  ID_CBW     48
#define  ID_CWD     49

#define  ID_CALL    50
#define  ID_WAIT    51
#define  ID_PUSHF   52
#define  ID_POPF    53
#define  ID_SAHF    54
#define  ID_LAHF    55
#define  ID_MOVSB   56
#define  ID_MOVSW   57
#define  ID_CMPSB   58
#define  ID_CMPSW   59

#define  ID_SOTSB   60
#define  ID_SOTS    61
#define  ID_LODSB   62
#define  ID_LODS    63
#define  ID_SCASB   64
#define  ID_SCAS    65
#define  ID_RET     66
#define  ID_LES     67
#define  ID_ENTER   68
#define  ID_LEAVE   69

#define  ID_RETF    70
#define  ID_BKPT    71
#define  ID_INT     72
#define  ID_INTO    73
#define  ID_IRET    74
#define  ID_AAM     75
#define  ID_AAD     76
#define  ID_SETALC  77
#define  ID_XLAT    78
#define  ID_ESC     79

#define  ID_LOOPNZ  80
#define  ID_LOOPZ   81
#define  ID_LOOP    82
#define  ID_JCXZ    83
#define  ID_JMP     84
#define  ID_LOCK    85
#define  ID_SMI     86
#define  ID_REPZ    87
#define  ID_REPNZ   88
#define  ID_HLT     89

#define  ID_CMC     90
#define  ID_CLC     91
#define  ID_STC     92
#define  ID_CLI     93
#define  ID_STI     94
#define  ID_CLD     95
#define  ID_STD     96
#define  ID_ROL     97
#define  ID_ROR     98
#define  ID_RCL     99

#define  ID_RCR     100
#define  ID_SHL     101
#define  ID_SHR     102
#define  ID_SAL     103
#define  ID_SAR     104
#define  ID_NOT     105
#define  ID_NEG     106
#define  ID_MUL     107
#define  ID_IMUL    108
#define  ID_DIV     109

#define  ID_IDIV    110
#define  ID_LDS     111

#define  ID_ES      112
#define  ID_CS      113
#define  ID_SS      114
#define  ID_DS      115
#define  ID_FS      116
#define  ID_GS      117

#define  ID_OPSIZE  118
#define  ID_ADDR    119

#define  ID_LGDT      120
#define  ID_SGDT      121
#define  ID_LIDT      122
#define  ID_SIDT      123
#define  ID_LLDT      124
#define  ID_SLDT      125
#define  ID_LTR       126
#define  ID_STR       127
#define  ID_LMSW      128
#define  ID_SMSW      129
#define  ID_LAR       130

#define  ID_LSL       131
#define  ID_VERR      132
#define  ID_VERW      133
#define  ID_CLTS      134
#define  ID_INVD      135
#define  ID_WBINVD    136
#define  ID_UD2       137
#define  ID_PREFETCH  138
#define  ID_FEMMS     139

#define  ID_MOVUPS    140
#define  ID_UNPCKLPS  141
#define  ID_UNPCKHPS  142
#define  ID_MOVHPS    143
#define  ID_MOVLPS    144
#define  ID_MOVAP     145
#define  ID_CVTPI2    146
#define  ID_MOVNTP    147
#define  ID_CVTT      148
#define  ID_CVT       149

#define  ID_UCOMIS    150
#define  ID_COMIS     151
#define  ID_WRMSR     152
#define  ID_RDTSC     153
#define  ID_RDMSR     154
#define  ID_RDPMC     155
#define  ID_SYSENTER  156
#define  ID_CMOVO     157
#define  ID_CMOVNO    158
#define  ID_CMOVC     159

#define  ID_CMOVNC    160
#define  ID_CMOVZ     161
#define  ID_CMOVNZ    162
#define  ID_CMOVBE    163
#define  ID_CMOVA     164
#define  ID_CMOVS     165
#define  ID_CMOVNS    166
#define  ID_CMOVPE    167
#define  ID_CMOVPO    168
#define  ID_CMOVL     169

#define  ID_CMOVNL    170
#define  ID_CMOVNG    171
#define  ID_CMOVG     172
#define  ID_MOVMSK    173
#define  ID_SQRT      174
#define  ID_RSQRT     175
#define  ID_RCP       176
#define  ID_ANDN      177
#define  ID_MIN       178
#define  ID_MAX       179

#define  ID_PUNPCKLBW 180
#define  ID_PUNPCKLWD 181
#define  ID_PUNPCKLDQ 182
#define  ID_PACKSSWB  183
#define  ID_PCMPGTB   184
#define  ID_PCMPGTW   185
#define  ID_PCMPGTD   186
#define  ID_PACKUSWB  187
#define  ID_PUNPCKHBW 188
#define  ID_PUNPCKHWD 189

#define  ID_PUNPCKHDQ 190
#define  ID_PACKSSDW  191
#define  ID_PUNPCKLQDQ  192
#define  ID_PUNPCKHQDQ  193
#define  ID_MOVD      194
#define  ID_PSHUF     195
#define  ID_PCMPEQB   196
#define  ID_PCMPEQW   197
#define  ID_PCMPEQQ   198
#define  ID_EMMS      199

#define  ID_MMX_UD    200
#define  ID_HADDPD    201
#define  ID_HSUBPD    202
#define  ID_SETO      203
#define  ID_SETNO     204
#define  ID_SETC      205
#define  ID_SETNC     206
#define  ID_SETZ      207
#define  ID_SETNZ     208
#define  ID_SETBE     209

#define  ID_SETA      210
#define  ID_SETS      211
#define  ID_SETNS     212
#define  ID_SETPE     213
#define  ID_SETPO     214
#define  ID_SETL      215
#define  ID_SETNL     216
#define  ID_SETNG     217
#define  ID_SETG      218
#define  ID_CPUID     219

#define  ID_BT        220
#define  ID_SHLD      221
#define  ID_RSM       222
#define  ID_BTS       223
#define  ID_SHRD      224
#define  ID_CMPXCHG   235
#define  ID_LSS       226
#define  ID_BTR       227
#define  ID_LFS       228
#define  ID_LGS       229

#define  ID_MOVZX     230
#define  ID_BTC       231
#define  ID_BSF       232
#define  ID_MOVSX     233
#define  ID_XADD      234
#define  ID_MOVNTI    235
#define  ID_PINSRW    236
#define  ID_PEXTRW    237
#define  ID_SHUFP     238
#define  ID_BSWAP     239

#define  ID_ADDSUB    240
#define  ID_PSRLW     241
#define  ID_PSRLD     242
#define  ID_PSRLQ     243
#define  ID_PADDQ     244
#define  ID_PMULLW    245
#define  ID_PMOVMSKB  246
#define  ID_PSUBUSB   247
#define  ID_PSUBUSW   248
#define  ID_PMINUB    249

#define  ID_PADND     250
#define  ID_PADDUSB   251
#define  ID_PADDUSW   252
#define  ID_PMAXUB    253
#define  ID_PANDN     254
#define  ID_PAVGB     255
#define  ID_PSRAW     256
#define  ID_PSRAD     257
#define  ID_PSRAQ     258
#define  ID_PMULHUW   259

#define  ID_PMULHW    260
#define  ID_MOVNTQ    261
#define  ID_PSUBSB    262
#define  ID_PSUBSW    263
#define  ID_PMINSW    264
#define  ID_POR       265
#define  ID_PADDSB    266
#define  ID_PADDSW    267
#define  ID_PMAXSW    268
#define  ID_PXOR      269

#define  ID_LDDQU     270
#define  ID_PSLLW     271
#define  ID_PSLLD     272
#define  ID_PSLLQ     273
#define  ID_PMULUDQ   274
#define  ID_PMADDWD   275
#define  ID_PSADBW    276
#define  ID_MASKMOVQ  277
#define  ID_PSUBB     278
#define  ID_PSUBW     279

#define  ID_PSUBD     280
#define  ID_PSUBQ     281
#define  ID_PADDB     282
#define  ID_PADDW     283
#define  ID_PADDD     284
#define  ID_INVLPG    285
#define  ID_FXSAVE    286
#define  ID_FXRSTOR   287
#define  ID_LDMXCSR   288
#define  ID_STMXCSR   289

#define  ID_LFENCE    290
#define  ID_MFENCE    291
#define  ID_SFENCE    292
#define  ID_CMPXCH8B  293
#define  ID_PREFTCHINTA 294
#define  ID_PREFTCH0  295
#define  ID_PREFTCH1  296
#define  ID_PREFTCH2  297
#define  ID_BSR       298
#define  ID_MOV_      299
#define  ID_IMUL2     300

#define  ID_METOD0  0    //format mod.reg.r/m            (2 .. 4 Byte)
#define  ID_METOD1  1    //Accumulator                  (1 .. 3 Byte)
#define  ID_METOD2  2    //nurmal  register           (1 .. 3 Byte)
#define  ID_METOD3  3    //segment register           (1 OR 3 Byte)
#define  ID_METOD4  4    //1 byte
#define  ID_METOD5  5    //2 or 3 byte             (jmp OR call OR int)
#define  ID_METOD6  6    //IMUL
#define  ID_METOD7  7

#define  ID_IMMEDIATE    8
#define  ID_SHIFT        9
#define  ID_GRP1        10
#define  ID_GRP2        11
#define  ID_GROUP       12
#define  ID_PREFIX      13

#define  ID_METOD8      15

#define  ID_ERORR       -7

#define  ID_Grp1        -7
#define  ID_Grp2        -7
#define  ID_Grp3        -7
#define  ID_Grp4        -7
#define  ID_Grp5        -7
#define  ID_Grp6        -7
#define  ID_Grp7        -7
#define  ID_Grp8        -7
#define  ID_Grp9        14
#define  ID_Grp10       -7
/*
#define  ID_Grp1        0
#define  ID_Grp2        1
#define  ID_Grp3        2
#define  ID_Grp4        3
#define  ID_Grp5        4
#define  ID_Grp6        5
#define  ID_Grp7        6
#define  ID_Grp8        7
#define  ID_Grp9        8
#define  ID_Grp10       9
*/

#define  __EAX   CReg(0)
#define  __EDX   CReg(2)
#define  __CL    CReg(9)

#define  reax   Reg[0].ex
#define  recx   Reg[1].ex
#define  redx   Reg[2].ex
#define  rebx   Reg[3].ex
#define  resp   Reg[4].ex
#define  rebp   Reg[5].ex
#define  resi   Reg[6].ex
#define  redi   Reg[7].ex

#define  r_ax   Reg[0].x
#define  r_cx   Reg[1].x
#define  r_dx   Reg[2].x
#define  r_bx   Reg[3].x
#define  r_sp   Reg[4].x
#define  r_bp   Reg[5].x
#define  r_si   Reg[6].x
#define  r_di   Reg[7].x

#define  r_al   Reg[0].l[0]
#define  r_cl   Reg[1].l[0]
#define  r_dl   Reg[2].l[0]
#define  r_bl   Reg[3].l[0]

#define  r_ah   Reg[0].l[1]
#define  r_ch   Reg[1].l[1]
#define  r_dh   Reg[2].l[1]
#define  r_bh   Reg[3].l[1]

#define  es   SReg[0]
#define  __CS SReg[1]
#define  ss   SReg[2]
#define  ds   SReg[3]
#define  fs   SReg[4]
#define  gs   SReg[5]

#define Xor   1
#define Ror   2
#define Rol   3
#define Rcr   4
#define Rcl   5

struct CTable
{
  unsigned short int Id;
  BYTE Method;
};

union Regis
{
    DWORD ex;
    WORD  x;
    BYTE  l[2];
};

extern union Regis Reg[8];

extern int d;
extern int w;
extern int VirusType;

extern const struct CTable Table[256];
extern const struct CTable Table0F[256];
extern short int TableALL[][8];
extern short int GroupTable[][8];

extern WORD (*pfRM[8])();

extern DWORD* Parametr[2];
extern DWORD SReg[6];
extern DWORD Const;
extern DWORD EmulReadError;

extern WORD Length;
extern DWORD EIP;
extern BYTE b[10];

#endif
