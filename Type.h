#ifndef TypeH
#define TypeH

typedef unsigned char      BYTE;
typedef BYTE*              PBYTE;

typedef unsigned short int WORD;
typedef WORD*              PWORD;

typedef unsigned long int  DWORD;
typedef DWORD*             PDWORD;

typedef int                BOOL;
typedef void*              PVOID;

typedef char               SIGNED_BYTE;
typedef short int          SIGNED_WORD;
typedef long int           SIGNED_DWORD;
typedef unsigned int       UINT;
   
#define DefaultEAX  0x00000000
#define DefaultECX  0x00000000
#define DefaultEDX  0x00000000
#define DefaultEBX  0x00000000
#define DefaultESI  0x00000000
#define DefaultEDI  0x00000000
#define DefaultESP  0xFFFFFFFE
#define DefaultEBP  0x00000000

#define DefaultES  0x004000000
#define DefaultCS  0x004000001
#define DefaultSS  0x004000002
#define DefaultDS  0x004000003
#define DefaultFS  0x004000004
#define DefaultGS  0x004000005

#ifndef NULL
#ifdef __cplusplus
#define NULL    0
#else
#define NULL    ((void*)0)
#endif
#endif

#define min(a,b) (((a) < (b)) ? (a) : (b))
#define MIN(a, b) min(a, b)

#define NUMBER_OF_ARRAY(arr) ((sizeof(arr)/sizeof(arr[0])))

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#endif
