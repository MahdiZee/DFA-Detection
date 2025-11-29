#ifndef ScanGeneralH
#define ScanGeneralH

#define MaxBuffSize 0x1000
#define MinBuffSize 0x10

enum AntiVirusOpertionType
{
    Detect, 
    DisInfect
};

enum VIRALSTATE
{
    VIRUSFREE,   // 0
    SUSPICIOUS,  // 1
    INFECTED     // 2
};

enum InfectionMethod
{
    ChangedEntryPoint = 0,            // CHE
    ReparableOverWrite,               // ROW
    CallHookRidirect,                 // CHR 
    ChangedRoutin = CallHookRidirect, // CHR 
    WithOutEntryPoint                 // WOE
};

enum ErrorMessage
{
    NoError = 0, 
    NotOpen,
    NotRead,
    NotWrite,
    ResultNonValid,
    NotExeFileMZ,
    NotExeFilePE,
    BufferNonAllocated,
    DisInfectedIncomplete,
    GeneralError
};

struct InfectionResult
{
    DWORD VirusNo;
    VIRALSTATE State;
    InfectionMethod Method;
    DWORD StartInfection;
    DWORD StartStub;
    union
    {
        struct
        {
            DWORD EntryPointOwerWriteLenght;
            BYTE  EntryPointOwerWrite[MaxBuffSize];
        } Row;
        struct
        {
            DWORD OffsetInfection;
            DWORD RoutinOwerWriteLenght;
            BYTE  RoutinOwerWrite[MinBuffSize]; 
        }Chr;
        struct
        {
            DWORD OrignalEntryPoint;              
        }Che;
    };
};
enum 
{
    Win32_Sality_AA = 1001, // Sality.q
    Win32_Sality_AB,        // Sality.x
    Win32_Sality_AC,        // Sality.v
    Win32_Sality_AD,        // Sality.z
    Win32_Sality_AE,        // Sality.ab
    Win32_Virut_F   = 2001,
    Win32_Virut_I,
    Win32_Virut_J,   
    Win32_Virut_K,   
    Win32_Virut_L,   
    Win32_Virut_M,   
    Win32_Virut_N,   
    Win32_Virut_Z,   
    Win32_Virut_AB,  
    Win32_Virut_AC,  
    Win32_Virut_AE,  
    Win32_Virut_AF,  
    Win32_Virut_AI
};

#define NO_INFECTION (0xFFFFFFFF)

#endif