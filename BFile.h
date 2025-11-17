#ifndef BFileH
#define BFileH
#include <windows.h>
#define AccessRead      (GENERIC_READ)
#define AccessWrite     (GENERIC_WRITE)
#define AccessReadWrite (GENERIC_WRITE | GENERIC_READ)

class BFile
{
private:
    DWORD FileSize;
    HANDLE mFileHandle;
    TCHAR* mFileName;
    TCHAR* mFileTemp;
public :
    ~BFile();
    BFile();
    BFile(HANDLE FileHandle);
    BFile(BFile& File);
    BFile(TCHAR* FileName, DWORD Access = AccessRead);
    BOOL  Open(TCHAR* FileName, DWORD Access = AccessRead);
    DWORD Read(PVOID Buffer, UINT Size);
    DWORD MianDoSefr(DWORD Start, DWORD Size, BYTE Target = 0);
    DWORD Seek(DWORD FilePointer, BYTE MoveMethod = FILE_BEGIN);
    void  Close();
    void  Erase(TCHAR* FileName);
    DWORD GetFileSize();
#if defined(Zeynali)
    DWORD Write(PVOID Buffer, UINT Size);
    DWORD WriteZero(UINT Size);
    DWORD Fill(UINT Size, BYTE byte);
    BOOL  Truncate (UINT FilePointer);
#endif
protected:
    BOOL  OpenTemp(TCHAR* FileName);
};

#endif