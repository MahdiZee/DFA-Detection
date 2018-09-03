#include "BFile.h"
#include "tchar.h"
BFile::~BFile()
{
    Close();
}
//-------------------------------------------------------------------------------------------------
BFile::BFile()
{
    FileSize = 0;
    mFileHandle = INVALID_HANDLE_VALUE;
    mFileTemp = NULL;
}
//-------------------------------------------------------------------------------------------------
BFile::BFile(BFile& File)
{
    *this = File;
    FileSize = 0;
    mFileTemp = NULL;
    if (mFileHandle != INVALID_HANDLE_VALUE)
        Open(mFileName);
}
//-------------------------------------------------------------------------------------------------
BFile::BFile(HANDLE FileHandle)
{
    FileSize = 0;
    mFileHandle = FileHandle; 
    mFileTemp = NULL;
}
//-------------------------------------------------------------------------------------------------
BFile::BFile(TCHAR* FileName, DWORD Access)
{
    mFileName = FileName;
    mFileTemp = NULL;
    Open(mFileName, Access);
}
//-------------------------------------------------------------------------------------------------
BOOL BFile::Open(TCHAR* FileName, DWORD Access)
{
    mFileHandle = INVALID_HANDLE_VALUE;
    __try
    {
        mFileHandle = ::CreateFile (FileName,
                                    Access,
                                    FILE_SHARE_WRITE | FILE_SHARE_READ,
                                    NULL,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    NULL);
    }
    __finally
    {
    }

    if (mFileHandle != INVALID_HANDLE_VALUE)
    {
        mFileName = FileName;
        FileSize = Seek(0, FILE_END);
        Seek(0);
    }
    return (mFileHandle != INVALID_HANDLE_VALUE);
}
//-------------------------------------------------------------------------------------------------
DWORD BFile::Read(PVOID Buffer, UINT Size)
{
    DWORD NumberOfBytesRead = 0;
    BOOL  isRead = FALSE;
    __try
    {
        isRead = ::ReadFile(mFileHandle, Buffer, Size, &NumberOfBytesRead, NULL);
    }
    __finally
    {
    }
    return (isRead == FALSE) ? 0 : NumberOfBytesRead;
}
//-------------------------------------------------------------------------------------------------
DWORD BFile::Seek(DWORD FilePointer, BYTE MoveMethod)
{
    DWORD _FilePointer = 0;
    __try
    {
        _FilePointer = ::SetFilePointer (mFileHandle, (LONG)FilePointer, NULL, MoveMethod);
    }
    __finally
    {
    }
    return _FilePointer;
}
//-------------------------------------------------------------------------------------------------
void BFile::Close()
{
    __try
    {
        ::CloseHandle (mFileHandle);
        if (mFileTemp != NULL)
        {
            DWORD Attributes = GetFileAttributes(mFileName);
            SetFileAttributes(mFileName, FILE_ATTRIBUTE_NORMAL);
            ::CopyFile (mFileTemp, mFileName, FALSE);
            SetFileAttributes(mFileName, Attributes);
            Erase(mFileTemp);
            delete[] mFileTemp;
            mFileTemp = NULL;
        }
    }
    __finally
    {
    }
}
//-------------------------------------------------------------------------------------------------
void BFile::Erase(TCHAR* FileName)
{
    __try
    {
        if (::DeleteFile(FileName) == TRUE)
            return;

        ::SetFileAttributes(FileName, FILE_ATTRIBUTE_NORMAL); // FILE_ATTRIBUTE_NORMAL
        if (::DeleteFile(FileName) == TRUE)
            return;

        // To delete or rename a file, you must have either delete permission on the file, 
        // or delete child permission in the parent directory.
        ::MoveFileEx(FileName, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    __finally
    {
    }
}
//-------------------------------------------------------------------------------------------------
DWORD BFile::GetFileSize()
{
    return FileSize;
}
//-------------------------------------------------------------------------------------------------
DWORD BFile::MianDoSefr(DWORD Start, DWORD Size, BYTE Target)
{
    BYTE* Buffer = new BYTE[Size];
    Seek(Start);
    if (Read(Buffer, Size) < Size)
        return 0;
    
    for(int i = Size - 1; i >= 0; i--)
    {
        if (Buffer[i] != Target)
        {
            delete[] Buffer;
            return Start + i;
        }
    }

    delete[] Buffer;
    return 0;
}
//------------------------------------------------------------------------------
#if defined(Behpad) || defined(Zeynali)
DWORD BFile::Write(PVOID Buffer, UINT Size)
{
    DWORD NumberOfBytesWrite = 0;
    BOOL  isWrite = FALSE;
    __try
    {
        isWrite = ::WriteFile(mFileHandle, Buffer, Size, &NumberOfBytesWrite, NULL);
    }
    __finally
    {
    }
    return (isWrite == FALSE)? 0 : NumberOfBytesWrite;
}
//-------------------------------------------------------------------------------------------------
DWORD BFile::WriteZero(UINT Size)
{
    return Fill(Size, 0);
}
//-------------------------------------------------------------------------------------------------
DWORD BFile::Fill(UINT Size, BYTE byte)
{
    DWORD NumberOfBytesWrite = 0;
    BYTE* Temp = new BYTE[Size];
    if (Temp == NULL)
        return NumberOfBytesWrite;
    
    memset(Temp, byte, Size);
    NumberOfBytesWrite = Write(Temp, Size);
    delete[] Temp;
    return NumberOfBytesWrite;
}
//-------------------------------------------------------------------------------------------------
BOOL BFile::Truncate (UINT FilePointer)
{
    Seek(FilePointer);
    return SetEndOfFile(mFileHandle);
}
//-------------------------------------------------------------------------------------------------
BOOL BFile::OpenTemp(TCHAR* FileName)
{
    TCHAR TempPath[MAX_PATH];
    DWORD ReturnValue = 0;
    __try
    {
        ReturnValue = ::GetTempPath(MAX_PATH, TempPath);
        if (ReturnValue > MAX_PATH || ReturnValue == 0)
            return FALSE;

        mFileTemp = new TCHAR[_tcslen(TempPath) + 40];

        ReturnValue = ::GetTempFileName(TempPath, "BAV", 1, mFileTemp);  
        if (ReturnValue == 0)
            return FALSE;

        if (::CopyFile (FileName, mFileTemp, FALSE) == FALSE)
            return FALSE;
    
        ::SetFileAttributes(mFileTemp, FILE_ATTRIBUTE_NORMAL);
        if (Open (mFileTemp, AccessReadWrite) == FALSE)
            return FALSE;

        mFileName = FileName;
    }
    __finally
    {
    }
    return TRUE;
}
#endif
//-------------------------------------------------------------------------------------------------
