#ifndef MessageH
#define MessageH

#if defined(_DEBUG)
#include "stdio.h"
#endif

#if defined(_DEBUG)
#define DebugMessage(Message) char temp[200];\
                              sprintf_s(temp, "File : %s\nFunction : %s\nLine : %d\nMessage : %s", __FILE__, __FUNCTION__, __LINE__, Message);\
                              MessageBox(NULL, temp, "Debug Message", MB_OK);
#else
#   define DebugMessage(Message) 
#endif

#endif
