#ifndef DataH
#define DataH

#include "Type.h"

void  BufferInit();
int   BufferIsEnd();
int   BufferRead(int, PBYTE);
void  BufferEnd();
void  BufferSeek(DWORD);
void* BufferGet(DWORD);
void  SetThresholdOfBufferShouldBeCached(DWORD Threshold);

#endif
