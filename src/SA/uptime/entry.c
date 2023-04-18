#include <windows.h>
#include "bofdefs.h"
#include "base.c"


#ifdef __x86_64__
void printUptime64() {
	// Counts millisecond ticks since last boot
	ULONGLONG ticks = KERNEL32$GetTickCount64();

	ULONGLONG seconds = ticks/1000;
	ULONGLONG minutes = seconds/60;
	ULONGLONG hours =   minutes/60;
	ULONGLONG days =	hours/24;

	internal_printf("Uptime: %lld days, %lld hours, %lld minutes, %lld seconds\n", 
		days, hours % 24, minutes % 60, seconds % 60);

	// MSDN recommends converting SysTime->FileTime before doing arithmetic
	SYSTEMTIME curTime = {0};
	FILETIME curFTime = {0};
	ULARGE_INTEGER utime;
	KERNEL32$GetLocalTime(&curTime);
	internal_printf("Local time: %4d-%.2d-%.2d %.2d:%.2d:%.2d\n", curTime.wYear, curTime.wMonth, 
			curTime.wDay, curTime.wHour, curTime.wMinute, curTime.wSecond);

	KERNEL32$SystemTimeToFileTime(&curTime, &curFTime);
	memcpy(&utime, &curFTime, sizeof(utime));
	utime.QuadPart -= ticks * 10000;

	memcpy(&curFTime, &utime, sizeof(utime));
	KERNEL32$FileTimeToSystemTime(&curFTime, &curTime);
	internal_printf("Boot time: %4d-%.2d-%.2d %.2d:%.2d:%.2d\n", curTime.wYear, curTime.wMonth, 
			curTime.wDay, curTime.wHour, curTime.wMinute, curTime.wSecond);
}
#endif

void printUptime32() {
	// Counts millisecond ticks since last boot
	DWORD ticks = KERNEL32$GetTickCount();
    
	DWORD seconds = ticks/1000;
	DWORD minutes = seconds/60;
	DWORD hours =   minutes/60;
	DWORD days =	hours/24;

	internal_printf("Uptime: %ld days, %ld hours, %ld minutes, %ld seconds\n", 
		days, hours % 24, minutes % 60, seconds % 60);
}

VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	if (!bofstart())
	{
		return;
	}
#ifdef __x86_64__
	printUptime64();
# else 
	printUptime32();
#endif
	printoutput(TRUE);
	bofstop();
};

