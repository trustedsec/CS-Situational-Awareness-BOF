#include <windows.h>
#include "bofdefs.h"
#include "base.c"


void printUptime() {

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

	KERNEL32$SystemTimeToFileTime(&curTime, &curFTime);
	memcpy(&utime, &curFTime, sizeof(utime));
	utime.QuadPart -= ticks * 10000;

	memcpy(&curFTime, &utime, sizeof(utime));
	KERNEL32$FileTimeToSystemTime(&curFTime, &curTime);
	internal_printf("Boot time: %4d-%.2d-%.2d %.2d:%.2d:%.2d\n", curTime.wYear, curTime.wMonth, 
			curTime.wDay, curTime.wHour, curTime.wMinute, curTime.wSecond);
	
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
	printUptime();
	printoutput(TRUE);
	bofstop();
};

