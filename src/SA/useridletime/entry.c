#include <windows.h>
#include "bofdefs.h"
#include "base.c"

void userIdletime() {
	LASTINPUTINFO lii = {0};
    DWORD tickCount = 0, idleTime = 0;


    lii.cbSize = sizeof(LASTINPUTINFO);

    if (USER32$GetLastInputInfo(&lii)) {
        tickCount = KERNEL32$GetTickCount();
        idleTime = (tickCount - lii.dwTime) / 1000; // Convert to seconds
		DWORD seconds = idleTime % 60;
		DWORD minutes = (idleTime / 60) % 60;
		DWORD hours = (idleTime / 3600) % 24;
		DWORD days = idleTime / 86400;

		internal_printf("Current User idle time: %lu days, %lu hours, %lu minutes, %lu seconds",days, hours, minutes, seconds);
        //internal_printf("Current User idle time: %lu seconds", idleTime);
    } else {
        internal_printf("Failed to retrieve last user idle time");
    }
}

#pragma comment(lib, "wtsapi32.lib")



VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	if (!bofstart())
	{
		return;
	}
	userIdletime();
	printoutput(TRUE);
	bofstop();
};