#include <windows.h>
#include "bofdefs.h"
#include "base.c"


VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	if(!bofstart())
	{
		return;
	}
	//CALLYOURFUNCHERE
	printoutput(TRUE);
	bofstop();
};
