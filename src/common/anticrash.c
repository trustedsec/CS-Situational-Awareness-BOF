#include <stdarg.h>
#include "bofdefs.h"
//For some reason char *[] is invalid in BOF files
//So this function stands to work around that problem

//makes a char *[] since we can't seem to otherwise
//count is the number of strings you're passing in will crash if this is wrong

//Must call intFree on returned result
char ** antiStringResolve(unsigned int count, ...)
{
    va_list strings;
    va_start(strings, count);
    char ** result = intAlloc(sizeof(char *) * count);
    for(int i = 0; i < count; i++)
    {
        result[i] = (char *)va_arg(strings, char *);
    }
    va_end(strings);
    return result;
}