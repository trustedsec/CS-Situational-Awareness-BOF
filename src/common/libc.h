/*
 * *grumble* *grumble* BOF files don't have access to a libc.
 * So, these are quick implementations of some stuff we need.
 */
// Credits: https://github.com/rsmudge/CVE-2020-0796-BOF/blob/master/src/libc.c
#include <stdio.h>
#include <windows.h>

void mycopy(char* dst, const char* src, int size) {
	int x;
	for (x = 0; x < size; x++) {
		*dst = *src;
		dst++;
		src++;
	}
}

char mylc(char a) {
	if (a >= 'A' && a <= 'Z') {
		return a + 32;
	}
	else {
		return a;
	}
}

BOOL mycmpi(char* a, char* b) {
	while (*a != 0 && *b != 0) {
		if (mylc(*a) != mylc(*b))
			return FALSE;
		a++;
		b++;
	}

	return TRUE;
}