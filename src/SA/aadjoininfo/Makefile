BOFNAME := aadjoininfo
COMINCLUDE := -I ../../common
LIBINCLUDE := -l netapi32
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CC=x86_64-w64-mingw32-clang

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) -Os -c entry.c -DBOF 
	$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) -Os -c entry.c -DBOF
	mkdir -p ../../../SA/$(BOFNAME) 
	mv $(BOFNAME)*.o ../../../SA/$(BOFNAME)

test:
	# NetApi32 definitions not available with mingw32 as of writing
	#$(CC_x64) entry.c -I . -g $(COMINCLUDE) $(LIBINCLUDE)  -o $(BOFNAME).x64.exe -D_WIN32_WINNT=0x0A00 -DWINAPI_FAMILY=WINAPI_FAMILY_DESKTOP_APP
	#$(CC_x86) entry.c -g $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x86.exe -D_WIN32_WINNT=0x0A00 -DWINAPI_FAMILY=WINAPI_FAMILY_DESKTOP_APP

scanbuild:
	$(CC) entry.c -o $(BOFNAME).scanbuild.exe $(COMINCLUDE) $(LIBINCLUDE)

check:
	cppcheck --enable=all $(COMINCLUDE) --platform=win64 entry.c

clean:
	rm $(BOFNAME).*.exe