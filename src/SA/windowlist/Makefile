BOFNAME := windowlist
COMINCLUDE := -I ../../common
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) -Os -c entry.c -DBOF 
	$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) -Os -c entry.c -DBOF
	mkdir -p ../../../SA/$(BOFNAME) 
	mv $(BOFNAME)*.o ../../../SA/$(BOFNAME)

test:
	$(CC_x64) -o $(BOFNAME).x64.exe $(COMINCLUDE) entry.c
	$(CC_x86) -o $(BOFNAME).x86.exe $(COMINCLUDE) entry.c

scanbuild:
	$(CC) -o $(BOFNAME).scanbuild.exe $(COMINCLUDE) entry.c

check:
	cppcheck --enable=all $(COMINCLUDE) entry.c

clean:
	rm $(BOFNAME).*.exe