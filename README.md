# Situational Awareness BOF
This Repo intends to serve two purposes.  First it provides a nice set of basic situational awareness commands implemented in BOF.  This allows you to perform some checks on a host before you begin executing commands that may be more invasive.

Its larger goal is providing a code example and workflow for others to begin making more BOF files.  It is a companion document of the blog post made here: https://www.trustedsec.com/blog/a-developers-introduction-to-beacon-object-files/

## Making a new BOF
If you want to use the same workflow as this repository, your basic steps are as follows
1. Make a folder that covers the target topic, for example in this repo we are using SA
2. copy base_template into topic/commandname
3. modify the Makefile to have your commandname on the first line, this should be the same as the folder name
4. If doing something other then SA make sure to modify lines 14 / 15 of the makefile as well so its moved to the correct location
5. Make a .cna file in the base of your topic folder and add the commands that you reference.  If you followed this format you can take the helper function readbof from SA.cna

Realistically, this could be compressed into a helper script, but those steps were not taken for this effort.

## Available commands
|command|Usage|notes|
|-------|-----|-----|
|ipconfig|ipconfig| Simply gets ipv4 addresses, hostname and dns server|
|listdns|listdns| Pulls dns cache entries, attempts to query and resolve each|
|netstat|netstat| tcp / udp ipv4 netstat listing|
|netuser|netuser [username] [opt: domain]| Pulls info about specific user.  Pulls from domain if a domainname is specified|
|netview|netview| Gets a list of reachable servers in the current domain|
|netGroupList|netGroupList [opt: domain]|Lists Groups from the default (or specified) domain|
|netGroupListMembers|netGroupListMembers [groupname] [opt: domain]| Lists group members from the default (or specified) domain|
|netLocalGroupList|netLocalGroupList [opt: server]|List local groups from the local (or specified) computer|
|netLocalGroupListMembers|netLocalGroupListMembers [groupname] [opt: server]| Lists local groups from the local (or specified) computer|
|nslookup|nslookup [hostname] [opt:dns server] [opt: record type]| Makes a dns query.<br/>  dns server is the server you want to query (do not specify or 0 for default) <br/>record type is something like A, AAAA, or ANY.  Some situations are limited due to observed crashes.|
|routeprint|routeprint| prints ipv4 configured routes|
|whoami|whoami| simulates whoami /all|
|windowlist|windowlist| lists visible windows in the current users session|
|driversigs|driversigs| enumerate installed services Imagepaths to check the signing cert against known edr/av vendors|

#### credits
The functional code for most of these commands was taken from the reactos project or code examples hosted on MSDN.  
The driversigs codebase comes from https://gist.github.com/jthuraisamy/4c4c751df09f83d3620013f5d370d3b9

##### compiler used
The follow compiler was used.  This project has not been tested with other compilers.
```
Using built-in specs.
COLLECT_GCC=x86_64-w64-mingw32-gcc
COLLECT_LTO_WRAPPER=/usr/local/Cellar/mingw-w64/7.0.0_2/toolchain-x86_64/libexec/gcc/x86_64-w64-mingw32/9.3.0/lto-wrapper
Target: x86_64-w64-mingw32
Configured with: ../configure --target=x86_64-w64-mingw32 --with-sysroot=/usr/local/Cellar/mingw-w64/7.0.0_2/toolchain-x86_64 --prefix=/usr/local/Cellar/mingw-w64/7.0.0_2/toolchain-x86_64 --with-bugurl=https://github.com/Homebrew/homebrew-core/issues --enable-languages=c,c++,fortran --with-ld=/usr/local/Cellar/mingw-w64/7.0.0_2/toolchain-x86_64/bin/x86_64-w64-mingw32-ld --with-as=/usr/local/Cellar/mingw-w64/7.0.0_2/toolchain-x86_64/bin/x86_64-w64-mingw32-as --with-gmp=/usr/local/opt/gmp --with-mpfr=/usr/local/opt/mpfr --with-mpc=/usr/local/opt/libmpc --with-isl=/usr/local/opt/isl --disable-multilib --enable-threads=posix
Thread model: posix
gcc version 9.3.0 (GCC) 
```
