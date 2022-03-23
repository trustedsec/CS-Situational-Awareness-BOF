#include "bofdefs.h"
#include "beacon.h"
#include "base.c"

BOOL is_port_open(char* host, int port)
{
    BOOL ret = FALSE;
    struct addrinfo* result = NULL;
    struct addrinfo hints;

    intZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8] = { 0 };
    MSVCRT$sprintf(port_str, "%d", port);

    if (WS2_32$getaddrinfo(host, port_str, &hints, &result) == ERROR_SUCCESS) {
        SOCKET sock = WS2_32$socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (sock) {
            u_long nonblock = 1;
            WS2_32$ioctlsocket(sock, FIONBIO, &nonblock);

            struct timeval tv;
            tv.tv_sec = 5;
            tv.tv_usec = 0;

            struct fd_set sockets;
            FD_ZERO(&sockets);
            FD_SET(sock, &sockets);

            WS2_32$connect(sock, result->ai_addr, result->ai_addrlen);
            WS2_32$select(1, NULL, &sockets, NULL, &tv);

            if (WS2_32$__WSAFDIsSet(sock, &sockets)) {
                ret = TRUE;
            }
            WS2_32$closesocket(sock);
        }
        WS2_32$freeaddrinfo(result);
    }

    return ret;
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    if (!bofstart()) { return; }

    datap parser;
    char* host = NULL;
    int port = 0;

    BeaconDataParse(&parser, Buffer, Length);
    host = BeaconDataExtract(&parser, NULL);
    port = BeaconDataInt(&parser);

    char* port_status = is_port_open(host, port) ? "OPEN" : "FAILED";
    internal_printf("%s:%d %s", host, port, port_status);

    printoutput(TRUE);
    bofstop();
};
#else
int main(int argc, char** argv)
{
    is_port_open("127.0.0.1", 1);
    is_port_open("127.0.0.1", 445);
    return 0;
}
#endif
