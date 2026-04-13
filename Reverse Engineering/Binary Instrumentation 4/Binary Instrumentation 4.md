# Binary Instrumentation 4 #

## Overview ##

Difficulty: Hard

Category: [Reverse Engineering](../)

Tags: `#reverseengineering #windows #winapi #frida`

## Description ##

The executable was designed to send the flag to someone. 
Are you that someone? 
The binary can be downloaded here. 
Password to unlock: picoctf

## Approach ##

Initially running the `bin-ins.exe` challenge binary there appeared to be no output, but if left long enough a `"Connection failed."` console message appears and execution terminates.

Connection failure suggests sockets communications to me, so to confirm [frida-trace](https://frida.re/docs/frida-trace/) was used to trace the use of Winsock API calls (including the `W32_32.dll` import).

    D:\CTF\picoCTF-2026\Binary-Instrumentation-4> frida-trace -I WS2_32.dll ./bin-ins.exe
    Started tracing 191 functions. Web UI available at http://localhost:51583/
               /* TID 0x49c */
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
                    .
                    .
      (snip - lots of these WSAGetLastError() calls in output)
                    .
                    .
      2858 ms  WSAGetLastError()
      2858 ms  WSAGetLastError()
      2858 ms  WSAGetLastError()
      2858 ms  WSAStartup()
      2858 ms  socket()
      2858 ms     | WahOpenCurrentThread()
      2858 ms     | WSASocketW()
      2858 ms     |    | WahCreateHandleContextTable()
      2858 ms     |    | WahInsertHandleContext()
      2858 ms     |    | WahInsertHandleContext()
      2858 ms  ntohs()
      2858 ms  inet_pton()
      2858 ms  connect()
      2858 ms     | WahReferenceContextByHandle()
      2858 ms     | WahReferenceContextByHandle()
      2858 ms     | WahReferenceContextByHandle()
      2858 ms     | WahReferenceContextByHandle()
      Connection failed. 
      23924 ms  WSAGetLastError()

               /* TID 0x3704 */
     23988 ms  WSAGetLastError()
     23988 ms  WSAGetLastError()
     23988 ms  WSAGetLastError()
     23988 ms  WSAGetLastError()
               /* TID 0x1e2c */
     29987 ms  WSAGetLastError()
     29987 ms  WSAGetLastError()
     29987 ms  WSAGetLastError()
               /* TID 0x3edc */
     29987 ms  WSAGetLastError()
     29987 ms  WSAGetLastError()
     29987 ms  WSAGetLastError()
               /* TID 0x49c */
     30261 ms  WSAGetLastError()
     30261 ms  WSAGetLastError()
     30261 ms  closesocket()
     30261 ms     | WahReferenceContextByHandle()
     30261 ms     | WahRemoveHandleContext()
     30261 ms     | WahRemoveHandleContext()
     30261 ms  WSACleanup()
    Process terminated

Confirmed, we can see use of the typical socket network programming calls (`socket()`, `ntohs()`, `inet_pton()` and `connect()`). The first step in analysis is to instrument these API calls to work out where and how (protocol) the challenge binary is trying to connect.

Modified `frida-trace` script for `socket()` in `__handlers__\WS2_32.dll\socket.js`:

    /*
        SOCKET WSAAPI socket(
          [in] int af,
          [in] int type,
          [in] int protocol
        );
     */

    defineHandler({
      onEnter(log, args, state) {
        log('socket() - af=', args[0]);
        log('socket() - type=', args[1]);
        log('socket() - protocol=', args[2]);
      },

      onLeave(log, retval, state) {
        log('socket() - retval=', retval);
      }
    });

Modified script for `ntohs()` in `__handlers__\WS2_32.dll\ntohs.js`:

    /*
        u_short ntohs(
          [in] u_short netshort
        );
     */

    defineHandler({
      onEnter(log, args, state) {
        log('ntohs() - netshort=', args[0]);
      },

      onLeave(log, retval, state) {
        log('ntohs() - retval=', retval);
      }
    });

Modified script for `inet_pton()` in `__handlers__\WS2_32.dll\inet_pton.js`:

    /*
        INT WSAAPI inet_pton(
          [in]  INT   Family,
          [in]  PCSTR pszAddrString,
          [out] PVOID pAddrBuf
        );
     */

    defineHandler({
      onEnter(log, args, state) {
        log('inet_pton() - Family=', args[0]);
        log('inet_pton() - pszAddrString=', args[1].readCString());
      },

      onLeave(log, retval, state) {
        log('inet_pton() - retval=', retval);    
      }
    });

Modified script for `connect()` in `__handlers__\WS2_32.dll\connect.js`:

    /*
        int WSAAPI connect(
          [in] SOCKET         s,
          [in] const sockaddr *name,
          [in] int            namelen
        );

        struct sockaddr_in {
            short   sin_family;
            u_short sin_port;
            struct  in_addr sin_addr;
            char    sin_zero[8];
        };
     */

    defineHandler({
      onEnter(log, args, state) {
        log('connect() - s=', args[0]);
        log('connect() - *name:');
        log('    sin_family=', args[1].readShort());
        log('    sin_port=', args[1].add(2).readUShort());
        log('    sin_addr.S_addr=', args[1].add(4).readULong());
        log('connect() - namelen=', args[2]);
      },

      onLeave(log, retval, state) {
        log('connect() - retval=', retval);
      }
    });

For good measure, I also added the return value (error number) for `WSAGetLastError()` to help debug any invalid input to these API calls used by the challenge binary, as has been common theme for this CTF series.

    defineHandler({
      onEnter(log, args, state) {
        log('WSAGetLastError()');
      },

      onLeave(log, retval, state) {
        log('WSAGetLastError() - retval=', retval);
      }
    });

Running the challenge binary again through `frida-trace` shows the API call input parameters used:

    D:\CTF\picoCTF-2026\Binary-Instrumentation-4> frida-trace -I WS2_32.dll ./bin-ins.exe
    Started tracing 239 functions. Web UI available at http://localhost:52014/
               /* TID 0x4db0 */
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSAGetLastError() - retval= 0xbb
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSAGetLastError() - retval= 0xbb
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSAGetLastError() - retval= 0xbb
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSAGetLastError() - retval= 0x0
       316 ms  WSAGetLastError()
       316 ms  WSAGetLastError() - retval= 0x0
                        .
                        .
          (snip - lots of these WSAGetLastError() calls in output)
                        .
                        .   
       316 ms  WSAGetLastError()
       316 ms  WSAGetLastError() - retval= 0x0
       316 ms  WSAGetLastError()
       316 ms  WSAGetLastError() - retval= 0x0
       316 ms  WSAStartup()
       316 ms  socket() - af= 0x2
       316 ms  socket() - type= 0x1
       316 ms  socket() - protocol= 0x6
       316 ms     | WahOpenCurrentThread()
       316 ms     | WSASocketW()
       316 ms     |    | WahCreateHandleContextTable()
       316 ms     |    | WahInsertHandleContext()
       316 ms     |    | WahInsertHandleContext()
       316 ms  socket() - retval= 0x2a0
       316 ms  ntohs() - netshort= 0x268b
       316 ms  ntohs() - retval= 0x8b26
       316 ms  inet_pton() - Family= 0x2
       316 ms  inet_pton() - pszAddrString= 192.168.29.25
       316 ms  inet_pton() - retval= 0x1
       316 ms  connect() - s= 0x2a0
       316 ms  connect() - *name:
       316 ms      sin_family= 2
       316 ms      sin_port= 35622
       316 ms      sin_addr.S_addr= 421374144
       316 ms  connect() - namelen= 0x10
       316 ms     | WahReferenceContextByHandle()
       316 ms     | WahReferenceContextByHandle()
       316 ms     | WahReferenceContextByHandle()
       316 ms     | WahReferenceContextByHandle()
    Connection failed.
      2382 ms  connect() - retval= 0xffffffff
      2382 ms  WSAGetLastError()
      2382 ms  WSAGetLastError() - retval= 0x274d
      2383 ms  WSAGetLastError()
      2383 ms  WSAGetLastError() - retval= 0x274d
      2383 ms  WSAGetLastError()
      2384 ms  WSAGetLastError() - retval= 0x274d
      2384 ms  closesocket()
      2384 ms     | WahReferenceContextByHandle()
      2384 ms     | WahRemoveHandleContext()
      2384 ms     | WahRemoveHandleContext()
      2384 ms  WSACleanup()
    Process terminated

Analysing the output we can see from the `socket()` creation call we have a standard IPv4 TCP stream socket {`af=AF_INET(0x2), type=SOCK_STREAM(0x1), protocol=IPPROTO_TCP(0x6)}`. The socket (file descriptor) returned is confirmed as being used correctly in the `connect()` call later on.

The challenge binary appears to be using an incorrect conversion function for the port number of the destination address. `ntohs()` or Network to Host byte order, so should be factored in when noting the destination address. The input of `0x268b (9867)` converts to `0x8b26 (35,622)`.

`inet_pton()` provides the destination IP address (`192.168.29.25`) to go with this port number.

We can also confirm the IP address provided to `inet_pton()` matches the value in the `sin_addr.S_addr` for the `connect()` call. The displayed value of `421374144` is `0x191DA8C0` where each byte is an octet of the IP address = (`0x19)25 . (0x1D)29 . (0xA8)168 . (0xC0)192` to confirm no bugs in the `connect()` call parameters.

Given the `connect()` attempt fails, my next step was to give the challenge binary something to connect to. To expedite the process, I simply used [`tcpserver.c`](https://www.cs.cmu.edu/afs/cs/academic/class/15213-f99/www/class26/tcpserver.c), which accepts incoming connections, receives incoming data and echoes it back to the client. This was compiled and ran on a local machine.

Now, to redirect the challenge binary connection to my local `tcpserver`, I further modified the `inet_pton()` `frida-trace` script to rewrite the `pszAddrString` parameter to my target IP address.

    /*
        INT WSAAPI inet_pton(
          [in]  INT   Family,
          [in]  PCSTR pszAddrString,
          [out] PVOID pAddrBuf
        );
     */

    defineHandler({
      onEnter(log, args, state) {
        log('inet_pton() - Family=', args[0]);
        log('inet_pton() - pszAddrString=', args[1].readCString());

        // rewrite the pszAddrString parameter to use the IP address of our
        // local tcpserver
        const buf = Memory.allocUtf8String('192.168.1.111');
        this.buf = buf;
        args[1] = buf;
      },

      onLeave(log, retval, state) {
        log('inet_pton() - retval=', retval);    
      }
    });

With the `tcpserver` running and listening on port `9867`, I re-ran the challenge binary through `frida-trace`:

    D:\CTF\picoCTF-2026\Binary-Instrumentation-4> frida-trace -I WS2_32.dll ./bin-ins.exe
    Started tracing 239 functions. Web UI available at http://localhost:52014/
               /* TID 0x4db0 */
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSAGetLastError() - retval= 0xbb
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSAGetLastError() - retval= 0xbb
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSAGetLastError() - retval= 0xbb
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSAGetLastError() - retval= 0x0
       316 ms  WSAGetLastError()
       316 ms  WSAGetLastError() - retval= 0x0
                            .
                            .
              (snip - lots of these WSAGetLastError() calls in output)
                            .
                            . 
       316 ms  WSAGetLastError()
       316 ms  WSAGetLastError() - retval= 0x0
       316 ms  WSAGetLastError()
       316 ms  WSAGetLastError() - retval= 0x0
       309 ms  WSAStartup()
       309 ms  socket() - af= 0x2
       309 ms  socket() - type= 0x1
       309 ms  socket() - protocol= 0x6
       309 ms     | WahOpenCurrentThread()
       309 ms     | WSASocketW()
       309 ms     |    | WahCreateHandleContextTable()
       324 ms     |    | WahInsertHandleContext()
       324 ms     |    | WahInsertHandleContext()
       324 ms  socket() - retval= 0x2a0
       324 ms  ntohs() - netshort= 0x268b
       324 ms  ntohs() - retval= 0x8b26
       324 ms  inet_pton() - Family= 0x2
       324 ms  inet_pton() - pszAddrString= 192.168.29.25
       324 ms  inet_pton() - retval= 0x1
       324 ms  connect() - s= 0x2a0
       324 ms  connect() - *name:
       324 ms      sin_family= 2
       324 ms      sin_port= 35622
       324 ms      sin_addr.S_addr= 1862379712
       324 ms  connect() - namelen= 0x10
       324 ms     | WahReferenceContextByHandle()
       324 ms     | WahReferenceContextByHandle()
       324 ms     | WahReferenceContextByHandle()
       324 ms     | WahReferenceContextByHandle()
       324 ms  connect() - retval= 0x0
       324 ms  send()
       324 ms  recv()
       324 ms     | WahReferenceContextByHandle()
       324 ms  send()
       324 ms  closesocket()
       324 ms     | WahReferenceContextByHandle()
       324 ms     | WahRemoveHandleContext()
       324 ms     | WahRemoveHandleContext()
       324 ms  WSACleanup()
    Process terminated

With a successful connection, we can now see attempts to `send()` to and `recv()` from our `tcpserver`. Instrumenting the `send()` API call is the next step to analyse what the challenge binary trying to send out.

Modified script for `send()` in `__handlers__\WS2_32.dll\send.js`:

    /*
        int WSAAPI send(
          [in] SOCKET     s,
          [in] const char *buf,
          [in] int        len,
          [in] int        flags
        );
     */

    defineHandler({
      onEnter(log, args, state) {
        log('send() - s=', args[0]);
        log('send() - len=', args[2]);
        log('send() - flags=', args[3]);  
        log('send() - buf=', hexdump(args[1]));      
      },

      onLeave(log, retval, state) {
        log('send() - retval=', retval);    
      }
    });

The output from `frida-trace` now:

    D:\CTF\picoCTF-2026\Binary-Instrumentation-4> frida-trace -I WS2_32.dll ./bin-ins.exe
    Started tracing 239 functions. Web UI available at http://localhost:52014/
               /* TID 0x4db0 */
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSAGetLastError() - retval= 0xbb
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSAGetLastError() - retval= 0xbb
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSAGetLastError() - retval= 0xbb
       239 ms  WSASetLastError()
       239 ms  WSAGetLastError()
       239 ms  WSAGetLastError() - retval= 0x0
       316 ms  WSAGetLastError()
       316 ms  WSAGetLastError() - retval= 0x0
                            .
                            .
              (snip - lots of these WSAGetLastError() calls in output)
                            .
                            . 
       316 ms  WSAGetLastError()
       316 ms  WSAGetLastError() - retval= 0x0
       316 ms  WSAGetLastError()
       316 ms  WSAGetLastError() - retval= 0x0
       309 ms  WSAStartup()
       309 ms  socket() - af= 0x2
       309 ms  socket() - type= 0x1
       309 ms  socket() - protocol= 0x6
       309 ms     | WahOpenCurrentThread()
       309 ms     | WSASocketW()
       309 ms     |    | WahCreateHandleContextTable()
       324 ms     |    | WahInsertHandleContext()
       324 ms     |    | WahInsertHandleContext()
       324 ms  socket() - retval= 0x2a0
       324 ms  ntohs() - netshort= 0x268b
       324 ms  ntohs() - retval= 0x8b26
       324 ms  inet_pton() - Family= 0x2
       324 ms  inet_pton() - pszAddrString= 192.168.29.25
       324 ms  inet_pton() - retval= 0x1
       324 ms  connect() - s= 0x2a0
       324 ms  connect() - *name:
       324 ms      sin_family= 2
       324 ms      sin_port= 35622
       324 ms      sin_addr.S_addr= 1862379712
       324 ms  connect() - namelen= 0x10
       324 ms     | WahReferenceContextByHandle()
       324 ms     | WahReferenceContextByHandle()
       324 ms     | WahReferenceContextByHandle()
       324 ms     | WahReferenceContextByHandle()
       324 ms  connect() - retval= 0x0
       324 ms  send() - s= 0x2a0
       324 ms  send() - len= 0xe
       324 ms  send() - flags= 0x0
       324 ms  send() - buf=              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
    ac9ceff700  45 6e 74 65 72 20 74 68 65 20 6b 65 79 3a 00 00  Enter the key:..
    ac9ceff710  20 f7 ef 9c ac 00 00 00 0b 00 00 00 00 00 00 00   ...............
    ac9ceff720  6b 65 79 65 66 62 30 33 37 66 37 00 fe 7f 00 00  keyefb037f7.....
    ac9ceff730  01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    ac9ceff740  e0 c4 40 00 00 00 00 00 40 00 00 00 00 00 00 00  ..@.....@.......
    ac9ceff750  10 00 00 00 00 00 00 00 c0 00 b8 57 e7 01 00 00  ...........W....
    ac9ceff760  a0 02 00 00 00 00 00 00 29 15 40 00 8b 26 00 00  ........).@..&..
    ac9ceff770  01 30 4b 00 00 00 00 00 0e 00 00 00 00 00 00 00  .0K.............
    ac9ceff780  90 18 c3 56 e7 01 00 00 01 00 00 00 00 00 00 00  ...V............
    ac9ceff790  00 00 00 00 00 00 00 00 b4 13 40 00 00 00 00 00  ..........@.....
    ac9ceff7a0  00 00 00 00 00 00 00 00 0e 00 00 00 00 00 00 00  ................
    ac9ceff7b0  58 f4 4d 00 00 00 00 00 cf 2a d1 3b fe 7f 00 00  X.M......*.;....
    ac9ceff7c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    ac9ceff7d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    ac9ceff7e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    ac9ceff7f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
       324 ms  send() - retval= 0xe
       324 ms  recv()
       324 ms     | WahReferenceContextByHandle()
       324 ms  send() - s= 0x2a0
       324 ms  send() - len= 0x9
       324 ms  send() - flags= 0x0
       324 ms  send() - buf=              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
    ac9ceff310  57 72 6f 6e 67 20 6b 65 79 00 4b 00 00 00 00 00  Wrong key.K.....
    ac9ceff320  30 f3 ef 9c ac 00 00 00 0d 00 00 00 00 00 00 00  0...............
    ac9ceff330  45 6e 74 65 72 20 74 68 65 20 6b 65 79 00 00 00  Enter the key...
    ac9ceff340  45 6e 74 65 72 20 74 68 65 20 6b 65 79 00 00 00  Enter the key...
    ac9ceff350  90 fe 4b 00 00 00 00 00 02 70 7c 39 fe 7f 00 00  ..K......p|9....
    ac9ceff360  00 25 4b 00 00 00 00 00 cb 07 80 39 fe 7f 00 00  .%K........9....
    ac9ceff370  ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    ac9ceff380  99 10 22 58 e5 4c 00 00 00 00 00 00 00 00 00 00  .."X.L..........
    ac9ceff390  ff 00 00 00 00 00 00 00 7a aa 51 3a fe 7f 00 00  ........z.Q:....
    ac9ceff3a0  00 00 00 00 00 00 00 00 6e f4 ef 9c ac 00 00 00  ........n.......
    ac9ceff3b0  01 00 00 00 01 00 00 00 40 06 4b 00 00 00 00 00  ........@.K.....
    ac9ceff3c0  40 00 4b 00 00 00 00 00 bb 97 49 00 00 00 00 00  @.K.......I.....
    ac9ceff3d0  51 ab 57 b1 a6 c0 00 00 00 00 00 00 00 00 00 00  Q.W.............
    ac9ceff3e0  7f 00 00 00 00 00 00 00 a0 0c 4b 00 00 00 00 00  ..........K.....
    ac9ceff3f0  10 00 00 00 00 00 00 00 95 5c 4a 00 00 00 00 00  .........\J.....
    ac9ceff400  40 00 4b 00 00 00 00 00 bb 97 49 00 00 00 00 00  @.K.......I.....
       324 ms  send() - retval= 0x9
       324 ms  closesocket()
       324 ms     | WahReferenceContextByHandle()
       324 ms     | WahRemoveHandleContext()
       324 ms     | WahRemoveHandleContext()
       324 ms  WSACleanup()
    Process terminated

We can see the challenge binary is requesting the server respond with a `"key"`. The `tcpserver` currently echoes back what it received, resulting in the challenge binary responding with `"Wrong key."`.

_(note: an interesting thing to observe in the capture above is that we have inadvertanly leaked the expected `"key"`, as the default `hexdump()` length has dumped beyond the length of the send buffer and dumped the key `"keyefb037f7"`, but we will continue with `frida`...)_

The response from the server could be compared with the expected key using a number of methods, but by adding `-i *Compare*` to `frida-trace` command we can determine the challenge binary is using `CompareStringA()` API call. So, we can hook and modify this call to always return an equal response to trick the challenge binary.

Modified script for `CompareStringA()` in `__handlers__\KERNEL32.DLL\CompareStringA.js`:

    /*
        int CompareStringA(
          [in] LCID   Locale,
          [in] DWORD  dwCmpFlags,
          [in] PCNZCH lpString1,
          [in] int    cchCount1,
          [in] PCNZCH lpString2,
          [in] int    cchCount2
        );
     */

    defineHandler({
      onEnter(log, args, state) {
        log('CompareStringA() - lpString1=', args[2].readCString());
        log('CompareStringA() - lpString2=', args[4].readCString());

        // rewrite String1 to point to the same string as String2,
        // therefore always evaluating as equal
        args[2] = args[4];
      },

      onLeave(log, retval, state) {
      }
    });

Running again through `frida-trace` with the latest version of the scripts:

    D:\CTF\picoCTF-2026\Binary-Instrumentation-4> frida-trace -i *Compare* -I WS2_32.dll ./bin-ins.exe
    Started tracing 239 functions. Web UI available at http://localhost:51994/
               /* TID 0x44c8 */
       225 ms  WSASetLastError()
       225 ms  WSAGetLastError()
       225 ms  WSAGetLastError() - retval= 0xbb
       225 ms  WSASetLastError()
       225 ms  WSAGetLastError()
       225 ms  WSAGetLastError() - retval= 0xbb
       225 ms  WSASetLastError()
       225 ms  WSAGetLastError()
       225 ms  WSAGetLastError() - retval= 0xbb
       225 ms  WSASetLastError()
       225 ms  WSAGetLastError()
       225 ms  WSAGetLastError() - retval= 0x0
       292 ms  WSAGetLastError()
       292 ms  WSAGetLastError() - retval= 0x0
                                .
                                .
                  (snip - lots of these WSAGetLastError() calls in output)
                                .
                                . 
       292 ms  WSAGetLastError()
       292 ms  WSAGetLastError() - retval= 0x0
       292 ms  WSAGetLastError()
       292 ms  WSAGetLastError() - retval= 0x0
       292 ms  WSAStartup()
       292 ms  socket() - af= 0x2
       292 ms  socket() - type= 0x1
       292 ms  socket() - protocol= 0x6
       292 ms     | WahOpenCurrentThread()
       292 ms     | WSASocketW()
       292 ms     |    | WahCreateHandleContextTable()
       292 ms     |    | WahInsertHandleContext()
       292 ms     |    | WahInsertHandleContext()
       292 ms  socket() - retval= 0x288
       292 ms  ntohs() - netshort= 0x268b
       292 ms  ntohs() - retval= 0x8b26
       292 ms  inet_pton() - Family= 0x2
       292 ms  inet_pton() - pszAddrString= 192.168.29.25
       292 ms  inet_pton() - retval= 0x1
       292 ms  connect() - s= 0x288
       292 ms  connect() - *name:
       292 ms      sin_family= 2
       292 ms      sin_port= 35622
       292 ms      sin_addr.S_addr= 1862379712
       292 ms  connect() - namelen= 0x10
       292 ms     | WahReferenceContextByHandle()
       292 ms     | WahReferenceContextByHandle()
       292 ms     | WahReferenceContextByHandle()
       292 ms     | WahReferenceContextByHandle()
       292 ms  connect() - retval= 0x0
       292 ms  send() - s= 0x288
       292 ms  send() - len= 0xe
       292 ms  send() - flags= 0x0
       292 ms  send() - buf=              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
    4863aff670  45 6e 74 65 72 20 74 68 65 20 6b 65 79 3a 00 00  Enter the key:..
    4863aff680  90 f6 af 63 48 00 00 00 0b 00 00 00 00 00 00 00  ...cH...........
    4863aff690  6b 65 79 65 66 62 30 33 37 66 37 00 fe 7f 00 00  keyefb037f7.....
    4863aff6a0  01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    4863aff6b0  e0 c4 40 00 00 00 00 00 40 00 00 00 00 00 00 00  ..@.....@.......
    4863aff6c0  10 00 00 00 00 00 00 00 c0 40 00 07 05 02 00 00  .........@......
    4863aff6d0  88 02 00 00 00 00 00 00 29 15 40 00 8b 26 00 00  ........).@..&..
    4863aff6e0  01 30 4b 00 00 00 00 00 0e 00 00 00 00 00 00 00  .0K.............
    4863aff6f0  90 18 14 06 05 02 00 00 01 00 00 00 00 00 00 00  ................
    4863aff700  00 00 00 00 00 00 00 00 b4 13 40 00 00 00 00 00  ..........@.....
    4863aff710  00 00 00 00 00 00 00 00 0e 00 00 00 00 00 00 00  ................
    4863aff720  58 f4 4d 00 00 00 00 00 cf 2a d1 3b fe 7f 00 00  X.M......*.;....
    4863aff730  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    4863aff740  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    4863aff750  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    4863aff760  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
       292 ms  send() - retval= 0xe
       292 ms  recv()
       292 ms     | WahReferenceContextByHandle()
       307 ms  CompareStringA() - lpString1= Enter the key
       307 ms  CompareStringA() - lpString2= keyefb037f7
       307 ms     | CompareStringA()
       307 ms  send() - s= 0x288
       307 ms  send() - len= 0x5b
       307 ms  send() - flags= 0x0
       307 ms  send() - buf=               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
    205061466a0  43 6f 6e 67 72 61 74 75 6c 61 74 69 6f 6e 73 21  Congratulations!
    205061466b0  20 48 65 72 65 27 73 20 79 6f 75 72 20 66 6c 61   Here's your fla
    205061466c0  67 3a 0a 63 47 6c 6a 62 30 4e 55 52 6e 74 75 4d  g:.cGljb0NURntuM
    205061466d0  33 52 33 4d 48 4a 72 58 7a 46 7a 58 7a 52 51 4d  3R3MHJrXzFzXzRQM
    205061466e0  58 4e 66 4e 46 4e 66 56 7a 4d 78 4d 56 39 6c 5a  XNfNFNfVzMxMV9lZ
    205061466f0  6d 49 77 4d 7a 64 6d 4e 33 30 4b 00 00 00 00 00  mIwMzdmN30K.....
    20506146700  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    20506146710  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    20506146720  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    20506146730  00 00 00 00 00 00 00 00 1a 07 97 7d 67 90 00 00  ...........}g...
    20506146740  90 24 72 06 05 02 00 00 20 66 14 06 05 02 00 00  .$r..... f......
    20506146750  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    20506146760  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    20506146770  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    20506146780  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    20506146790  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
       307 ms  send() - retval= 0x5b
       307 ms  closesocket()
       307 ms     | WahReferenceContextByHandle()
       307 ms     | WahRemoveHandleContext()
       307 ms     | WahRemoveHandleContext()
       307 ms  WSACleanup()
    Process terminated

And there we have it! The second `send()` call contains the base64 encoded flag `cGljb0NURntuM3R3MHJrXzFzXzRQMXNfNFNfVzMxMV9lZmIwMzdmN30K`.

## Solution ##

The critical `frida-trace` scripts (i.e. those that modify calls) to arrive to the solution are presented above in the approach description, these include hooks for:
- `inet_pton()`
- `CompareStringA()`

All other scripts were for instrumentation purposes to assist with arriving to the above solution.

The flag is dropped in the created output file and base64 encoded.

    $ echo "cGljb0NURntuM3R3MHJrXzFzXzRQMXNfNFNfVzMxMV9lZmIwMzdmN30K" | base64 -d 
    picoCTF{...........redacted.............}

Where the actual flag value has been redacted for the purposes of this write up.

## Notes ##

For my write ups of the previous _Binary Instrumentation_ challenges refer:
- [picoCTF-2025](https://github.com/snwau/picoCTF-2025-Writeup):
  - [Binary Instrumentation 1](https://github.com/snwau/picoCTF-2025-Writeup/blob/main/Reverse%20Engineering/Binary%20Instrumentation%201/Binary%20Instrumentation%201.md) 
  - [Binary Instrumentation 2](https://github.com/snwau/picoCTF-2025-Writeup/blob/main/Reverse%20Engineering/Binary%20Instrumentation%202/Binary%20Instrumentation%202.md)
- [picoCTF-2026](https://github.com/snwau/picoCTF-2026-Writeup):
  - [Binary Instrumentation 3](../Binary%20Instrumentation%203/Binary%20Instrumentation%203.md)
