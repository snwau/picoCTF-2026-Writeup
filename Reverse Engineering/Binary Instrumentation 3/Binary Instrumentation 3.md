# Binary Instrumentation 3 #

## Overview ##

Difficulty: Hard

Category: [Reverse Engineering](../)

Tags: `#reverseengineering #windows #winapi #frida #ioredirection`

## Description ##

The executable was designed to write the flag but it seems like I messed up few things on the way? Can use find a way to get it to work? 
The binary can be downloaded here. 
Password to unlock: picoctf

## Approach ##

A returning series from [picoCTF-2025](https://github.com/snwau/picoCTF-2025-Writeup), I'll be using techniques first learnt from [Binary Instrumentation 1](https://github.com/snwau/picoCTF-2025-Writeup/blob/main/Reverse%20Engineering/Binary%20Instrumentation%201/Binary%20Instrumentation%201.md) and [Binary Instrumentation 2](https://github.com/snwau/picoCTF-2025-Writeup/blob/main/Reverse%20Engineering/Binary%20Instrumentation%202/Binary%20Instrumentation%202.md), for which I have write ups.

Running the challenge binary from a Microsoft Windows command prompt we get the following console output:

    D:\CTF\picoCTF-2026\Binary-Instrumentation-3>bin-ins.exe
    [+] Let me get started!
    [!] Failed to open output file.

Straight away the mention of file output suggests using [frida-trace](https://frida.re/docs/frida-trace/) to trace the use of file API calls.

    D:\CTF\picoCTF-2026\Binary-Instrumentation-3>frida-trace -i *File* -f bin-ins.exe
    Started tracing 558 functions. Web UI available at http://localhost:55829/
               /* TID 0x1e74 */
      9443 ms  NtDeviceIoControlFile()
      9848 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      9848 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      9848 ms  RtlDosApplyFileIsolationRedirection_Ustr()
    [+] Let me get started!
      9848 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      9848 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      9848 ms  RtlDosApplyFileIsolationRedirection_Ustr()

    [!] Failed to open output file.
      9907 ms  GetSystemTimeAsFileTime()
      9907 ms     | GetSystemTimeAsFileTime()
      9907 ms  GetModuleFileNameA()
      9907 ms     | GetModuleFileNameA()
      9907 ms     |    | GetModuleFileNameW()
      9909 ms     |    |    | GetModuleFileNameW()
      9909 ms  WriteFile()
      9909 ms     | WriteFile()
      9909 ms  WriteFile()
      9909 ms     | WriteFile()
      9909 ms  WriteFile()
      9909 ms     | WriteFile()
      9909 ms  CreateFileA()
      9909 ms     | CreateFileA()
      9909 ms  WriteFile()
      9909 ms     | WriteFile()
      9909 ms  WriteFile()
      9909 ms     | WriteFile()
      9909 ms  WriteFile()
      9909 ms     | WriteFile()
    Process terminated

Given the error message is `"Failed to open output file."`, this would suggest `CreateFileA()` should be our first API call to investigate further.

Modifying the auto-generated Javascript created by [frida-trace](https://frida.re/docs/frida-trace/) for the `CreateFileA()` API call within `__handlers__\KERNEL32.DLL\CreateFileA.js` of the current working directory. I added log output for some of the important input parameters in `onEnter()` and the return value from the call in `onLeave`

    /*
        WIN API function signature:

        HANDLE CreateFileA(
          [in]           LPCSTR                lpFileName,
          [in]           DWORD                 dwDesiredAccess,
          [in]           DWORD                 dwShareMode,
          [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
          [in]           DWORD                 dwCreationDisposition,
          [in]           DWORD                 dwFlagsAndAttributes,
          [in, optional] HANDLE                hTemplateFile
        );
    */

    defineHandler({
      onEnter(log, args, state) {
        log('CreateFileA() - lpFileName = ', args[0].readCString());
      },

      onLeave(log, retval, state) {
        log('CreateFileA() - retVal = ', retval);
      }
    });

Running again to check our new log output:

    D:\CTF\picoCTF-2026\Binary-Instrumentation-3>frida-trace -i *File* -f bin-ins.exe
    Started tracing 558 functions. Web UI available at http://localhost:56813/
               /* TID 0x3170 */
      1205 ms  NtDeviceIoControlFile()
    [+] Let me get started!
    [!] Failed to open output file.
      1288 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1288 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1288 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1289 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1289 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1290 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1302 ms  GetSystemTimeAsFileTime()
      1302 ms     | GetSystemTimeAsFileTime()
      1302 ms  GetModuleFileNameA()
      1302 ms     | GetModuleFileNameA()
      1302 ms     |    | GetModuleFileNameW()
      1302 ms     |    |    | GetModuleFileNameW()
      1302 ms  WriteFile()
      1302 ms     | WriteFile()
      1303 ms  WriteFile()
      1303 ms     | WriteFile()
      1303 ms  WriteFile()
      1303 ms     | WriteFile()
      1303 ms  CreateFileA()
      1303 ms     | CreateFileA() - lpFileName =  C:\random\output_flag.txt
      1303 ms  CreateFileA() - retVal =  0xffffffffffffffff
      1304 ms  WriteFile()
      1304 ms     | WriteFile()
      1304 ms  WriteFile()
      1304 ms     | WriteFile()
      1305 ms  WriteFile()
      1305 ms     | WriteFile()
    Process terminated

Ok, we the challenge binary is attempting to create a file at `C:\random\output_flag.txt`, this path does not exist on my machine, which correlates with the `-1` return value. Now we have two options; create the `C:\random` folder, or use the `frida` hook and modify the `lpFileName` input parameters (which is what I did).

The `CreateFileA.js` script now becomes:

    /*
        WIN API function signature:

        HANDLE CreateFileA(
          [in]           LPCSTR                lpFileName,
          [in]           DWORD                 dwDesiredAccess,
          [in]           DWORD                 dwShareMode,
          [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
          [in]           DWORD                 dwCreationDisposition,
          [in]           DWORD                 dwFlagsAndAttributes,
          [in, optional] HANDLE                hTemplateFile
        );
    */

    defineHandler({
      onEnter(log, args, state) {
        log('CreateFileA() - lpFileName = ', args[0].readCString());
        // rewrite the lpFileName parameter with a valid path
        const buf = Memory.allocUtf8String('flag.txt');
        this.buf = buf;
        args[0] = buf;
      },

      onLeave(log, retval, state) {
        log('CreateFileA() - retVal = ', retval);
      }
    });

Running again we should expect the output file to be created in the current working directory:

    D:\CTF\picoCTF-2026\Binary-Instrumentation-3>frida-trace -i *File* -f bin-ins.exe
    Started tracing 558 functions. Web UI available at http://localhost:56823/
    [+] Let me get started!
               /* TID 0xb94 */
       338 ms  NtDeviceIoControlFile()
       407 ms  RtlDosApplyFileIsolationRedirection_Ustr()
       407 ms  RtlDosApplyFileIsolationRedirection_Ustr()
       407 ms  RtlDosApplyFileIsolationRedirection_Ustr()
       407 ms  RtlDosApplyFileIsolationRedirection_Ustr()
       407 ms  RtlDosApplyFileIsolationRedirection_Ustr()
       407 ms  RtlDosApplyFileIsolationRedirection_Ustr()
    [!] I didn't work!
       423 ms  GetSystemTimeAsFileTime()
       423 ms     | GetSystemTimeAsFileTime()
       423 ms  GetModuleFileNameA()
       423 ms     | GetModuleFileNameA()
       423 ms     |    | GetModuleFileNameW()
       423 ms     |    |    | GetModuleFileNameW()
       423 ms  WriteFile()
       423 ms     | WriteFile()
       423 ms  WriteFile()
       423 ms     | WriteFile()
       423 ms  WriteFile()
       423 ms     | WriteFile()
       423 ms  CreateFileA()
       423 ms     | CreateFileA() - lpFileName =  C:\random\output_flag.txt
       423 ms  CreateFileA() - retVal =  0xf8
       423 ms  GetFileAttributesW()
       423 ms     | GetFileAttributesW()
       423 ms  WriteFile()
       423 ms     | WriteFile()
       423 ms  WriteFile()
       423 ms     | WriteFile()
       423 ms  WriteFile()
       423 ms     | WriteFile()
    Process terminated

The return value is no longer `-1` indicating success, with the value being the `HANDLE` (file descriptor) of the created file. We also see the challenge binary output has changed to now report `"[!] I didn't work!"`.

Confirmed the creation of the file and inspecting its contents we see:

    D:\CTF\picoCTF-2026\Binary-Instrumentation-3>type flag.txt
    The handle is invalid.

Not quite what we expected. But notice in the `frida-trace` output there is now another `*File*` API call being made after the `CreateFileA()`, a call to `GetFileAttriutesW()`.

Instrumenting the `frida` javascript hook for this API call `__handlers__\KERNEL32.DLL\GetFileAttributesW.js` to work out what it is trying to do, nothing that this is a `W` version of the API call (meaning Wide character support, so we need to make sure we read the string in the right format).

    /*
        DWORD GetFileAttributesW(
          [in] LPCWSTR lpFileName
        );
    */

    defineHandler({
      onEnter(log, args, state) {
        log('GetFileAttributesW() - lpFileName = ', args[0].readUtf16String());
      },

      onLeave(log, retval, state) {
        log('GetFileAttributesW() - retVal = ', retval);
      }
    });

Running again we see something interesting, the `lpFileName` string refers to `C:\Windows\SYSTEM32\cmd.exe`, it seems like the challenge binary is possibly trying to run something?

    D:\CTF\picoCTF-2026\Binary-Instrumentation-3>frida-trace -i *File* -f bin-ins.exe
    Started tracing 1319 functions. Web UI available at http://localhost:58244/
               /* TID 0x1978 */
      1325 ms  NtDeviceIoControlFile()
      1376 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1376 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1376 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1376 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1376 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1376 ms  RtlDosApplyFileIsolationRedirection_Ustr()
    [+] Let me get started!
    [!] I didn't work!
      1391 ms  GetSystemTimeAsFileTime()
      1391 ms     | GetSystemTimeAsFileTime()
      1391 ms  GetModuleFileNameA()
      1391 ms     | GetModuleFileNameA()
      1391 ms     |    | GetModuleFileNameW()
      1391 ms     |    |    | GetModuleFileNameW()
      1391 ms  WriteFile()
      1391 ms     | WriteFile()
      1391 ms  WriteFile()
      1391 ms     | WriteFile()
      1391 ms  WriteFile()
      1391 ms     | WriteFile()
      1391 ms  CreateFileA()
      1391 ms     | CreateFileA() - lpFileName =  C:\random\output_flag.txt
      1404 ms  CreateFileA() - retVal =  0x28c
      1404 ms  GetFileAttributesW()
      1404 ms     | GetFileAttributesW() - lpFileName =  C:\Windows\SYSTEM32\cmd.exe
      1404 ms  GetFileAttributesW() - retVal =  0x20
      1404 ms  WriteFile()
      1404 ms     | WriteFile()
      1404 ms  WriteFile()
      1404 ms     | WriteFile()
      1404 ms  WriteFile()
      1404 ms     | WriteFile()
    Process terminated

With this hunch in mind, the `frida-trace` was expanded to include API calls that matched the `*Process*` pattern also, with the assumption `CreateProcess` type function would be called.

    D:\CTF\picoCTF-2026\Binary-Instrumentation-3>frida-trace -i *File* -i *Process* -f bin-ins.exe
    Started tracing 1319 functions. Web UI available at http://localhost:58244/
               /* TID 0x1978 */
      1325 ms  NtDeviceIoControlFile()
      1376 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1376 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1376 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1376 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1376 ms  RtlDosApplyFileIsolationRedirection_Ustr()
      1376 ms  RtlDosApplyFileIsolationRedirection_Ustr()
    [+] Let me get started!
    [!] I didn't work!
      1391 ms  GetSystemTimeAsFileTime()
      1391 ms     | GetSystemTimeAsFileTime()
      1391 ms  GetModuleFileNameA()
      1391 ms     | GetModuleFileNameA()
      1391 ms     |    | GetModuleFileNameW()
      1391 ms     |    |    | GetModuleFileNameW()
      1391 ms  WriteFile()
      1391 ms     | WriteFile()
      1391 ms  WriteFile()
      1391 ms     | WriteFile()
      1391 ms  WriteFile()
      1391 ms     | WriteFile()
      1391 ms  CreateFileA()
      1391 ms     | CreateFileA() - lpFileName =  C:\random\output_flag.txt
      1404 ms  CreateFileA() - retVal =  0x28c
      1404 ms  CreateProcessA()
      1404 ms     | CreateProcessA()
      1404 ms     |    | CreateProcessInternalA()
      1404 ms     |    |    | CreateProcessInternalW()
      1404 ms     |    |    |    | BasepReleaseSxsCreateProcessUtilityStruct()
      1404 ms     |    |    |    | GetFileAttributesW()
      1404 ms     |    |    |    |    | GetFileAttributesW() - lpFileName =  C:\Windows\SYSTEM32\cmd.exe
      1404 ms     |    |    |    | GetFileAttributesW() - retVal =  0x20
      1404 ms     |    |    |    | BasepConstructSxsCreateProcessMessage()
      1404 ms     |    |    |    | BasepReleaseSxsCreateProcessUtilityStruct()
      1404 ms  WriteFile()
      1404 ms     | WriteFile()
      1404 ms  WriteFile()
      1404 ms     | WriteFile()
      1404 ms  WriteFile()
      1404 ms     | WriteFile()
    Process terminated

Confirmed, the `__handlers__\KERNEL32.DLL\CreateProcessA.js` script was then modified to instrument the call (after many iterations, increasing the amount of instrumentation until I arrived at the following):

    /*
        BOOL CreateProcessA(
          [in, optional]      LPCSTR                lpApplicationName,
          [in, out, optional] LPSTR                 lpCommandLine,
          [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
          [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
          [in]                BOOL                  bInheritHandles,
          [in]                DWORD                 dwCreationFlags,
          [in, optional]      LPVOID                lpEnvironment,
          [in, optional]      LPCSTR                lpCurrentDirectory,
          [in]                LPSTARTUPINFOA        lpStartupInfo,
          [out]               LPPROCESS_INFORMATION lpProcessInformation
        );

        typedef struct _STARTUPINFOA {      // (size : offset)
          DWORD  cb;                        // 4 : 0 (followed by padding)
          LPSTR  lpReserved;                // 8 : 8
          LPSTR  lpDesktop;                 // 8 : 16
          LPSTR  lpTitle;                   // 8 : 24
          DWORD  dwX;                       // 4 : 32
          DWORD  dwY;                       // 4 : 36
          DWORD  dwXSize;                   // 4 : 40
          DWORD  dwYSize;                   // 4 : 44
          DWORD  dwXCountChars;             // 4 : 48
          DWORD  dwYCountChars;             // 4 : 52
          DWORD  dwFillAttribute;           // 4 : 56
          DWORD  dwFlags;                   // 4 : 60
          WORD   wShowWindow;               // 2 : 64
          WORD   cbReserved2;               // 2 : 66 (followed by padding)
          LPBYTE lpReserved2;               // 8 : 72
          HANDLE hStdInput;                 // 8 : 80
          HANDLE hStdOutput;                // 8 : 88
          HANDLE hStdError;                 // 8 : 96
        } STARTUPINFOA, *LPSTARTUPINFOA;
    */

    defineHandler({
      onEnter(log, args, state) {
        log('CreateProcessA() - lpApplicationName = ', args[0].readCString());
        log('CreateProcessA() - lpCommandLine = ', args[1].readCString());

        log('CreateProcessA() - bInheritHandles = ', args[4]);
        log('CreateProcessA() - dwCreationFlags = ', args[5]);

        log('CreateProcessA() - lpCurrentDirectory = ', args[7].readCString());    
        log('CreateProcessA() - lpStartupInfo = ', args[8]);

        log('CreateProcessA() -    cb=', args[8].readInt());
        log('CreateProcessA() -    lpReserved=', args[8].add(8).readCString());
        log('CreateProcessA() -    lpDesktop=', args[8].add(16).readCString());
        log('CreateProcessA() -    lpTitle=', args[8].add(24).readCString());
        log('CreateProcessA() -    dwX=', args[8].add(32).readInt());
        log('CreateProcessA() -    dwY=', args[8].add(36).readInt());
        log('CreateProcessA() -    dwXSize=', args[8].add(40).readInt());
        log('CreateProcessA() -    dwYSize=', args[8].add(44).readInt());

        log('CreateProcessA() -    dwFlags=', args[8].add(60).readInt());    

        log('CreateProcessA() -    hStdInput=', args[8].add(80).readU64());
        log('CreateProcessA() -    hStdOutput=', args[8].add(88).readU64());
        log('CreateProcessA() -    hStdError=', args[8].add(96).readU64());            

        log('CreateProcessA() -    raw=', hexdump(args[8]));

        log('CreateProcessA() - lpProcessInformation = ', args[9]);    
      },

      onLeave(log, retval, state) {
        log('CreateProcessA() - retVal = ', retval);   
      }
    });

The `hexdump()` log output was used to confirm the offset of the elements of the `STARTUPINFOA` data structure, given padding, etc. The individual elements of the structure identified with surrounding `[]` below:

    STARTUPINFOA cb=0x68 (104)
    8efeaff730 [68 00  00 00] 00 00 00 00 [00 00 00 00  00 00 00 00] h...............
    8efeaff740 [00 00  00 00  00 00 00 00][00 00 00 00  00 00 00 00]  ................
    8efeaff750 [00 00  00 00][00 00 00 00][00 00 00 00][00 00 00 00]  ................
    8efeaff760 [00 00  00 00][00 00 00 00][00 00 00 00][00 01 00 00]  ................
    8efeaff770 [00 00][00 00] 00 00 00 00 [00 00 00 00  00 00 00 00]  ................
    8efeaff780 [00 00  00 00  00 00 00 00][0a 00 00 00  00 00 00 00]  ................
    8efeaff790 [74 02  00 00  00 00 00 00]

Running `frida-trace` now yields:

    D:\CTF\picoCTF-2026\Binary-Instrumentation-3>frida-trace -i *CreateFile* -i *CreateProcess* .\bin-ins.exe
    Started tracing 53 functions. Web UI available at http://localhost:50338/
    [+] Let me get started!
    [!] I didn't work!
               /* TID 0xa98 */
       153 ms  CreateFileA() - lpFileName =  C:\random\output_flag.txt
       169 ms     | CreateFileA() - retVal =  0xf8
       169 ms  CreateProcessA() - lpApplicationName =
       169 ms  CreateProcessA() - lpCommandLine =  cmd.exe /c echo testing if redirection works
       169 ms  CreateProcessA() - bInheritHandles =  0x1
       169 ms  CreateProcessA() - dwCreationFlags =  0x0
       169 ms  CreateProcessA() - lpCurrentDirectory =
       169 ms  CreateProcessA() - lpStartupInfo =  0x7e260ffb40
       169 ms  CreateProcessA() -    cb= 104
       169 ms  CreateProcessA() -    lpReserved=
       169 ms  CreateProcessA() -    lpDesktop=
       169 ms  CreateProcessA() -    lpTitle=
       169 ms  CreateProcessA() -    dwX= 0
       169 ms  CreateProcessA() -    dwY= 0
       169 ms  CreateProcessA() -    dwXSize= 0
       169 ms  CreateProcessA() -    dwYSize= 0
       169 ms  CreateProcessA() -    dwFlags= 256
       169 ms  CreateProcessA() -    hStdInput= 0
       169 ms  CreateProcessA() -    hStdOutput= 10
       169 ms  CreateProcessA() -    hStdError= 248
       169 ms  CreateProcessA() -    raw=              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
    7e260ffb40  68 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  h...............
    7e260ffb50  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    7e260ffb60  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    7e260ffb70  00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00  ................
    7e260ffb80  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    7e260ffb90  00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00  ................
    7e260ffba0  f8 00 00 00 00 00 00 00 e8 f5 4a 00 00 00 00 00  ..........J.....
    7e260ffbb0  20 66 2f 9b 99 01 00 00 2c 00 00 00 00 00 00 00   f/.....,.......
    7e260ffbc0  2c 00 00 00 00 00 00 00 86 aa 50 3a fe 7f 00 00  ,.........P:....
    7e260ffbd0  18 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    7e260ffbe0  01 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ........@.......
    7e260ffbf0  10 00 00 00 00 00 00 00 c0 f0 0e 9c 99 01 00 00  ................
    7e260ffc00  60 18 2f 9b 99 01 00 00 29 15 40 00 00 00 00 00  `./.....).@.....
    7e260ffc10  f8 00 00 00 00 00 00 00 0e 00 00 00 00 00 00 00  ................
    7e260ffc20  01 00 00 00 00 00 00 00 90 18 2f 9b 99 01 00 00  ........../.....
    7e260ffc30  00 00 00 00 00 00 00 00 b4 13 40 00 00 00 00 00  ..........@.....
       169 ms  CreateProcessA() - lpProcessInformation =  0x7e260ffb20
       169 ms     | CreateProcessA()
       169 ms     |    | CreateProcessInternalA()
       169 ms     |    |    | CreateProcessInternalW()
       169 ms     |    |    |    | BasepReleaseSxsCreateProcessUtilityStruct()
       169 ms     |    |    |    | BasepConstructSxsCreateProcessMessage()
       169 ms     |    |    |    | BasepReleaseSxsCreateProcessUtilityStruct()
       169 ms  CreateProcessA() - retVal =  0x1
    Process terminated

Here we note in the `lpCommandLine` that the challenge binary is trying to do something with Input/Output (IO) redirection with the command being `cmd.exe /c echo testing if redirection works`, which mustn't be working as desired given the `"[!] I didn't work!"` console message.

For redirection to work a number of parameters to the `CreateProcessA()` call must be set correctly:
- `bInheritHandles` must be true, to allow inheritable handles from the parent process to be inherited by this process.
- `lpStartupInfo->dwFlags` must have `STARTF_USESTDHANDLES` (`0x100`) set to specify the use of the standard I/O handle parameters (`hStdInput`, `hStdOutput` and `hStdError`).
- `lpStartupInfo->{hStdInput, hStdOutput and hStdError}` handles to use for Standard Input, Standard Output and Standard Error for the process being created.

From the above output, we can see `bInheritHandles` is non-zero, so configured correctly, as is `lpStartupInfo->dwFlags`.

However `hStdInput, hStdOutput and hStdError` do not look correct. `hStdError` is the handle from the file created earlier, this is likely meant to be `hStdOutput` instead. Updating the `frida-trace` hook script to re-write this parameter to test:

    /*
        BOOL CreateProcessA(
          [in, optional]      LPCSTR                lpApplicationName,
          [in, out, optional] LPSTR                 lpCommandLine,
          [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
          [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
          [in]                BOOL                  bInheritHandles,
          [in]                DWORD                 dwCreationFlags,
          [in, optional]      LPVOID                lpEnvironment,
          [in, optional]      LPCSTR                lpCurrentDirectory,
          [in]                LPSTARTUPINFOA        lpStartupInfo,
          [out]               LPPROCESS_INFORMATION lpProcessInformation
        );

        typedef struct _STARTUPINFOA {      // (size : offset)
          DWORD  cb;                        // 4 : 0 (followed by padding)
          LPSTR  lpReserved;                // 8 : 8
          LPSTR  lpDesktop;                 // 8 : 16
          LPSTR  lpTitle;                   // 8 : 24
          DWORD  dwX;                       // 4 : 32
          DWORD  dwY;                       // 4 : 36
          DWORD  dwXSize;                   // 4 : 40
          DWORD  dwYSize;                   // 4 : 44
          DWORD  dwXCountChars;             // 4 : 48
          DWORD  dwYCountChars;             // 4 : 52
          DWORD  dwFillAttribute;           // 4 : 56
          DWORD  dwFlags;                   // 4 : 60
          WORD   wShowWindow;               // 2 : 64
          WORD   cbReserved2;               // 2 : 66 (followed by padding)
          LPBYTE lpReserved2;               // 8 : 72
          HANDLE hStdInput;                 // 8 : 80
          HANDLE hStdOutput;                // 8 : 88
          HANDLE hStdError;                 // 8 : 96
        } STARTUPINFOA, *LPSTARTUPINFOA;
    */

    defineHandler({
      onEnter(log, args, state) {
        log('CreateProcessA() - lpApplicationName = ', args[0].readCString());
        log('CreateProcessA() - lpCommandLine = ', args[1].readCString());

        log('CreateProcessA() - bInheritHandles = ', args[4]);
        log('CreateProcessA() - dwCreationFlags = ', args[5]);

        log('CreateProcessA() - lpCurrentDirectory = ', args[7].readCString());    
        log('CreateProcessA() - lpStartupInfo = ', args[8]);

        log('CreateProcessA() -    cb=', args[8].readInt());
        log('CreateProcessA() -    lpReserved=', args[8].add(8).readCString());
        log('CreateProcessA() -    lpDesktop=', args[8].add(16).readCString());
        log('CreateProcessA() -    lpTitle=', args[8].add(24).readCString());
        log('CreateProcessA() -    dwX=', args[8].add(32).readInt());
        log('CreateProcessA() -    dwY=', args[8].add(36).readInt());
        log('CreateProcessA() -    dwXSize=', args[8].add(40).readInt());
        log('CreateProcessA() -    dwYSize=', args[8].add(44).readInt());

        log('CreateProcessA() -    dwFlags=', args[8].add(60).readInt());    

        log('CreateProcessA() -    hStdInput=', args[8].add(80).readU64());
        log('CreateProcessA() -    hStdOutput=', args[8].add(88).readU64());
        log('CreateProcessA() -    hStdError=', args[8].add(96).readU64());            

        log('CreateProcessA() -    raw=', hexdump(args[8]));

        log('CreateProcessA() - lpProcessInformation = ', args[9]);  

        // rewrite hStdOutput with the value incorrectly assigned to hStdError
        args[8].add(88).writeU64(args[8].add(96).readU64());  
      },

      onLeave(log, retval, state) {
        log('CreateProcessA() - retVal = ', retval);   
      }
    });

Re-running `frida-trace` and we've fixed the redirection sufficiently, with the challenge binary outputting the `"[+] I think I worked!"` message.

    D:\CTF\picoCTF-2026\Binary-Instrumentation-3>frida-trace -i *CreateFile* -i *CreateProcess* .\bin-ins.exe
    Started tracing 53 functions. Web UI available at http://localhost:50326/
    [+] Let me get started!
               /* TID 0x2a58 */
       506 ms  CreateFileA() - lpFileName =  C:\random\output_flag.txt
       515 ms     | CreateFileA() - retVal =  0x294
       515 ms  CreateProcessA() - lpApplicationName =
       515 ms  CreateProcessA() - lpCommandLine =  cmd.exe /c echo testing if redirection works
       515 ms  CreateProcessA() - bInheritHandles =  0x1
       515 ms  CreateProcessA() - dwCreationFlags =  0x0
       515 ms  CreateProcessA() - lpCurrentDirectory =
       515 ms  CreateProcessA() - lpStartupInfo =  0xfe5ecff510
       515 ms  CreateProcessA() -    cb= 104
       515 ms  CreateProcessA() -    lpReserved=
       515 ms  CreateProcessA() -    lpDesktop=
       515 ms  CreateProcessA() -    lpTitle=
       515 ms  CreateProcessA() -    dwX= 0
       515 ms  CreateProcessA() -    dwY= 0
       515 ms  CreateProcessA() -    dwXSize= 0
       515 ms  CreateProcessA() -    dwYSize= 0
       515 ms  CreateProcessA() -    dwFlags= 256
       515 ms  CreateProcessA() -    hStdInput= 0
       515 ms  CreateProcessA() -    hStdOutput= 10
       515 ms  CreateProcessA() -    hStdError= 660
       515 ms  CreateProcessA() -    raw=              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
    fe5ecff510  68 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  h...............
    fe5ecff520  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    fe5ecff530  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    fe5ecff540  00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00  ................
    fe5ecff550  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    fe5ecff560  00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00  ................
    fe5ecff570  94 02 00 00 00 00 00 00 e8 f5 4a 00 00 00 00 00  ..........J.....
    fe5ecff580  10 66 51 af b5 02 00 00 2c 00 00 00 00 00 00 00  .fQ.....,.......
    fe5ecff590  2c 00 00 00 00 00 00 00 86 aa 50 3a fe 7f 00 00  ,.........P:....
    fe5ecff5a0  18 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    fe5ecff5b0  01 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ........@.......
    fe5ecff5c0  10 00 00 00 00 00 00 00 c0 a0 29 b0 b5 02 00 00  ..........).....
    fe5ecff5d0  60 18 51 af b5 02 00 00 29 15 40 00 00 00 00 00  `.Q.....).@.....
    fe5ecff5e0  94 02 00 00 00 00 00 00 0e 00 00 00 00 00 00 00  ................
    fe5ecff5f0  01 00 00 00 00 00 00 00 90 18 51 af b5 02 00 00  ..........Q.....
    fe5ecff600  00 00 00 00 00 00 00 00 b4 13 40 00 00 00 00 00  ..........@.....
       515 ms  CreateProcessA() - lpProcessInformation =  0xfe5ecff4f0
       515 ms     | CreateProcessA()
       515 ms     |    | CreateProcessInternalA()
       515 ms     |    |    | CreateProcessInternalW()
       515 ms     |    |    |    | BasepReleaseSxsCreateProcessUtilityStruct()
       515 ms     |    |    |    | BasepConstructSxsCreateProcessMessage()
       515 ms     |    |    |    | BasepReleaseSxsCreateProcessUtilityStruct()
       515 ms  CreateProcessA() - retVal =  0x1
    [+] I think I worked!
       591 ms  CreateProcessA() - lpApplicationName =
       591 ms  CreateProcessA() - lpCommandLine =  cmd.exe /c echo cGljb0NURns0MTFfNHIzXzRwMTVfbjA3aDFuOV8zbDUzXzRmNzA2NDBlfQo=
       591 ms  CreateProcessA() - bInheritHandles =  0x1
       591 ms  CreateProcessA() - dwCreationFlags =  0x0
       591 ms  CreateProcessA() - lpCurrentDirectory =
       591 ms  CreateProcessA() - lpStartupInfo =  0xfe5ecff510
       591 ms  CreateProcessA() -    cb= 104
       591 ms  CreateProcessA() -    lpReserved=
       591 ms  CreateProcessA() -    lpDesktop=
       591 ms  CreateProcessA() -    lpTitle=
       591 ms  CreateProcessA() -    dwX= 0
       591 ms  CreateProcessA() -    dwY= 0
       591 ms  CreateProcessA() -    dwXSize= 0
       591 ms  CreateProcessA() -    dwYSize= 0
       591 ms  CreateProcessA() -    dwFlags= 256
       591 ms  CreateProcessA() -    hStdInput= 0
       591 ms  CreateProcessA() -    hStdOutput= 660
       591 ms  CreateProcessA() -    hStdError= 660
       591 ms  CreateProcessA() -    raw=              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
    fe5ecff510  68 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  h...............
    fe5ecff520  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    fe5ecff530  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    fe5ecff540  00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00  ................
    fe5ecff550  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    fe5ecff560  00 00 00 00 00 00 00 00 94 02 00 00 00 00 00 00  ................
    fe5ecff570  94 02 00 00 00 00 00 00 e8 f5 4a 00 00 00 00 00  ..........J.....
    fe5ecff580  10 66 51 af b5 02 00 00 2c 00 00 00 00 00 00 00  .fQ.....,.......
    fe5ecff590  2c 00 00 00 00 00 00 00 86 aa 50 3a fe 7f 00 00  ,.........P:....
    fe5ecff5a0  18 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    fe5ecff5b0  01 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ........@.......
    fe5ecff5c0  e0 e0 4d 00 00 00 00 00 00 e1 4d 00 00 00 00 00  ..M.......M.....
    fe5ecff5d0  60 e0 4d 00 00 00 00 00 29 15 40 00 01 00 00 00  `.M.....).@.....
    fe5ecff5e0  94 02 00 00 00 00 00 00 00 e1 4d 00 00 00 00 00  ..........M.....
    fe5ecff5f0  01 00 00 00 00 00 00 00 90 18 51 af b5 02 00 00  ..........Q.....
    fe5ecff600  00 00 00 00 00 00 00 00 b4 13 40 00 00 00 00 00  ..........@.....
       591 ms  CreateProcessA() - lpProcessInformation =  0xfe5ecff4f0
       607 ms     | CreateProcessA()
       607 ms     |    | CreateProcessInternalA()
       607 ms     |    |    | CreateProcessInternalW()
       607 ms     |    |    |    | BasepReleaseSxsCreateProcessUtilityStruct()
       607 ms     |    |    |    | BasepConstructSxsCreateProcessMessage()
       607 ms     |    |    |    | BasepReleaseSxsCreateProcessUtilityStruct()
       607 ms  CreateProcessA() - retVal =  0x1
    Process terminated

Checking the contents of the `flag.txt` file we see it no longer contains `"The handle is invalid."`, but contains, from the two invocations of `echo` seen in the output above:

    D:\CTF\picoCTF-2026\Binary-Instrumentation-3>type flag.txt
    testing if redirection works
    cGljb0NURns0MTFfNHIzXzRwMTVfbjA3aDFuOV8zbDUzXzRmNzA2NDBlfQo=

## Solution ##

The `frida-trace` scripts to arrive to the solution are presented above in the approach description, these include hooks for:
- `CreateFileA()`
- `CreateProcessA()`

The flag is dropped in the created output file and base64 encoded.
