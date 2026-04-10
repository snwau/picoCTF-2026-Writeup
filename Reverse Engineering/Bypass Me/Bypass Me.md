# Bypass Me #

## Overview ##

Difficulty: Medium

Category: [Reverse Engineering](../)

Tags: `#reverseengineering`

## Description ##

Your task is to analyze and exploit a password-protected binary called `bypassme.bin` and binary performs input sanitization. 
However, instead of guessing the password, you are expected to reverse engineer or debug the program to bypass the authentication logic and retrieve the hidden flag. You'll need to think like an attacker using tool like LLDB to uncover how the binary works under the hood and leak the correct password.

## Approach ##

As the challenge binary was not provided as a download, it was transferred from the challenge server via secure copy `scp` for local disassembly and debugging.

Disassembling with [Ghidra](http://ghidra.net/), we are presented with the following `main()` entry function:

    int main(void)
    {
      long lVar1;
      int iVar2;
      size_t sVar3;
      FILE *__stream;
      char *pcVar4;
      long in_FS_OFFSET;
      int attempts;
      FILE *flag_file;
      char buf [128];
      char sanitized [128];
      char password [128];
      char flag [128];
      
      lVar1 = *(long *)(in_FS_OFFSET + 0x28);
      attempts = 3;
      decode_password(password);
      intro_sequence();
      do {
        if (attempts == 0) {
          puts("\nAll attempts used. Try harder!");
          iVar2 = 1;
    LAB_00101823:
          if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                        /* WARNING: Subroutine does not return */
            __stack_chk_fail();
          }
          return iVar2;
        }
        printf("\n[%d tries left] Enter password: ",(ulong)(uint)attempts);
        fflush(stdout);
        fgets(buf,0x80,stdin);
        sVar3 = strcspn(buf,"\n");
        buf[sVar3] = '\0';
        sanitize(buf,sanitized);
        printf("\nRaw Input:      [%s]\n",buf);
        printf("Sanitized Input:[%s]\n",sanitized);
        puts("Hint: Input must match something special...");
        iVar2 = strcmp(buf,password);
        if (iVar2 == 0) {
          auth_sequence();
          __stream = fopen("../../root/flag.txt","r");
          if (__stream == (FILE *)0x0) {
            puts("Flag file not found.");
          }
          else {
            pcVar4 = fgets(flag,0x80,__stream);
            if (pcVar4 == (char *)0x0) {
              puts("Error reading flag.");
            }
            else {
              printf(&DAT_00102832,flag);
            }
            fclose(__stream);
          }
          iVar2 = 0;
          goto LAB_00101823;
        }
        puts("Access Denied ");
        attempts = attempts + -1;
      } while( true );
    }

Enabling highlighting of the use of the `password` buffer in [Ghidra](http://ghidra.net/), we see it provided as a parameter to the `decode_password()` function and later used in some conditional logic via `strcmp()` to drop the flag if our user input is equal.

Inspecting the disassembly for the `decode_password()` function, we see very similar to the [Secure Password Database](../Secure%20Password%20Database/Secure%20Password%20Database.md) challenge an `XOR` of a static byte array, byte by byte with a fixed value `0xaa`.

    void decode_password(char *out)
    {
      long lVar1;
      long in_FS_OFFSET;
      char *out_local;
      int i;
      uchar enc [11];
      
      lVar1 = *(long *)(in_FS_OFFSET + 0x28);
      enc[0] = 0xf9;
      enc[1] = 0xdf;
      enc[2] = 0xda;
      enc[3] = 0xcf;
      enc[4] = 0xd8;
      enc[5] = 0xf9;
      enc[6] = 0xcf;
      enc[7] = 0xc9;
      enc[8] = 0xdf;
      enc[9] = 0xd8;
      enc[10] = 0xcf;
      for (i = 0; (uint)i < 0xb; i = i + 1) {
        out[i] = enc[i] ^ 0xaa;
      }
      out[0xb] = '\0';
      if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }

Although simple to calculate manually, lets use `gdb` to calculate the value for us. Debugging the `bypassme.bin` binary, stepping until we reach the call to `decode_password()` we can take note of the address of the `password` buffer in register `$rdi`, then step over the call (using `next`). At which point we can dump the memory at this address to inspect the contents of the buffer after `decode_password()` has done its thing.

    [ Legend: Modified register | Code | Heap | Stack | String ]
    ───────────────────────────────────────────────────────────────── registers ────
    $rax   : 0x0               
    $rbx   : 0x0               
    $rcx   : 0xffffff65        
    $rdx   : 0xffffff65        
    $rsp   : 0x007fffffffdc50  →  0x0000000300000000
    $rbp   : 0x007fffffffde70  →  0x0000000000000001
    $rsi   : 0x007fffffffdf88  →  0x007fffffffe2fa  →  "/picoCTF/Bypass-Me/bypassme.bin"
    $rdi   : 0x007fffffffdd60  →  "SuperSecure"
    $rip   : 0x00555555555665  →  <main+55> call 0x5555555554c6 <_Z14intro_sequencev>
    $r8    : 0x007ffff7e1bf10  →  0x0000000000000004
    $r9    : 0x007ffff7fc9040  →  <_dl_fini+0> endbr64 
    $r10   : 0x007ffff7fc3908  →  0x000d00120000000e
    $r11   : 0x007ffff7fde660  →  <_dl_audit_preinit+0> endbr64 
    $r12   : 0x007fffffffdf88  →  0x007fffffffe2fa  →  "/picoCTF/Bypass-Me/bypassme.bin"
    $r13   : 0x0055555555562e  →  <main+0> endbr64 
    $r14   : 0x0               
    $r15   : 0x007ffff7ffd040  →  0x007ffff7ffe2e0  →  0x00555555554000  →   jg 0x555555554047
    $eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
    $cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
    ───────────────────────────────────────────────────────────────────── stack ────
    0x007fffffffdc50│+0x0000: 0x0000000300000000   ← $rsp
    0x007fffffffdc58│+0x0008: 0x000000ff00000000
    0x007fffffffdc60│+0x0010: 0x2f2f2f2f2f2f2f2f
    0x007fffffffdc68│+0x0018: 0x2f2f2f2f2f2f2f2f
    0x007fffffffdc70│+0x0020: 0x0000000000000d98
    0x007fffffffdc78│+0x0028: 0x0000000000000000
    0x007fffffffdc80│+0x0030: 0x00000000000060 ("`"?)
    0x007fffffffdc88│+0x0038: 0x0000000000000000
    ─────────────────────────────────────────────────────────────── code:x86:64 ────
       0x555555555656 <main+40>        lea    rax, [rbp-0x110]
       0x55555555565d <main+47>        mov    rdi, rax
       0x555555555660 <main+50>        call   0x555555555333 <_Z15decode_passwordPc>
     → 0x555555555665 <main+55>        call   0x5555555554c6 <_Z14intro_sequencev>
       ↳  0x5555555554c6 <intro_sequence()+0> endbr64 
          0x5555555554ca <intro_sequence()+4> push   rbp
          0x5555555554cb <intro_sequence()+5> mov    rbp, rsp
          0x5555555554ce <intro_sequence()+8> sub    rsp, 0x50
          0x5555555554d2 <intro_sequence()+12> mov    rax, QWORD PTR fs:0x28
          0x5555555554db <intro_sequence()+21> mov    QWORD PTR [rbp-0x8], rax
    ───────────────────────────────────────────────────────────────── arguments ────
    _Z14intro_sequencev (<void>)
    ─────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "bypassme.bin", stopped 0x555555555665 in main (), reason: SINGLE STEP
    ───────────────────────────────────────────────────────────────────── trace ────
    [#0] 0x555555555665 → main()
    ────────────────────────────────────────────────────────────────────────────────
    gef➤  x/16xb $rdi
    0x7fffffffdd60: 0x53  0x75  0x70  0x65  0x72  0x53  0x65  0x63
    0x7fffffffdd68: 0x75  0x72  0x65  0x00  0x00  0x00  0x00  0x00
    gef➤  x/s $rdi
    0x7fffffffdd60: "SuperSecure"

As simple as that, we have our password.

## Solution ##

Opening a secure shell on the challenge server and testing our discovered password:

    $ ssh -p 55487 ctf-player@foggy-cliff.picoctf.net
    The authenticity of host '[foggy-cliff.picoctf.net]:55487 ([3.15.249.208]:55487)' can't be established.
    ED25519 key fingerprint is SHA256:ZQOsifIrLIQqZXW0DLH5in9vw9TVqb6eSQ0XHXTvej8.
    This host key is known by the following other names/addresses:
        ~/.ssh/known_hosts:62: [hashed name]
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '[foggy-cliff.picoctf.net]:55487' (ED25519) to the list of known hosts.
    ctf-player@foggy-cliff.picoctf.net's password: 
    Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 6.17.0-1009-aws x86_64)

     * Documentation:  https://help.ubuntu.com
     * Management:     https://landscape.canonical.com
     * Support:        https://ubuntu.com/advantage

    This system has been minimized by removing packages and content that are
    not required on a system that users do not log into.

    To restore this content, you can run the 'unminimize' command.

    The programs included with the Ubuntu system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.

    Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
    applicable law.

    ctf-player@pico-chall$ ls
    bypassme.bin
    ctf-player@pico-chall$ ./bypassme.bin 



              ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗    ██████╗  ██████╗ ██████╗ ████████╗ █████╗ ██╗     
              ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██║     
              ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗      ██████╔╝██║   ██║██████╔╝   ██║   ███████║██║     
              ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝      ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══██║██║     
              ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗    ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗
              ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝

     Initializing secure modules...
     Running memory diagnostics...
     All systems online...

     Access to this terminal is restricted.
     Please authenticate below.
    ----------------------------------------


    [3 tries left] Enter password: SuperSecure

    Raw Input:      [SuperSecure]
    Sanitized Input:[SuperSecure]
    Hint: Input must match something special...

    Authenticating...
    🎉 Flag: picoCTF{...........redacted.............}

Where the actual flag value has been redacted for the purposes of this write up.
