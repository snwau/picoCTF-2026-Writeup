# Gatekeeper #

## Overview ##

Difficulty: Medium

Category: [Reverse Engineering](../)

Tags: `#reverseengineering`

## Description ##

What’s behind the numeric gate? You only get access if you enter the right kind of number. You can download the program file here.

## Approach ##

Running the challenge binary we see some sort of guessing game:

    $ ./gatekeeper 
    Enter a numeric code (must be > 999 ): 456
    Too small.

Inspecting the challenge binary strings we can see reference to the flag file `flag.txt` and a `reveal_flag` symbol, which should be interesting to locate the use of.

    $ strings gatekeeper | grep flag
    /flag.txt
    reveal_flag

Disassembling with [Ghidra](http://ghidra.net/), we get the following `main()` function:

    undefined8 main(void)
    {
      int iVar1;
      size_t sVar2;
      long lVar3;
      undefined8 uVar4;
      long in_FS_OFFSET;
      int local_40;
      char local_38 [40];
      long local_10;
      
      local_10 = *(long *)(in_FS_OFFSET + 0x28);
      printf("Enter a numeric code (must be > 999 ): ");
      fflush(stdout);
      __isoc99_scanf(&DAT_00102070,local_38);
      sVar2 = strlen(local_38);
      iVar1 = is_valid_decimal(local_38);
      if (iVar1 == 0) {
        iVar1 = is_valid_hex(local_38);
        if (iVar1 == 0) {
          puts("Invalid input.");
          uVar4 = 1;
          goto LAB_00101698;
        }
        lVar3 = strtol(local_38,(char **)0x0,0x10);
        local_40 = (int)lVar3;
      }
      else {
        local_40 = atoi(local_38);
      }
      if (local_40 < 1000) {
        puts("Too small.");
      }
      else if (local_40 < 10000) {
        if ((int)sVar2 == 3) {
          reveal_flag();
        }
        else {
          puts("Access Denied.");
        }
      }
      else {
        puts("Too high.");
      }
      uVar4 = 0;
    LAB_00101698:
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return uVar4;
    }

Narrowing in and working back from the calling of the `reveal_flag()` function mentioned earlier we see the following logic from the above disassembly:

    if (local_40 < 1000) {
      puts("Too small.");
    }
    else if (local_40 < 10000) {
      if ((int)sVar2 == 3) {
        reveal_flag();
      }
      else {
        puts("Access Denied.");
      }
    }
    else {
      puts("Too high.");
    }

So our guess (`local_40`) has to be greater than 1,000, less than 10,000, but notice the last condition `sVar2 == 3`, which from the disassembly we can see is the string length of our guess.

This seems impossible until you look closely at the initial input validation and notice the functions `is_valid_decimal()` and `is_valid_hex()`, so our guess can be a hexadecimal number!

Lets try again with a value of `FFF` (`0xFFF` or `4,095`), which satisfies all those conditions. 

    $ nc green-hill.picoctf.net 49825
    Enter a numeric code (must be > 999 ): fff
    Access granted: }af5ftc_oc_ip7128ftc_oc_ipf_99ftc_oc_ip9_TGftc_oc_ip_xehftc_oc_ip_tigftc_oc_ipid_3ftc_oc_ip{FTCftc_oc_ipocipftc_oc_ip

Well, we can see remnants of our picoCTF flag in the output, but what is going on?
Consulting the disassembly for `reveal_flag()` :

    void reveal_flag(void)
    {
      FILE *__stream;
      size_t __n;
      void *__ptr;
      uint local_24;
      
      __stream = fopen("/flag.txt","r");
      if (__stream == (FILE *)0x0) {
        puts("Flag file not found.");
      }
      else {
        fseek(__stream,0,2);
        __n = ftell(__stream);
        rewind(__stream);
        __ptr = malloc(__n + 1);
        if (__ptr != (void *)0x0) {
          fread(__ptr,1,__n,__stream);
          *(undefined *)((long)__ptr + __n) = 0;
          fclose(__stream);
          printf("Access granted: ");
          local_24 = (uint)__n;
          while (local_24 = local_24 - 1, -1 < (int)local_24) {
            putchar((int)*(char *)((long)__ptr + (long)(int)local_24));
            if ((local_24 & 3) == 0) {
              printf("ftc_oc_ip");
            }
          }
          putchar(10);
          free(__ptr);
        }
      }
      return;
    }

We notice two things;
- the `while()` loop traverses the flag buffer in reverse, and
- the string `"ftc_oc_ip"` is being inserted whenever the loop index `local_24 & 3` is non-zero.

## Solution ##

The above output was copy and pasted into my editor of choice, [Sublime Text](https://www.sublimetext.com/) where;
- all instances of `"ftc_oc_ip"` were removed with (Find & Replace), leaving:
    
    `}af57128f_999_TG_xeh_tigid_3{FTCocip`

- reversing the string using a regex search (of all characters), selecting `Find All` to select all characters, and using the `Edit > Permute Selections > Reverse` menu function.

    picoCTF{...........redacted.............}

Where the actual flag value has been redacted for the purposes of this write up.
