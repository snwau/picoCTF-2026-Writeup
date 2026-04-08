# Hidden Cipher 2 #

## Overview ##

Difficulty: Medium

Category: [Reverse Engineering](../)

Tags: `#reverseengineering`

## Description ##

The flag is right in front of you... kind of. You just need to solve a basic math problem to see it. But to get the real flag, you’ll have to understand how that math answer is used.
You can download the program files here.

## Approach ##

Downloading and extracting the challenge archive:

    $ unzip hiddencipher2.zip 
    Archive:  hiddencipher2.zip
      inflating: hiddencipher2           
     extracting: flag.txt                

Inspecting the challenge binary strings it was determined this binary was not packed like previous challenge in the series ([Hidden Cipher 1](../Hidden%20Cipher%201/Hidden%20Cipher%201.md).

The challenge binary couldn't be run on my machine locally out of the box due to a `libc` mismatch, but I didn't bother trying to correct this and worked on the challenge server where required.

    $ ./hiddencipher2 
    ./hiddencipher2: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by ./hiddencipher2)

Running the challenge binary we are prompted to answer a seemingly random basic maths question (that changes each invocation). Once answered correctly we are supplied with the flag as cipher text (or in encoded form):

    $ nc crystal-peak.picoctf.net 62406
    What is 2 + 2? 4
    Encoded flag values:
    448, 420, 396, 444, 268, 336, 280, 492, 436, 208, 464, 416, 380, 392, 204, 416, 196, 440, 400, 380, 396, 196, 448, 416, 204, 456, 380, 408, 204, 408, 200, 200, 396, 216, 216, 500

Testing what happens if we answer incorrectly out of interest:

    $ nc crystal-peak.picoctf.net 62406
    What is 10 - 2? 4
    Wrong answer! No flag for you.

Disassembling the challenge binary with [Ghidra](http://ghidra.net/), we are presented with the following `main()` entry function:

        undefined8 main(void)
        {
          int iVar1;
          time_t tVar2;
          undefined8 uVar3;
          long in_FS_OFFSET;
          char local_29;
          uint local_28;
          uint local_24;
          int local_20;
          int local_1c;
          void *local_18;
          long local_10;
          
          local_10 = *(long *)(in_FS_OFFSET + 0x28);
          tVar2 = time((time_t *)0x0);
          srand((uint)tVar2);
          local_1c = generate_math_question(&local_29,&local_28,&local_24);
          printf("What is %d %c %d? ",(ulong)local_28,(ulong)(uint)(int)local_29,(ulong)local_24);
          fflush(stdout);
          iVar1 = __isoc23_scanf(&DAT_0010201d,&local_20);
          if (iVar1 == 1) {
            if (local_1c == local_20) {
              local_18 = (void *)read_flag_file("flag.txt");
              if (local_18 == (void *)0x0) {
                uVar3 = 1;
              }
              else {
                encode_flag(local_18,local_1c);
                free(local_18);
                uVar3 = 0;
              }
            }
            else {
              puts("Wrong answer! No flag for you.");
              uVar3 = 1;
            }
          }
          else {
            puts("Invalid input. Exiting.");
            uVar3 = 1;
          }
          if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                            /* WARNING: Subroutine does not return */
            __stack_chk_fail();
          }
          return uVar3;
        }

We can see that `main()` calls `generate_math_question()` to generate the randomised maths question, which when answered correctly results in the `read_flag_file()` function being called. The operation of this `read_flag_file()` function is pretty standard, opening and reading the contents of the `flag.txt` file to a buffer (pointer of which is returned) without any manipulation of the data.

If reading of the flag file is successful the `encode_flag()` function is called:

    void encode_flag(long param_1,int param_2)
    {
      int local_c;
      
      puts("Encoded flag values:");
      for (local_c = 0; *(char *)(param_1 + local_c) != '\0'; local_c = local_c + 1) {
        printf("%d",(ulong)(uint)(*(char *)(param_1 + local_c) * param_2));
        if (*(char *)(param_1 + (long)local_c + 1) != '\0') {
          printf(", ");
        }
      }
      putchar(10);
      return;
    }

The two parameters that can be traced in the above disassembly of `main()` to:
- `param_1` = `local_18` (void*) from `main()` which is the return value of `read_flag_file()`, our flag buffer
- `param_2` = `local_1c` is the return value from `generate_math_question()` and is the answer to the generated maths question.

The encoding loop iterates until a null termination character is reached, encoding (or encrypting) each character of the flag individually before printing the encoded value for the character. The encoding is simply equivalent to:

    plain_text[idx] * param_2

Taking the example above from running on the challenge server and dividing the first encoded value (`448`) by `param_2` (`4` for this maths question) to reverse the encoding, we get:

    448 / 4 = 112 (0x70 or 'p')

`p` corresponding with the first character of our picoCTF challenge flag string.

To automate this process, I created a simply [pwntools](https://docs.pwntools.com/en/stable/) script to interpret the received maths question, calculate the resultant and decode the cipher text received.

## Solution ##

The final [pwntools](https://docs.pwntools.com/en/stable/) script used:

    #!/usr/bin/env python3

    from pwn import *

    target_elf = ELF("./hiddencipher2")

    # command line support for local, remote and gdb modes
    if len(sys.argv) > 1:
      if "remote" in sys.argv:
        if len(sys.argv) > 3:
          target_proc = remote(sys.argv[2], sys.argv[3])
        else:
          print('usage: ./pwn-vuln.py remote <server> <port>')
          exit(1)
      elif "gdb" in sys.argv:
        target_proc = target_elf.process([arg1, arg2])
        gdb.attach(target_proc)
    else:
      target_proc = target_elf.process([arg1, arg2])

    # Expected line format: What is 2 + 2?
    math_question = target_proc.recvuntil(b'? ')
    match = re.search("What is (\d+)\s([\+\-\*]{1})\s(\d+)\?", math_question.decode("utf-8"))
    if match:
      first_value = int(match.group(1))
      second_value = int(match.group(3))
      if match.group(2) == '+':
        resultant = first_value + second_value;
      elif match.group(2) == '-':
        resultant = first_value - second_value;    
      else:
        resultant = first_value * second_value;

      target_proc.sendline(str(resultant).encode("utf-8"))
      target_proc.readline()    # "Encoded flag values:\n"
      cipher_text = target_proc.readline()
      print(b'Cipher Text: ' + cipher_text)

      # tokenise cipher text
      characters = cipher_text.split(b', ')
      flag = str()
      for ch in characters:
        cipher_value = int(ch)
        plain_text_value = (int)(cipher_value / resultant)
        flag += str(chr(plain_text_value))
      print('Plain Text (Flag): ' + flag)

The resulting output from running against the challenge server:

    $ ./pwn-hiddencipher2.py remote crystal-peak.picoctf.net 64523
    [*] '/picoCTF/Hidden-Cipher-2/hiddencipher2'
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    [+] Opening connection to crystal-peak.picoctf.net on port 64523: Done
    b'Cipher Text: 336, 315, 297, 333, 201, 252, 210, 369, 327, 156, 348, 312, 285, 294, 153, 312, 147, 330, 300, 285, 297, 147, 336, 312, 153, 342, 285, 306, 153, 306, 150, 150, 297, 162, 162, 375\n'
    Plain Text (Flag): picoCTF{...........redacted.............}
    [*] Closed connection to crystal-peak.picoctf.net port 64523

Where the actual flag value has been redacted for the purposes of this write up.

## Notes ##

During testing of the solution it was noted that the encoding process can fail, when the randomised math question generates an equation that results in an answer of zero.

This results in a multiplication of the cipher text characters by zero which cannot be undone.

Example output from running the solution script on the challenge server:

    b'What is 3 - 3? '
    3
    -
    3
    0
    b'0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0\n'
    [b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0\n']
