# Hidden Cipher 1 #

## Overview ##

Difficulty: Medium

Category: [Reverse Engineering](../)

Tags: `#reverseengineering #packed #upx #encryption #cipher #xor`

## Description ##

The flag is right in front of you; just slightly encrypted. All you have to do is figure out the cipher and the key. You can download the program files here.

## Approach ##

Downloading and extracting the challenge archive:

    $ unzip hiddencipher.zip 
    Archive:  hiddencipher.zip
      inflating: hiddencipher            
     extracting: flag.txt                

We see the following when running the challenge binary with the provided dummy practice flag file locally:

    $ ./hiddencipher 
    Here your encrypted flag:
    235a201d70201548251358110c552f135409

Analysing the strings within the challenge binary doesn't expose anything related to the above output, but does indicate the binary is packed via [UPX](http://upx.sf.net) executable packer. Which we had seen before back in the [packer](https://github.com/snwau/picoCTF-2024-Writeup/blob/main/Reverse%20Engineering/packer/packer.md) challenge of picoCTF-2024.

    $ strings hiddencipher
    ...
    UPX!
    ...
    $Info: This file is packed with the UPX executable packer http://upx.sf.net $
    $Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $

Unpacking the challenge binary using the same method:

    $ ../bin/upx-4.2.2-amd64_linux/upx -d hiddencipher
                           Ultimate Packer for eXecutables
                              Copyright (C) 1996 - 2024
    UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 3rd 2024

            File size         Ratio      Format      Name
       --------------------   ------   -----------   -----------
         24275 <-      7196   29.64%   linux/amd64   hiddencipher

    Unpacked 1 file.

After which the strings output is much more as we would expect.

Disassembling with [Ghidra](http://ghidra.net/), we get the following `main()` function, with only the odd variable renamed for clarity.

    undefined8 main(void)
    {
      FILE *__stream;
      undefined8 uVar1;
      size_t file_size;
      void *flag_buf;
      long lVar2;
      int idx;
      
      __stream = fopen("flag.txt","rb");
      if (__stream == (FILE *)0x0) {
        perror("[!] Failed to open flag.txt");
        uVar1 = 1;
      }
      else {
        fseek(__stream,0,2);
        file_size = ftell(__stream);
        rewind(__stream);
        flag_buf = malloc(file_size + 1);
        if (flag_buf == (void *)0x0) {
          puts("[!] Memory allocation error.");
          fclose(__stream);
          uVar1 = 1;
        }
        else {
          fread(flag_buf,1,file_size,__stream);
          fclose(__stream);
          *(undefined *)((long)flag_buf + file_size) = 0;
          lVar2 = get_secret();
          puts("Here your encrypted flag:");
          for (idx = 0; (long)idx < (long)file_size; idx = idx + 1) {
            printf("%02x",(ulong)(*(byte *)(lVar2 + idx % 6) ^
                                 *(byte *)((long)flag_buf + (long)idx)));
          }
          putchar(10);
          free(flag_buf);
          uVar1 = 0;
        }
      }
      return uVar1;
    }

We see the `flag.txt` file being opened and read into a buffer after determining its length. Then a `get_secret()` function is called, which disassembles as:

    undefined7 * get_secret(void)
    {
      s.0._0_1_ = 0x53;
      s.0._1_1_ = 0x33;
      s.0._2_1_ = 0x43;
      s.0._3_1_ = 0x72;
      s.0._4_1_ = 0x33;
      s.0._5_1_ = 0x74;
      s.0._6_1_ = 0;
      return &s.0;
    }

Essentially a null terminated array of bytes with static values seen in the disassembly. Then for each byte in the flag buffer, it is encrypted then printed until the flag buffer is exhausted, using:

    printf("%02x",(ulong)(*(byte *)(lVar2 + idx % 6) ^
                         *(byte *)((long)flag_buf + (long)idx)));

This encryption effectively translates to the following, where `idx` is the index of the current byte being encrypted and printed from the flag buffer:

    cipher_text[idx] = secret_key[idx % 6] XOR flag_buf[idx];

XOR (or `^`) is reversable, so to reverse the encryption we can simply XOR again by the same value, such that:

    plain_text[idx] = cipher_text[idx] XOR secret_key[idx %6]

I created a simple C program (provided in the Solution below) to take input from standard input and undertake this decryption, which was tested locally with the provided dummy flag file:

    $ cat flag.txt | ./hiddencipher_unpacked 
    Here your encrypted flag:
    235a201d70201548251358110c552f135409

    $ echo "235a201d70201548251358110c552f135409" | ./pwn-cipher 
    picoCTF{fake_flag}

`./hiddencipher_unpacked` is just the UPX unpacked version of the provided challenge binary.

## Solution ##

The final C program used to decrypt the cipher text was:

    #include <stdio.h> 

    int
    main(void)
    {
      unsigned char secret_key[] = { 0x53, 0x33, 0x43, 0x72, 0x33, 0x74 };
      int count = 0;
      int hex_value;

      for(;;)
      {
        if (scanf("%02x", &hex_value) == EOF)
        {
          break;
        }

        printf("%c", ((char)(hex_value) ^ secret_key[count++ % 6]));
      }

      return 0;  
    }

Used with the output from the challenge server:

    $ nc candy-mountain.picoctf.net 53348
    Here your encrypted flag:
    235a201d702015483b1d412b265d3313501f0c072d135f0d2002302d01156a57224306172e

    $ echo "235a201d702015483b1d412b265d3313501f0c072d135f0d2002302d01156a57224306172e" | ./pwn-cipher 
    picoCTF{...........redacted.............}

Where the actual flag value has been redacted for the purposes of this write up.
