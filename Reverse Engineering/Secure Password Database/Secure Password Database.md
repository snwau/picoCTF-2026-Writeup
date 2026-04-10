# Secure Password Database #

## Overview ##

Difficulty: Medium

Category: [Reverse Engineering](../)

Tags: `#reverseengineering #hash`

## Description ##

I made a new password authentication program that even shows you the password you entered saved in the database! Isn't that cool? system.out

## Approach ##

Downloading and running the provided `system.out` challenge binary we get an idea of the input flow:

    $ ./system.out 
    Please set a password for your account:
    qwerty
    How many bytes in length is your password?
    6
    You entered: 6
    Your successfully stored password:
    113 119 101 114 116 121 10 
    Enter your hash to access your account!
    12345678

Disassembling the challenge binary with [Ghidra](http://ghidra.net/), we are presented with the following `main()` entry function:

    undefined8 main(void)
    {
      uint password_length;
      char *user_input_ptr;
      undefined8 uVar1;
      long in_FS_OFFSET;
      int local_128;
      char *local_120;
      ulong local_118;
      char *user_password;
      size_t hash_length;
      ulong hash_value;
      ulong local_f8;
      FILE *local_f0;
      undefined local_e5 [13];
      char local_d8 [31];
      char acStack_b9 [65];
      char local_78 [104];
      long local_10;
      
      local_10 = *(long *)(in_FS_OFFSET + 0x28);
      user_password = (char *)calloc(0x5a,1);
      for (local_118 = 0; local_118 < 0xd; local_118 = local_118 + 1) {
        user_password[local_118 + 0x3c] = obf_bytes[local_118] ^ 0xaa;
      }
      puts("Please set a password for your account:");
      user_input_ptr = fgets(acStack_b9 + 1,0x32,stdin);
      if (user_input_ptr != (char *)0x0) {
        strcpy(user_password,acStack_b9 + 1);
        puts("How many bytes in length is your password?");
        user_input_ptr = fgets(local_d8,0x14,stdin);
        if (user_input_ptr != (char *)0x0) {
          password_length = atoi(local_d8);
          printf("You entered: %d\n",(ulong)password_length);
          puts("Your successfully stored password:");
          for (local_128 = 0; (local_128 <= (int)password_length && (local_128 < 0x5a));
              local_128 = local_128 + 1) {
            printf("%d ",(ulong)(uint)(int)user_password[local_128]);
          }
          putchar(10);
        }
      }
      puts("Enter your hash to access your account!");
      user_input_ptr = fgets(acStack_b9 + 1,0x32,stdin);
      if (user_input_ptr != (char *)0x0) {
        hash_length = strlen(acStack_b9 + 1);
        if ((hash_length != 0) && (acStack_b9[hash_length] == '\n')) {
          acStack_b9[hash_length] = '\0';
        }
        hash_value = strtoul(acStack_b9 + 1,&local_120,10);
        if (local_120 == acStack_b9 + 1) {
          printf("No digits were found");
                        /* WARNING: Subroutine does not return */
          __assert_fail("1 == 0","heartbleed.c",0x45,"main");
        }
        local_f8 = make_secret(local_e5);
        if (local_f8 == hash_value) {
          local_f0 = fopen("flag.txt","r");
          if (local_f0 == (FILE *)0x0) {
            perror("Could not open flag.txt");
            uVar1 = 1;
            goto LAB_0010173e;
          }
          user_input_ptr = fgets(local_78,100,local_f0);
          if (user_input_ptr == (char *)0x0) {
            puts("Failed to read the flag");
          }
          else {
            printf("%s",local_78);
          }
          fclose(local_f0);
        }
      }
      free(user_password);
      uVar1 = 0;
    LAB_0010173e:
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return uVar1;
    }

Working backwards from the dropping of the flag from the `flag.txt` file, we see the following conditional logic:

    local_f8 = make_secret(local_e5);
    if (local_f8 == hash_value) { ...

Where `hash_value` is derived from user input (stdin) and converted to an `unsigned long` from the input string, via `strtoul()`. Which is compared to the `local_f8` for equality to drop the flag.

`local_f8` is returned from the `make_secret()` function, which from the disassembly is simply `XOR`'ing bytes within an array `obf_bytes` by the value `0xaa`, that forms an input parameter to another `hash()` function.

    long make_secret(long param_1)
    {
      long idx;
      
      for (idx = 0; obf_bytes[idx] != '\0'; idx = idx + 1) {
        *(byte *)(idx + param_1) = obf_bytes[idx] ^ 0xaa;
      }
      *(undefined *)(param_1 + 0xc) = 0;
      return hash(param_1);
    }

The `obf_bytes` array used by `make_secret()` from the disassembly:

                             obf_bytes[] 
           00102008 c3              undefined1C3h      [0] XREF[1]:make_secret:001013b0(*) 
           00102009 ff              undefined1FFh      [1]  
           0010200a c8              undefined1C8h      [2]
           0010200b c2              undefined1C2h      [3]
           0010200c 92              undefined192h      [4]
           0010200d 9b              undefined19Bh      [5]
           0010200e 8b              undefined18Bh      [6]
           0010200f c0              undefined1C0h      [7]
           00102010 80              undefined180h      [8]
           00102011 c2              undefined1C2h      [9]
           00102012 c4              undefined1C4h      [10]
           00102013 8b              undefined18Bh      [11]
           00102014 00              undefined100h      [12]

Now, inspecting the `hash()` function from the disassembly, traverses the `secret_value` parameter byte by byte to accumulate a value to form a hash.

    long hash(byte *secret_value)
    {
      byte *secret_value_trav;
      long local_10;
      
      local_10 = 0x1505;
      secret_value_trav = secret_value;
      while( true ) {
        if (*secret_value_trav == 0) break;
        local_10 = (long)(int)(uint)*secret_value_trav + local_10 * 0x21;
        secret_value_trav = secret_value_trav + 1;
      }
      return local_10;
    }

The calculation simplifying to:

    hash_value = 0x1505 (or 5381)
    FOR each byte in secret_value:
      hash_value = byte + (hash_value * 0x21 (or 33))
    ENDFOR

From the above we see that the hash value is not based on the user provided password at all and results in a static fixed value. Therefore we can use `gdb` to set a breakpoint at this conditional statement to obtain the hash value without having to calculate it ourselves.

    gef➤  br *(main+693)

     → 0x555555555685 <main+693>       cmp    rax, QWORD PTR [rbp-0xf8]
       0x55555555568c <main+700>       jne    0x55555555572a <main+858>
       0x555555555692 <main+706>       lea    rax, [rip+0xa60]        # 0x5555555560f9
       0x555555555699 <main+713>       mov    rsi, rax
       0x55555555569c <main+716>       lea    rax, [rip+0xa58]        # 0x5555555560fb
       0x5555555556a3 <main+723>       mov    rdi, rax
    ─────────────────────────────────────────────────────────────────── threads ────
    [#0] Id 1, Name: "system.out", stopped 0x555555555685 in main (), reason: BREAKPOINT
    ───────────────────────────────────────────────────────────────────── trace ────
    [#0] 0x555555555685 → main()
    ────────────────────────────────────────────────────────────────────────────────
    gef➤  x/x $rbp-0xf8
    0x7fffffffdd68: 0x0001e240
    gef➤  p/x $rax
    $1 = 0xd3770d6251b31be2

The local (stack) variable `[$rbp-0xf8]` can be seen as our user input, in this case I used `"123456"` (`0x1e240`).

Register `$rax` (the return value from `make_secret()`) can be seen as `0xd3770d6251b31be2`, or decimal `15237662580160011234`.

## Solution ##

Using the reverse engineered hash value the output from running against the challenge server:

    $ nc candy-mountain.picoctf.net 57265
    Please set a password for your account:
    qwerty
    How many bytes in length is your password?
    6
    You entered: 6
    Your successfully stored password:
    113 119 101 114 116 121 10 
    Enter your hash to access your account!
    15237662580160011234
    picoCTF{...........redacted.............}

Where the actual flag value has been redacted for the purposes of this write up.
