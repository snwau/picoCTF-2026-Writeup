# Autorev 1 #

## Overview ##

Difficulty: Medium

Category: [Reverse Engineering](../)

Tags: `#reverseengineering #pwntools #automation`

## Description ##

You think you can reverse engineer? Let's test out your speed.

## Approach ##

Connecting to the challenge server we see the following output (abridged to cut out the bulk of the binary hex data for the purposes of write-up):

    $ nc mysterious-sea.picoctf.net 61098
    Welcome! I think I'm pretty good at reverse enginnering. There's NO WAY anyone's better than me. Wanna try? I have 20 binaries I'm going to send you and you have 1 second EACH to get the secret in each one. Good luck >:)
    126099310
    Here's the next binary in bytes:
    7f454c4602010100000000000000000002003e000100000050104000000000004000000000000000283900000000000000000000400038000d00400020001f000600000004000000400000000000000040004000000000004000400000000000d802000000000000d802000000000000080000000000000003000000040000001803000000000000180340000000000018034000000000001c000000000000001c00000000000000010000000000000001000000040000000000000000000000000040000000000000004000000000006805000000000000680500000000000000100000000000000100000005000000001000000000000000104000000000000010400000000000a101000000000000a10100000000000000100000000000000100000004000000002000000000000000204000000000000020400000000000f400000000000000f40000000000000000100000000000000100000006000000f82d000000000000f83d400000000000f83d4000000000001c02000000000000200200000000000000100000000000000200000006000000082e000000000000083e400000000000083e400000000000d001000000000000
                                              .
                                              .
                                            (snip)
                                              .
                                              .
    10300000000000000400000000000000000000000000000001000000000000000000000000000000080100000800000003000000000000001440400000000000143000000000000004000000000000000000000000000000010000000000000000000000000000000d010000010000003000000000000000000000000000000014300000000000002e0000000000000000000000000000000100000000000000010000000000000016010000030000003000000000000000000000000000000042300000000000004f0100000000000000000000000000000100000000000000010000000000000025010000070000000000000000000000186040000000000094310000000000004401000000000000000000000000000004000000000000000000000000000000010000000200000000000000000000000000000000000000d83200000000000048030000000000001e00000012000000080000000000000018000000000000000900000003000000000000000000000000000000000000002036000000000000cd01000000000000000000000000000001000000000000000000000000000000110000000300000000000000000000000000000000000000ed370000000000003b01000000000000000000000000000001000000000000000000000000000000
    What's the secret?:

Given we have very little time to respond with the secret and there are 20 of binaries, this requires automation, a job for [pwntools](https://docs.pwntools.com/en/stable/).

At first I thought I had to capture the binary hex data, dump a binary locally and execute to interrogate some output (or similar), but it turns out the secret is much simpler than that.

Looking closely at the output from the challenge server, there is a value printed prior to the `"Here's the next binary in bytes:"` line, with some experimentation manually it turns out this is our secret (although copy and pasting this value into the `"What's the secret?"` results in a `"Too slow :("` response, but at least confirms we are on the right track).

A simple script was written to extract this secret value, wait for the prompt and respond with the secret. Looped 20 times.

## Solution ##

The final [pwntools](https://docs.pwntools.com/en/stable/) script used:

    #!/usr/bin/env python3

    from pwn import *

    if len(sys.argv) > 2:
      target_proc = remote(sys.argv[1], sys.argv[2])
    else:
      print('usage: .' + sys.argv[0] + ' <remote server> <port number>')
      exit(1)

    target_proc.recvuntil(b'Good luck >:)\n')

    for i in range (20):
      secret = target_proc.recvline()
      target_proc.recvuntil(b'Here\'s the next binary in bytes:\n')
      target_proc.recvuntil(b'What\'s the secret?:')
      print(b'Sending secret: ' + secret)
      target_proc.sendline(secret[0:-1])
      response = target_proc.recvline() #Correct!
      print(response)

    target_proc.interactive()

The resulting output after transferring this script to the challenge server and running against the challenge:

    $ ./pwn-autorev1.py mysterious-sea.picoctf.net 58807
    [+] Opening connection to mysterious-sea.picoctf.net on port 58807: Done
    b'Sending secret: 997906230\n'
    b'Correct!\n'
    b'Sending secret: 1394293202\n'
    b'Correct!\n'
    b'Sending secret: 3957067899\n'
    b'Correct!\n'
    b'Sending secret: 723038215\n'
    b'Correct!\n'
    b'Sending secret: 2265364267\n'
    b'Correct!\n'
    b'Sending secret: 2109533154\n'
    b'Correct!\n'
    b'Sending secret: 4056595042\n'
    b'Correct!\n'
    b'Sending secret: 508269935\n'
    b'Correct!\n'
    b'Sending secret: 32353874\n'
    b'Correct!\n'
    b'Sending secret: 3302329544\n'
    b'Correct!\n'
    b'Sending secret: 2489166087\n'
    b'Correct!\n'
    b'Sending secret: 3139865009\n'
    b'Correct!\n'
    b'Sending secret: 1632867264\n'
    b'Correct!\n'
    b'Sending secret: 1828486501\n'
    b'Correct!\n'
    b'Sending secret: 2885163839\n'
    b'Correct!\n'
    b'Sending secret: 3315791925\n'
    b'Correct!\n'
    b'Sending secret: 2602847480\n'
    b'Correct!\n'
    b'Sending secret: 2301216384\n'
    b'Correct!\n'
    b'Sending secret: 1163927254\n'
    b'Correct!\n'
    b'Sending secret: 4232017701\n'
    b'Correct!\n'
    [*] Switching to interactive mode
    Woah, how'd you do that??
    Here's your flag: picoCTF{...........redacted.............}

    [*] Got EOF while reading in interactive
    $ 
    [*] Interrupted
    [*] Closed connection to mysterious-sea.picoctf.net port 58807

Where the actual flag value has been redacted for the purposes of this write up.
