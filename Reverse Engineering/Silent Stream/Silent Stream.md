# Silent Stream #

## Overview ##

Difficulty: Medium

Category: [Reverse Engineering](../)

Tags: `#reverseengineering #pcap`

## Description ##

We recovered a suspicious packet capture file that seems to contain a transferred file. The sender was kind enough to also share the script they used to encode and send it. Can you reconstruct the original file?
Download the PCAP file: here. And the sender's encoding script

## Approach ##

Analysing the provided encryption python script `encrypt.py`, we see each byte of the input `flag.txt` file is manipulated by the `encode_byte()` function that adds the `key` value to the current byte value and takes the modulo of `256` to keep it within an 8-bit byte range.

    $ cat encrypt.py 
    import socket

    def encode_byte(b, key):

        return (b + key) % 256

    def simulate_flag_transfer(filename, key=42):
        print(f"[!] flag transfer for '{filename}' using encoding key = {key}")

        with open(filename, "rb") as f:
            data = f.read()

        print(f"[+] Encoding and sending {len(data)} bytes...")

        for b in data:
            encoded = encode_byte(b, key)
            pass

        print("Transfer complete")

    if __name__ == "__main__":
        simulate_flag_transfer("flag.txt") 

I modified this script slightly to output the encoded byte stream to a file for further analysis. Encrypting a dummy `flag.txt` file I used the resultant encrypted byte stream to attempt to find the `picoCTF` flag prefix within the packet capture file loaded into [Wireshark](https://www.wireshark.org/).

This sequence was not found anywhere within the packet capture.

I then tried exporting the data from all packets within the packet capture via Wireshark:
- Right-clicking on any of the data packets and selecting `Follow > TCP Stream` from the context menu
- Switching the `Show data as` selection to `Raw`.
- Using `Save as...` to export to a binary file `encoded-byte-stream.bin`

A `decrypt.py` script was then created to reverse the encryption performed by the provided `encrypt.py` script on the data within the packets, reusing the original script with minimal modifications:

    #!/usr/bin/env python3

    import socket

    def decode_byte(e, key):
        return (e - key) % 256

    def simulate_flag_transfer(filename, key=42):
        print(f"[!] Decrypting '{filename}' using encoding key = {key}")

        with open(filename, "rb") as f:
            data = f.read()

        print(f"[+] Decoding and exporting {len(data)} bytes...")

        decoded_data = bytearray()
        for b in data:
            d = decode_byte(b, key)
            decoded_data.append(d)

        # save decoded data to file for analysis
        with open("decoded.data", "wb") as binary_file:
            binary_file.write(decoded_data)

        print("Transfer complete")

    if __name__ == "__main__":
        simulate_flag_transfer("encoded-byte-stream.bin") 

Running this `decrypt.py` yields a `decoded.data` file containing the decrypted byte stream. Inspecting the raw contents of the `decoded.data` file, presents a familiar signature/identifier within what is the file header `JFIF` (JPEG File Interchange Format). 

    $ hd decoded.data 
    00000000  ff d8 ff e0 00 10 4a 46  49 46 00 01 01 00 00 01  |......JFIF......|
    00000010  00 01 00 00 ff db 00 43  00 08 06 06 07 06 05 08  |.......C........|
    00000020  07 07 07 09 09 08 0a 0c  14 0d 0c 0b 0b 0c 19 12  |................|
    00000030  13 0f 14 1d 1a 1f 1e 1d  1a 1c 1c 20 24 2e 27 20  |........... $.' |
    00000040  22 2c 23 1c 1c 28 37 29  2c 30 31 34 34 34 1f 27  |",#..(7),01444.'|
    00000050  39 3d 38 32 3c 2e 33 34  32 ff db 00 43 01 09 09  |9=82<.342...C...|
    00000060  09 0c 0b 0c 18 0d 0d 18  32 21 1c 21 32 32 32 32  |........2!.!2222|
    00000070  32 32 32 32 32 32 32 32  32 32 32 32 32 32 32 32  |2222222222222222|

## Solution ##

From here the solution is simple, renaming the file to have a `.jpg` extension and opening in an image viewer of choice yields an image with the flag as text within the image.

Where the resultant image and actual flag value are redacted for the purposes of this write up.
