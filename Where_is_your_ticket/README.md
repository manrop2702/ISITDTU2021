
## ISITDU CTF 2021

---

This is my first challenge I've ever written. The challenge is for my univeristy (Duy Tan University) CTF - ISITDTU CTF.

---

# Challenge `Where is your ticket?`

Category: Crypto

* Source: https://github.com/manrop2702/ISITDTU2021/blob/main/Where_is_your_ticket/challenge/wheres_your_ticket.py

* Description: 
    - All the rich (**_royal_**) people are invited to my party. I will show them my big and shiny secret Flag.
    - No peasant is allowed.
    - Information about you is encrypted, it will be your identity.
    - The guards will check your identity with the **_Signature_** before letting you in, so don't think about lying.

* Server: `nc 34.125.6.66 5000`

Access to the server and you will see this:

```
Your role: guest
Encrypted data of your role:
Encrypted: b8bf9e1b29187db0f8221c7f143923734533d69b5a726e7ecab62aa30226ec37977c9c52fa0335724be032d59c516ed7
Signature: 7d9d7c5a60b221e63b19bc3b0d91c44d
1. Verify your data:
2. Sign your data in new way:
3. Sign your data in old way:
4. Quit
Your choice:
```

Basically, the challenge give us a role as a <span style="color:green">guest</span>. Base on the description and the source code, we should find a way to change our identity to <span style="color:red">royal</span>.

Here is the encrypted data of our identity:

```
Encrypted: b8bf9e1b29187db0f8221c7f143923734533d69b5a726e7ecab62aa30226ec37977c9c52fa0335724be032d59c516ed7
Signature: 7d9d7c5a60b221e63b19bc3b0d91c44d
```

It is encrypted using AES-CBC, signed by HMAC.

```python
def encrypt(self, data):
	iv = self._initialisation_vector()
	cipher = self._cipher(self.key, iv)
	pad = self.AES_BLOCK_SIZE - len(data) % self.AES_BLOCK_SIZE
	data = data + (pad * chr(pad)).encode()
	data = iv + cipher.encrypt(data)
	ss = b'name=player101&role=%s'%(hexlify(data))
	sig = self.sign_new(ss)
	return data, sig

def sign_new(self, data):
	return hmac.new(self.key, data, md5).digest()
```

So what we get is the encryption of `our-role` (enc_role), and a HMAC signature of `name=player101&role=enc_role`.

On the server, we can do 3 things:
1. Send the encrypted data and its signature to verify and check the identity.
2. Sign the input data in _new way_ (HMAC):
3. Sign the input data in _old way_:
   
```python
def sign_old(self, data):
    return md5(self.xor_key(data)).digest()
```

If we try to sign `name=player101&role=something` with HMAC then we would receive this message:

```
Not that easy!
```

So no easy way.

The idea is to apply `Hash length extension attack`, which is not doable on HMAC.
However, the challenge gives us not only the HMAC, but also the old hashing method that is vulnerable to the attack.

If we look at the HMAC source code, it's basically implemented like this:

> `HMAC(data, key) = hash(key ^ (\x5c*blocksize) + hash(key ^ (\x36*blocksize) + data))`

And the old message authentication:

> `hash(key ^ data)`

Ok so here we will do some magic tricks:

The hashing this challenge uses is MD5, so block size will be `md5().digest_size = 64`

First, add `64*(\x36)` to our data "`hello`" to sign the old way, :

> `hash(key ^ "64*(\x64) + hello")`

Then add `64*(\x5c)` to the hash we just got, sign the old way:

> `hash(key ^ "64*/x5c" + hash(key ^ "64*(\x64) + hello")) = HMAC("hello", key)`

So here we just created the HMAC of our data.

In order to change our identity, we have to change our encrypted data so that when it get decrypted, it'll become `"royal"`.

We don't have the key, so all we can do is rely on what the server gave us.

When `nc` to the server first thing we got was an encrypted data of `"guest"`.
Remember it was encrypted with AES-CBC, so bit flip is the way.

After bit-flipping the original data, we have to generate the HMAC of the new data using the above method.

Finally we will have the new data which will be decrypted to `"royal"` and its HMAC signature.

Verify it and we should get the flag.

Here's the implemented code in python:

```python
from hashpumpy import hashpump
from pwn import *
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from hashlib import md5

r = remote("34.125.6.66", 5000)
r.recvuntil(b'Encrypted: ')
enc_role = unhexlify(r.recvuntil(b'\n').strip(b'\n'))

print(f"Enc Data: {hexlify(enc_role).decode('utf-8')}")

payload = f"name=player101&role={hexlify(enc_role).decode('utf-8')}"
print(f"Payload: {payload}")

r.sendlineafter(b"Your choice: ", b'3')
r.sendlineafter(b"Your data: ", payload.encode())
r.recvuntil(b'Hash: ')
sign = r.recvuntil(b'\n').strip(b'\n')
print(f"Hash   : {sign.decode()}\n")
payload_36 = "\x36"*64 + f"name=player101&role={hexlify(enc_role).decode('utf-8')}"
print(f"Payload_36: {payload_36}")

r.sendlineafter(b"Your choice: ", b'3')
r.sendlineafter(b"Your data: ", payload_36.encode())
r.recvuntil(b'Hash: ')
sign_36 = r.recvuntil(b'\n').strip(b'\n')
print(f"Hash_36 : {sign_36.decode()}\n")
xor_a = xor(b'guest', b'royal')
bitflip = xor(xor_a, enc_role[:5]) + enc_role[5:]
print(f"Original enc: {hexlify(enc_role).decode('utf-8')}")
print(f"Flipped enc : {hexlify(bitflip).decode('utf-8')}")

new_payload = b'&role=' + hexlify(bitflip)
new_key, new_msg = hashpump(sign_36, payload_36[64:].encode('utf-8'), new_payload, 64)
print(f"New hash: {new_key}")
print(f"New payload: {new_msg}\n")
payload_5c = b"\x5c"*64 + unhexlify(new_key)
print(f"Payload_5c: {payload_5c}")

r.sendlineafter(b"Your choice: ", b'3')
r.sendlineafter(b"Your data: ", payload_5c)
r.recvuntil(b'Hash: ')
sign_5c = r.recvuntil(b'\n').strip(b'\n')
print(f"Hash_5c : {sign_5c.decode()}\n")
final_payload = b"%s&sign=%s"%(new_msg, sign_5c)
print(f"Final payload: {final_payload}")

r.sendlineafter(b"Your choice: ", b'1')
r.sendlineafter(b"Your data: ", final_payload)
print(r.recvuntil(b'Your role:').strip(b'\nYour role:'))
```

Result:

```
[+] Opening connection to 34.125.6.66 on port 5000: Done
Enc Data: 846e6bba925edeb52c8d104a490e1193bce7a94beeef3a884a0a2bfcbd671b2e7daa4ed01c6d93f6693222ea6f969fec
Payload: name=player101&role=846e6bba925edeb52c8d104a490e1193bce7a94beeef3a884a0a2bfcbd671b2e7daa4ed01c6d93f6693222ea6f969fec
Hash   : 0c8b04010691b7fd8a3c82be3972dbab

Payload_36: 6666666666666666666666666666666666666666666666666666666666666666name=player101&role=846e6bba925edeb52c8d104a490e1193bce7a94beeef3a884a0a2bfcbd671b2e7daa4ed01c6d93f6693222ea6f969fec
Hash_36 : 5c8d998d03c7194b718e65c6249f8b1d

Original enc: 846e6bba925edeb52c8d104a490e1193bce7a94beeef3a884a0a2bfcbd671b2e7daa4ed01c6d93f6693222ea6f969fec
Flipped enc : 917477a88a5edeb52c8d104a490e1193bce7a94beeef3a884a0a2bfcbd671b2e7daa4ed01c6d93f6693222ea6f969fec
exploit.py:35: DeprecationWarning: PY_SSIZE_T_CLEAN will be required for '#' formats
  new_key, new_msg = hashpump(sign_36, payload_36[64:].encode('utf-8'), new_payload, 64)
New hash: 4900cd7433772fc059eff335d6fa924a
New payload: b'name=player101&role=846e6bba925edeb52c8d104a490e1193bce7a94beeef3a884a0a2bfcbd671b2e7daa4ed01c6d93f6693222ea6f969fec\x80\x00\x00\x00\xa0\x05\x00\x00\x00\x00\x00\x00&role=917477a88a5edeb52c8d104a490e1193bce7a94beeef3a884a0a2bfcbd671b2e7daa4ed01c6d93f6693222ea6f969fec'

Payload_5c: b'\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\I\x00\xcdt3w/\xc0Y\xef\xf35\xd6\xfa\x92J'
Hash_5c : ff3e757062b709ea9d9709d591b10f2a

Final payload: b'name=player101&role=846e6bba925edeb52c8d104a490e1193bce7a94beeef3a884a0a2bfcbd671b2e7daa4ed01c6d93f6693222ea6f969fec\x80\x00\x00\x00\xa0\x05\x00\x00\x00\x00\x00\x00&role=917477a88a5edeb52c8d104a490e1193bce7a94beeef3a884a0a2bfcbd671b2e7daa4ed01c6d93f6693222ea6f969fec&sign=ff3e757062b709ea9d9709d591b10f2a'
b'Flag here: ISITDTU{p34s4nts_w1LL_n0T_f1Nd_mY_S3cr3t}'
[*] Closed connection to 34.125.6.66 port 5000
```

Flag: ISITDTU{p34s4nts_w1LL_n0T_f1Nd_mY_S3cr3t}