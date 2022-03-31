from __future__ import print_function
from sqlite3 import apilevel

import sys
import time
import Crypto.Cipher.AES
import Crypto.Hash
import Crypto.Protocol
import Crypto.Util.Padding

import hashlib
import hmac
import os

def eprint(*args, **kwargs):							# from https://stackoverflow.com/a/14981125
	print(*args, file=sys.stderr, **kwargs)

def getTimestamp():
	return int(time.time())

def getTimestampMs():
	return int(round(time.time() * 1000))

def mergeDicts(x, y):									# from https://stackoverflow.com/a/26853961
	if x is None and y is None:
		return
	z = (y if x is None else x).copy()
	if x is not None and y is not None:
		z.update(y)
	return z

def getAttr(obj, key, alt=None):
	return obj[key] if isinstance(obj, dict) and key in obj else alt

def filterNone(obj):
	if isinstance(obj, dict):
		return dict((k, filterNone(v)) for k, v in obj.items() if v is not None)
	elif isinstance(obj, list):
		return [filterNone(entry) for entry in obj]
	else:
		return obj

def getNumValidKeys(obj):
	return len(list(filter(lambda x: obj[x] is not None, list(obj.keys()))))

def encodeUTF8(s):
	if not isinstance(s, str):
		s = s.encode("utf-8")
	return s


def ceil(n):											# from https://stackoverflow.com/a/32559239
	res = int(n)
	return res if res == n or n < 0 else res+1

def floor(n):
	res = int(n)
	return res if res == 0 or n >= 0 else res-1

def HmacSha256(key, sign):
    return hmac.new(key, sign, hashlib.sha256).digest()

def HKDF(key, length, appInfo=b""):						# implements RFC 5869, some parts from https://github.com/MirkoDziadzka/pyhkdf
    key = HmacSha256(b"\0"*32, key)
    keyStream = b""
    keyBlock = b""
    blockIndex = 1
    while len(keyStream) < length:
        keyBlock = hmac.new(key, msg=keyBlock+appInfo+blockIndex.to_bytes(1, byteorder='big'), digestmod=hashlib.sha256).digest()
        blockIndex += 1
        keyStream += keyBlock
    return keyStream[:length]

def to_bytes(n, length, endianess='big'):
    h = '%x' % n
    s = bytearray.fromhex(('0'*(len(h) % 2) + h).zfill(length*2)).decode()
    return s if endianess == 'big' else s[::-1]    

def AESPad(s):
    bs = Crypto.Cipher.AES.block_size
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

def AESUnpad(s):
    return s[:-ord(s[len(s)-1:])]

def bchr(s):
    return bytes([s])


def pad(data_to_pad, block_size, style='pkcs7'):
    padding_len = block_size-len(data_to_pad)%block_size
    if style == 'pkcs7':
        padding = bchr(padding_len)*padding_len
    elif style == 'x923':
        padding = bchr(0)*(padding_len-1) + bchr(padding_len)
    elif style == 'iso7816':
        padding = bchr(128) + bchr(0)*(padding_len-1)
    else:
        raise ValueError("Unknown padding style")
    return data_to_pad + padding

def AESEncrypt(key, plaintext):
    plaintext = pad(plaintext, Crypto.Cipher.AES.block_size)
    iv = os.urandom(Crypto.Cipher.AES.block_size)
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    return iv + cipher.encrypt(plaintext)

def AESDecrypt(key, ciphertext):
    iv = ciphertext[:Crypto.Cipher.AES.block_size]
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[Crypto.Cipher.AES.block_size:])
    return AESUnpad(plaintext)

def WhatsAppEncrypt(encKey, macKey, plaintext):
    enc = AESEncrypt(encKey, plaintext)
    return HmacSha256(macKey, enc) + enc


def convertToSeconds(tm):
    return tm.second + tm.minute*60 + tm.hour*60*60