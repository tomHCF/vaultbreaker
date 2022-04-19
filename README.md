#### Wildfly/Jboss vault passwords decryptor

Original source code: http://hacktracking.blogspot.com/2017/07/decrypt-wildflyjboss-vault-password.html

The code in this repository has been tested with dependencies:
 - hashlib==20081119
 - javaobj-py3==0.2.4
 - pyjks==20.0.0
 - pycrypto==2.6.1

Python version - 2.7.13

Usage: `python2 vaultbreaker.py KEYSTORE_PASSWORD KEYSTORE_ALIAS SALT ITERATION_COUNT KEYSTORE VAULT`
