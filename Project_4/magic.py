from pwn import *
import os
import time

# avoid printing Opening connection and Closed connection
context.log_level = 'warn'

try:
    start = time.time()
    # compile magic.c
    os.system('gcc -o rand magic.c -Os -s')
    os.system('./rand')
    with open('secret_answer.txt', 'rb') as f:
        secret_answer = f.read()

    r = remote('140.113.24.241', '30171')
    r.recv()
    r.sendline(secret_answer)
    r.recvline()
    print(r.recvregex(b'FLAG{(.*)}').decode('utf-8').split('\n')[-1])
    r.close()
    end = time.time()

    #print(end-start)

    os.system('rm rand')
    os.system('rm secret_answer.txt')
except Exception:
    os.system('rm rand')
    os.system('rm secret_answer.txt')