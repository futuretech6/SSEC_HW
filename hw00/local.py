# local.py
from pwn import *
context.log_level = 'DEBUG'     # 将pwntools的日志级别记为调试

# 计算flag
mask = 0xffffffff


def tea_encrypt(v, k):          # 由于py的整形不同于C，所以要加上许多的与操作限制32位长
    v0, v1 = v[0], v[1]
    sums = 0
    delta = 0x9e3779b9
    k0, k1, k2, k3 = k[0], k[1], k[2], k[3]
    for i in range(32):
        sums += delta
        sums &= mask
        v0 += (((v1 << 4)) + k0) ^ (v1 + sums) ^ (((v1 >> 5)) + k1)
        v0 &= mask
        v1 += (((v0 << 4)) + k2) ^ (v0 + sums) ^ (((v0 >> 5)) + k3)
        v1 &= mask
    result = b""
    result += p32(v0)
    result += p32(v1)
    return result


# 获知的key和目标
key = b"\xaa" * 16
verify = b"\xf2\xaf\x3c\xe2\xbb\xc2\xa2\xd0\x69\x41\x92\x3c\xda\x4a\x02\xb1\xd7\xdd\xcf\xac\x6d\xcc\x62\x16\x17\x00\x3d\x6c\xc5\x60\x65\x21"
keys = [0, 0, 0, 0]
keys[0] = u32(key[:4])
keys[1] = u32(key[4:8])
keys[2] = u32(key[8:12])
keys[3] = u32(key[12:16])

output = b""
for i in range(0, 32, 8):
    v = [0, 0]
    v[0] = u32(verify[i: i + 4])
    v[1] = u32(verify[i + 4: i + 8])
    output += tea_encrypt(v, keys)

conn = remote("47.99.80.189", 11000)    # pwntools通过socket连接至远端
conn.recvuntil("ID:\n") # 远程环境统一要求输入学号    
conn.sendline("3180103012")  #

conn.recvuntil("flag:\n")    # 交互至接受完 "flag:\n"
conn.sendline(output)        # 发送计算的flag
print(conn.recv())           # 获知结果
