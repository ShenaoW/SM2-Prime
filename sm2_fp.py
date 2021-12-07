'''
基于素域的 SM2算法实现
杂凑函数使用 sha256 or sm3
曲线使用国密局推荐的素数域 256位椭圆曲线
author：ShenaoW
'''

import hashlib
from Crypto.Util.number import *
import sm3

p=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

def add_point(x1, y1, x2, y2):    #点加转化为域元素进行运算
    if x1!=x2:
        lamda = ((y2-y1)*inverse((x2-x1),p))%p   #在有限域中，除法运算即求逆！
        x3=((lamda**2)%p-x1-x2)%p
        y3 = ((lamda*(x1-x3))%p-y1)%p
    else:
        lamda = ((3*(x1**2)%p+a)*inverse(2*y1,p))%p
        x3=((lamda**2)%p-2*x1)%p
        y3=(lamda*(x1-x3)%p-y1)%p
    return x3,y3

def multiply_point(k, x1, y1):    #倍点运算递归转化为加法运算
    if k == 1:
        return x1, y1
    elif k == 2:
        return add_point(x1, y1, x1, y1)
    elif k % 2 == 0:
        x, y = multiply_point(k // 2, x1, y1)
        x, y = multiply_point(2, x, y)
        return x,y
    elif k % 2 == 1:
        x, y = multiply_point((k - 1) // 2, x1, y1)
        x, y = multiply_point(2, x, y)
        x, y = add_point(x, y, x1, y1)
        return x, y

# multiply_point test
# x,y=multiply_point(k,Gx,Gy)
# print(hex(x),hex(y))
#
# x2,y2=multiply_point(k,xb,yb)
# print(hex(x2),hex(y2))

def KDF(Z,klen):
    # 杂凑算法用sha256 or sm3
    v=256
    ct=0x00000001
    H=[]
    K=''
    interation = ceil_div(klen, v)
    #分块产生密钥
    for i in range(0,interation):
        # 杂凑函数用sha256
        # m=hashlib.sha256()
        # m.update(bytes(bin(Z)[2:]+bin(ct)[2:].zfill(32),encoding='UTF8'))   #将 int转化为 str，再转化为 bytes类型进行 hash
        # H.append(bin(int(m.hexdigest(),16))[2:].zfill(v))

        # 杂凑函数用sm3
        m = sm3.sm3_hash(bytes(bin(Z)[2:]+bin(ct)[2:].zfill(32),encoding='UTF8'))
        H.append(bin(int(m, 16))[2:].zfill(v))

        ct+=1
    #每块密钥进行拼接，最后一块如果不足256位，用左边比特补齐
    if klen%v == 0:
        for i in range(0,interation):
            K+=H[i]
    else:
        for i in range(0,interation-1):
            K+=H[i]
        K+=H[interation-1][:klen%v]
    #验证密钥生成长度满足预期后再return
    if len(K)==klen:
        return int(K,2)
    else:
        print("KDF error!")

# KDF test
# print(KDF(12138,size(12138)))

def key():
    dB = getRandomNBitInteger(256)
    xb, yb = multiply_point(dB, Gx, Gy)
    return dB, xb, yb

def encrypt(m:bytes,xb,yb):
    m=int(m.hex(),16)
    # print('encrypt:' + str(m))
    k = getRandomRange(1,n)
    C1_x, C1_y = multiply_point(k,Gx,Gy)
    #用未压缩的点到比特串转换，选用未压缩形式
    PC='0x04'
    C1=int(PC[2:]+hex(C1_x)[2:]+hex(C1_y)[2:],16)
    # S_x,S_y=multiply_point(h,xb,yb)  无穷远点如何定义？
    x2,y2 = multiply_point(k,xb,yb)
    # print('encrypt:' + str(x2) + str(y2))
    t=KDF(int(bin(x2)[2:]+bin(y2)[2:],2),klen)
    C2= m ^ t

    # 杂凑函数用sha256
    # C3_hash = hashlib.sha256()
    # C3_hash.update(bytes(bin(x2)[2:]+bin(m)[2:]+bin(y2)[2:],encoding='UTF8'))
    # C3 = int(C3_hash.hexdigest(),16)

    # 杂凑函数用sm3
    C3 = int(sm3.sm3_hash(bytes(bin(x2)[2:]+bin(m)[2:]+bin(y2)[2:],encoding='UTF8')),16)
    # C=bin(C1)[2:]+bin(C2)[2:]+bin(C3)[2:]
    C = hex(C1)[2:]+hex(C2)[2:]+hex(C3)[2:]
    return C1_x,C1_y,C2,C3,C

# encrypt test
# print(encrypt(b'hello world'))

def decrypt(C1_x,C1_y,C2,C3,dB):
    if (C1_x**3+(a*C1_x)+b)%p != (C1_y**2)%p:
        print('C1 check error!')
        return False
    else:
        x2,y2=multiply_point(dB,C1_x,C1_y)
        # print('decrypt:'+str(x2)+str(y2))
        t = KDF(int(bin(x2)[2:] + bin(y2)[2:], 2), klen)
        m=C2^t
        # print('decrypt:'+str(m))

        # 杂凑函数用sha256
        # u_hash=hashlib.sha256()
        # u_hash.update(bytes(bin(x2)[2:]+bin(m)[2:]+bin(y2)[2:],encoding='UTF8'))
        # u=int(u_hash.hexdigest(),16)

        # 杂凑函数用sm3
        u = int(sm3.sm3_hash(bytes(bin(x2)[2:]+bin(m)[2:]+bin(y2)[2:],encoding='UTF8')),16)

        if u != C3:
            print('C3 check error!')
            return False
        else:
            M = bytes.fromhex(hex(m)[2:])  # 截取得到 hexstr
            return M

if __name__ == '__main__':
    #明文处理
    m = bytes(input(),encoding='UTF8')
    print('plaintext:',m)
    klen = size(int(m.hex(),16))
    #公私钥生成
    dB, xb, yb = key()
    print('secret key:',dB)
    print('public key:',(xb,yb))
    #调用SM2进行加解密
    C1_x,C1_y,C2,C3,C = encrypt(m, xb, yb)
    print('ciphertext:',C)
    print('result:',decrypt(C1_x, C1_y, C2, C3, dB))
