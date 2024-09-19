from Crypto.Util.number import getPrime

p_512 = getPrime(512)
q1_512 = getPrime(512)
q2_512 = getPrime(512)
q3_512 = getPrime(512)


p_1024 = getPrime(1024)
q1_1024 = getPrime(1024)
q2_1024 = getPrime(1024)

n1_1024 = p_512 * q1_512
n2_1024 = p_512 * q2_512
n3_1024 = p_512 * q3_512

n1_2048 = p_1024 * q1_1024
n2_2048 = p_1024 * q2_1024

e = 65537

phi_n1 = (p_512 - 1) * (q1_512 - 1)
phi_n2 = (p_512 - 1) * (q2_512 - 1)


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def gcd_multiple(*numbers):
    result = numbers[0]
    for num in numbers[1:]:
        result = gcd(result, num)
    return result
#a
print(n1_1024)
print(n2_1024)

#b c
gcd512 = gcd_multiple(n1_1024, n2_1024, n3_1024)
print(f"p:{p_512}")
print(f"GCD of n1 and n2 (shared prime factor p): {gcd512}")


m = 5163

a = phi_n1
b = e
n = n1_1024
# 初始值
x0, x1 = 1, 0
y0, y1 = 0, 1

# 开始算法迭代
while b != 0:
    q = a // b  # 计算商

    # 临时保存 a 和 b
    a_temp = a
    b_temp = b

    # 更新 a 和 b
    a = b
    b = a_temp % b_temp

    # 更新系数 x 和 y
    x_temp = x1
    y_temp = y1
    x1 = x0 - q * x1
    y1 = y0 - q * y1
    x0 = x_temp
    y0 = y_temp

# 此时，a 是 gcd(phi_n, e)，应为 1
# y0 是 e 关于 φ(n) 的模逆
if a == 1:
    d = y0 % phi_n1  # 确保 d 为正数
    print("计算得到的私钥指数 d =", d)
else:
    print("e 和 φ(n) 不互素，无法计算私钥指数 d")


c = 1
for i in range(e):
    c = (c * m) % n  # c = (c * m) mod n

print("加密后的密文 c =", c)

# 解密过程：m' ≡ c^d mod n
# 我们需要计算 c 的 d 次幂，然后对 n 取模
# 由于 d 较大（d = 2753），需要使用重复平方与乘法算法（模幂运算）

# 初始化明文 m'
m_prime = 1
exponent = d  # 指数 d
base = c % n  # 基数为密文 c 对 n 取模

while exponent > 0:
    if exponent % 2 == 1:
        m_prime = (m_prime * base) % n
    exponent = exponent // 2
    base = (base * base) % n

print("解密得到的明文 m' =", m_prime)