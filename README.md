# SM2-Prime

基于素数域的SM2的简单实现。

A simple implementation of SM2 based on the prime domain.



**公钥Pb，私钥db，密文C1 || C2 || C3，明文M**

### 加密流程

![SM2加密流程](https://s2.loli.net/2022/01/09/2O9wMmounHCKE4F.png)



### 解密流程

![SM2解密流程](https://s2.loli.net/2022/01/09/hLPgloDr7vmfZXc.png)





**C1：基点的随机倍点运算结果，可以用于验证椭圆曲线和解密**

**C2：明文有关的杂凑值，其中t是由密钥派生函数生成，x2y2是公钥的倍点运算结果**

**C3：明文有关的杂凑值，x2 M y2的拼接，用于正确性验证**



用户密钥对需要满足：

![image-20211201162825490](https://s2.loli.net/2022/01/09/flTI45ZDWQLFOAY.png)

基点的选取：

![image-20211201162916628](https://s2.loli.net/2022/01/09/yhG7gLdos3Xf4uR.png)

椭圆曲线推荐参数：

![image-20211201162953261](https://s2.loli.net/2022/01/09/si4YVqjwnM8cOH7.png)

![素域加法](https://s2.loli.net/2022/01/09/F2Nd49g6mrpWPkL.png)

![素域倍点](https://s2.loli.net/2022/01/09/ZufCQS5dTVwP7rj.png)



