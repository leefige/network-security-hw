# 网络安全工程 实验4: Linux 系统口令破译

## 实验要求

Linux下`passwd`生成如下口令

```text
test:$6$dRf2Gldj$W4DfAK9vGyz9XCCJrsPOtR7tgf3q6lDH92k
E2WKHNXZHfmu7dKFgo5M72jrL2hXJjxcdg596WsWPYYgGr
mPZp1:17107:0:99999:7:::
```
请破解口令明文

> 提示：该口令只有5个ASCII字符

## 密文分析

Linux下加密的口令保存在`/etc/shadow`下，只有root用户权限能够查看

保存加密后的密码和用户的相关密码信息，每一行代表一个用户，每一行通过冒号':'分为九个部分：

1. 用户名
2. 加密后的密码
3. 上次修改密码的时间(从1970.1.1开始的总天数)
4. 两次修改密码间隔的最少天数，如果为0，则没有限制
5. 两次修改密码间隔最多的天数,表示该用户的密码会在多少天后过期，如果为99999则没有限制
6. 提前多少天警告用户密码将过期
7. 在密码过期之后多少天禁用此用户
8. 用户过期日期(从1970.1.1开始的总天数)，如果为0，则该用户永久可用
9. 保留

那么，原密文可以分解为：

1. 用户名: test
2. 密码: `$6$dRf2Gldj$W4DfAK9vGyz9XCCJrsPOtR7tgf3q6lDH92kE2WKHNXZHfmu7dKFgo5M72jrL2hXJjxcdg596WsWPYYgGrmPZp1`
3. 17107
4. 0
5. 99999
6. 7

其他部分为空。

因此，我们只需要对密码的密文部分进行破解

## 密码破译

密码密文具有如下格式：

```txt
$id$salt$encrypted
```

其中`id`表示加密算法; `salt`表示盐值(Salt), 由系统随机生成, 作用是混合入加密算法，使得即使是同一个密码，使用同一种加密方式，所产生的密文值也不同(类似密钥);`encrypted`表示密文。

`id`包含如下种类：

- 1: MD5
- 2a: Blowfish
- 2y: Blowfish
- 5: SHA-256
- 6: SHA-512

可见本密文中`id`为6，即SHA-512算法


## Reference

\[1\][Understanding /etc/shadow file](https://www.cyberciti.biz/faq/understanding-etcshadow-file/)

\[2\][Linux下的密码Hash——加密方式与破解方法的技术整理](https://3gstudent.github.io/3gstudent.github.io/Linux%E4%B8%8B%E7%9A%84%E5%AF%86%E7%A0%81Hash-%E5%8A%A0%E5%AF%86%E6%96%B9%E5%BC%8F%E4%B8%8E%E7%A0%B4%E8%A7%A3%E6%96%B9%E6%B3%95%E7%9A%84%E6%8A%80%E6%9C%AF%E6%95%B4%E7%90%86/)

\[3\][linux密码暴力破解之SHA-512破解](https://blog.csdn.net/Key_book/article/details/80439243)
