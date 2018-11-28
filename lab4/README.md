# 网络安全工程 实验4: 密码学

## Part 1: Linux 系统口令破译

### 实验要求

Linux下`passwd`生成如下口令

```text
test:$6$dRf2Gldj$W4DfAK9vGyz9XCCJrsPOtR7tgf3q6lDH92k
E2WKHNXZHfmu7dKFgo5M72jrL2hXJjxcdg596WsWPYYgGr
mPZp1:17107:0:99999:7:::
```
请破解口令明文

> 提示：该口令只有5个ASCII字符

### 密文分析

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

本密文的`salt`为`dRf2Gldj`

### 密码破译

对于SHA-512算法，目前常用的破解方法主要为字典法和暴力法，较为实用的方法是利用相关软件进行破解。本实验中我们选用[`John the Ripper`](https://www.openwall.com/john/)破解工具，该工具对Linux的用户密码文件破译具有较高的针对性。

#### 实验平台

【乔总补充一下】

#### 工具安装

当前该工具存在一个社区加强版本[`bleeding-jumbo`](https://github.com/magnumripper/JohnTheRipper)，我们选用该版本，将git repo下载到服务器后，根据文档，编辑`Makefile`使其支持OpenMP，再执行`make`即可编译项目

#### 破解过程

由于已知密文的明文长度为5位，所以可以直接指定尝试的长度；同时，由于服务器为多核，可以定义环境变量`OMP_NUM_THREADS`，这样会自动使用OpenMP并行执行，加快破译速度。

```sh
$ export OMP_NUM_THREADS=24
$ run/john lab4 --min-length=5 --max-length=5
```

John the Ripper工具在破译时会首先用字典尝试常见的密码，在失败后，会进入暴力破解。问题中的密文不在工具的字典中，于是进入暴力破解过程，尽管服务器有24核，但仍然预期在12月9日才能穷尽5位的明文空间。

![【插图片】]()

不过事实上，在两小时暴力尝试后就已经破译成功，明文为`tls13`。

### Reference

\[1\] [Understanding /etc/shadow file](https://www.cyberciti.biz/faq/understanding-etcshadow-file/)

\[2\] [Linux下的密码Hash——加密方式与破解方法的技术整理](https://3gstudent.github.io/3gstudent.github.io/Linux%E4%B8%8B%E7%9A%84%E5%AF%86%E7%A0%81Hash-%E5%8A%A0%E5%AF%86%E6%96%B9%E5%BC%8F%E4%B8%8E%E7%A0%B4%E8%A7%A3%E6%96%B9%E6%B3%95%E7%9A%84%E6%8A%80%E6%9C%AF%E6%95%B4%E7%90%86/)

\[3\] [linux密码暴力破解之SHA-512破解](https://blog.csdn.net/Key_book/article/details/80439243)

\[4\] [John the Ripper password cracker](https://github.com/magnumripper/JohnTheRipper/tree/bleeding-jumbo/doc)

## Part 2: 清华校园网身份认证及单点登录安全分析

### 实验要求

通过调研、实验操作等各种手段，给出你所认为的认证方法和过程（包括SSO），指出可能的威胁（给出具体的攻击方法，尽可能验证）

### 清华校园网联网方式

当前清华校园网包括有线的Ethernet（支持IPv4和IPv6，仅考虑IPv4）和无线网络（Tsinghua, Tsinghua 5G, 不考虑DIVI等支持IPv6协议栈的无线连接）。联网过程分为如下步骤：

1. 将网线接入主机，或连接清华无线网络Tsinghua/Tsinghua 5G
2. 通过DHCP，从校园网的DHCP服务器获取IP地址
3. 进行认证，获取网络访问能力

清华校园网支持的认证方式主要有两种：1）通过web页面进行认证；2）通过客户端进行认证。本实验将对PC端上两种认证方式进行分析

### 实验平台

- OS: Windows 10 Professional Build 1809
- 浏览器: Microsoft Edge 44.17763.1.0
- 认证客户端: TUnet 2015版

### 1) Web页面认证

当前清华校园网的web页面认证已经支持HTTPS，下面的分析均基于HTTPS，通过验证，HTTP的过程相似。

另外，本实验针对无线网Tsinghua进行实验，Ethernet理论上应该过程类似，但近期似乎由于校园网的一些变动，Ethernet需要通过`auth4.tsinghua.edu.cn`验证，而非像无线网络一样使用`net.tsinghua.edu.cn`，因此可能会有细节上的不同之处。

#### 工具配置

为了监听HTTPS链接的内容，使用了`Fiddler`工具，通过MITM（中间人攻击）类似方法，由`Fiddler`生成一个CA根证书，信任该证书后，即可由`Fiddler`为站点签发证书，从而实现HTTPS监听。

在未配置CA证书前，如果试图监听HTTPS通信，可以看到`Fiddler`通过一个HTTP tunnel直接传输加密通信，无法获取其中内容

![](fig/web/tunnel.PNG)

配置CA证书，`Fiddler`会随机生成一个根证书，需要使用者信任并将其添加到OS的信任根证书库中

![](fig/web/trust.PNG)
![](fig/web/warn.PNG)

随后再监听HTTPS链接，可以看到传输的具体内容

![](fig/web/decrypt.PNG)

#### 过程分析

下面具体分析认证过程（无线网络）。截获的部分脚本保存在`code/`目录下，下文提到的脚本均位于此处。

##### 1. 登录

首先，在浏览器中访问`https://net.tsinghua.edu.cn`，该站点会将用户重定向到`https://net.tsinghua.edu.cn/wireless`，该站点的response为我们熟悉的认证页面

![](fig/web/page.PNG)

部分HTML如下，用户在该页面输入用户名和密码，提交，触发`do_login()`函数，该函数定义在`login.js`中

```html
<head>
    ...
    <script src="/script/jquery.js"></script>
    <script src="util.js"></script>
    <script src="md5.js"></script>
    <script src="login.js"></script>
</head>

<body id="non_phone">
    <div id="center">
        ...
        <div id="login">
            <form name="login_form" id="login_form" action="/do_login.php" method="post"
                    onkeydown="if(event.keyCode==13)do_login();" onsubmit="do_login();">
                ...
                <div class="field">
                    <div class="label_text" for="uname">用户名<p class="english">User&nbsp;ID</p>
                    </div> <input type="text" name="uname" id="uname" value="" autocorrect="off" autocapitalize="off">
                </div>
                <div class="field">
                    <div class="label_text" for="pass">密码<p class="english">Password</p>
                    </div> <input type="password" name="pass" id="pass" autocorrect="off" autocapitalize="off">
                </div>
                <div class="field" id="remember"> <input type="checkbox" name="save_me" id="cookie" value="yes">
                    <div class="checkbox_text">记住密码<p class="english">Remember&nbsp;Password</p>
                    </div>
                </div> <a id="account" href="https://usereg.tsinghua.edu.cn" title="账户设置&#10;Account&nbsp;Settings">账户设置
                    <p class="english">Account&nbsp;Settings</p></a> <input type="button" name="connect" id="connect" onclick="do_login();">
            </form>
        </div>
    </div>
</body>
```
在`login.js`中，`do_login()`定义为

```js
function do_login() { 	
    var uname = $('#uname').val();
    var pass = $('#pass').val();
    var ac_id = $('#ac_id').val();
    if (uname == '') {
        alert("请填写用户名");
        $('#uname').focus();
        return;
    }

    if (pass == '') {
        alert("请填写密码");
        $('#pass').focus();
        return;
    }
    //var topost = "action=login&username=" + uname + "&password={MD5_HEX}" + CryptoJS.MD5(pass) +
    var topost = "action=login&username=" + uname + "&password={MD5_HEX}" + hex_md5(pass) +
        "&ac_id="+ac_id;
	//alert(topost);
    //var res = post('/do_login.php', topost);
    $.post("/do_login.php", topost, function(res) {
   	if(res == "Login is successful.") {
            nav = navigator.userAgent.toLowerCase();
            var pp_nav = /safari/;
            var pp_mac = /mac/;
            if(pp_nav.test(nav) || (!pp_mac.test(nav))) {
            	if ($('#cookie')[0].checked) {
            	    $.cookie('tunet', uname + '\n' + pass,
            	        { expires: 365, path: '/' });
            	} else {
            	    $.cookie('tunet', null);
            	}
            }
            window.location="succeed.html";
	} else if(res == "IP has been online, please logout.") {
            alert("您已在线了");
	} else {
            var msg111 = get_err(res);
                        if(msg111 == "用户被禁用或无联网权限")
                        {
                                alert(res+" or max_online_num=0" + "("+msg111+")")
                        }
                        else
                        {
                                alert(res+"("+msg111+")");
                        }

        }
    }); 
}
```

可见，该函数会向`/do_login.php`发送POST，表单中包含用户名、密码等信息，其中密码是使用`md5.js`提供的`hex_md5()`进行MD5加密过的。随后，若用户选择了“记住我”，那么用户名和密码（ **注意** ：cookie中保存的密码为明文！！！）会被记录在本地的cookie中。

一个POST实例如下：

![](fig/web/do_login.PNG)

登录成功后，会跳转至`/wireless/succeed.html`，该页面加载完成后会调用`succeed.js`，查询用户在线状态：

```js
$(document).ready(function() {
	var r = post('/rad_user_info.php');
    var a = r.split(',');
    $('#uname').text(a[0]);
    var f = a[6] / 1000000000;
    if (f <=25) {
        len = f * 106 / 25
    } else if (f >25 && f <=55) {
	len = 106 + (f - 25) * (53 * 3) / 30
    } else {
	len = 280
    }
    //tm = Number(a[4]);
    tm = Number(a[2]-a[1]);
    $('#usage_value').css('width', len + 'px');
    $('#usage_flux').text(format_byte(a[6]));
    myclock();
});
```

通过POST到`/rad_user_info.php`，服务器会返回包括用户已用流量在内的用户信息如下：

![](fig/web/user_info.jpg)

至此，登录成功。

![](fig/web/success.jpg)

##### 2. 登出

登出时，只需点击页面上的“断开链接”按钮，这会调用`succeed.js`中的`do_logout()`函数

```js
function do_logout() {
	var topost = "action=logout";
    var res = post('/do_login.php', topost);
	if(res == "Logout is successful.")
	{
		alert("连接已断开");
        	window.location.href="/";
	}
	else
	{
		alert(res);
	}
	
	return;
    var code = {
        'logout_ok': '连接已断开',
        'not_online_error': '您不在线上'
    }[res];

    if (code) {
        alert(code);
       	window.location.href="/";
        //window.close();
    } else {
        alert('操作失败');
       	window.location.href="/";
    }
}
```

该函数向`/do_login.php`POST一个`logout`的action，服务器终止当前连接如下：

![](fig/web/logout.PNG)

##### 3. 在HTTP上的情况

在HTTP下情况类似，登录时同样用了MD5对用户名加密

![](fig/web/http_login.PNG)

但是，问题在于，HTTP request中都会包含cookie字段，而如果用户保存了密码，密码会以明文形式出现在该字段中，HTTP本身又是明文传输，那么用户名和密码的明文将可能被任何监听所截获！

![](fig/web/http_cookie.jpg)

### 2) 客户端(SRUN)认证

#### 过程分析

### 可能的攻击方案


### Reference

\[1\] [网络抓包工具 wireshark 入门教程](https://blog.csdn.net/zjy900507/article/details/79303359)

\[2\] [突破https——https抓包](https://blog.csdn.net/justfwd/article/details/78767328)

\[3\] [Fiddler抓取https设置详解](https://www.cnblogs.com/joshua317/p/8670923.html)
