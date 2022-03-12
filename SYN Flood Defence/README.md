## SYN Flood 防御

### 介绍

------

此存储库代码用于部署在`p4`交换机上，用于清洗SYN-Flood流，来实现简单和初步SYN-Flood防御。

SYN-Flood攻击是利用TCP协议三次握手机制的漏洞，攻击者通常利用工具或者控制僵尸主机向服务器发送海量的`变源IP`地址或变源端口的TCP SYN报文，服务器响应了这些报文后就会生成大量的半连接，当系统资源被耗尽后，服务器将无法提供正常的服务。

### 防御策略

------

由于交换机的特性，我们使用首保丢弃+源认证的策略进行流量清洗，来进行初步的防御。

#### 禁止源IP：

根据SYN-Flood攻击的特性，我们统计`SYN`和`ACK`包的数目，并给定一个阈值，如果超过此阈值，我们将对此`IP`写入黑名单，并不接受此`IP`的数据包。

#### 首保丢弃：

SYN Flood攻击时，黑客发送的绝大多数是**变源**的SYN报文，所有的SYN报文对于交换机来说都是首包，都将被直接丢弃。这样可以大大减少增强源`IP`策略的防御效果。

### P4实现：

------

#### 实验环境

我们将实验部署在`ubuntu16.04`系统上，并安装了以下环境：

* `p4c`:P4代码的编译器
* `Bmv2`：虚拟交换机
* `mininet`：虚拟网络
* `p4-utils`or`p4app`：简化`p4`网络和交换机构建的开发工具
* `hping3`：用于模拟SYN-Flood工具
* `wireshark`：抓包工具

#### 代码逻辑

##### 拓扑结构：

![SYN Flood Defence](D:/%E8%87%AA%E5%B8%A6%E6%96%87%E4%BB%B6/cby/%E6%A1%8C%E9%9D%A2/SYN%20Flood%20Defence.png)

##### 代码结构：

1. 我们需要为交换机添加数据包头，包括`ethernet`、`ipv4`、`tcp`和一些元数据。

2. 编写解析程序，进行数据包协议的解析。

3. 在交换机`Ingress`处编写处理逻辑，使用两个寄存器来实现禁止源`IP`和首保丢弃。

4. 编写应用逻辑：

   1. 如果为首个`IP`发过来的包则丢弃：

      ```p4
      first_drop();
      if(meta.counter_three == (bit<32>)1){
          drop();
           return;
      }
      ```

   2. 更新寄存器，检测`SYN-ACK`是否大于阈值，大于则丢弃，否则就通过。

      ```p4
      update_bloom_filter();
      //only if IPV4 the rule is applied. Therefore other packets will not be forwarded.
      if(meta.counter_one > meta.counter_two){
         if ( (meta.counter_one - meta.counter_two > PACKET_THRESHOLD)){
             drop();
             return;
         }
      }
      ```

5. 为交换机编写`checksum`和`Deparser`将数据包发出。

### 实验结果

------

1. 启动拓扑并编译`p4`程序

   ```bash
   sudo p4run
   ```

2. 检查是否可以`ping`:

   ```mininet
   mininet> pingall
   ```

   ![image-20220312230727125](C:/Users/cby/AppData/Roaming/Typora/typora-user-images/image-20220312230727125.png)

3. 打开虚拟主机终端:

   ```mininet
   mininet> xterm h1 h2
   ```

4. 打开抓包工具进行流量检测：

   ```bash
   sudo wireshark
   ```

5. 在主机`h1`上对`h2`利用`hping3`进行模拟SYN-Flood攻击：

   ```bash
   hping3 -q -n --rand-source -S -p 5001 --faster 10.0.2.2
   ```

   * rand-source：伪造随机源`IP`

   * flood：每秒发送100个数据包

6. 观察`wireshark`曲线：

   ![image-20220312231116753](E:/P4_file/code/SYN%20Flood%20Defence/images/image-20220312231116753.png)

   由数据包曲线分析可知，`h1`发出的攻击数据包从`s1-eth1`端口发出，`h2`从`s2-eth1`端口接受数据包。在防御初期防御有着不错的效果，而随着数据包的增多，会逐渐产生哈希冲突，而导致部分攻击流数据包未能及进行防御。

7. 测量`h3`与`h2`之间能否建立正常TCP链接

   ```bash
   iperf -s
   ```

   ```bash
   iperf -c 10.0.2.2
   ```

   ![image-20220312231449966](E:/P4_file/code/SYN%20Flood%20Defence/images/image-20220312231449966.png)

   由`iperf`测量带宽可知，可以看出`h3`与`h2`在攻击时仍能进行正常连接。

### 实验总结

------

1. 对于基础的`SYN-Flood`攻击，我们部署在`p4`交换机上的流量清洗策略有着不错的防御效果。
2. 由于我们部署的防御策略本身存在一定的先天缺陷，在数据包过多时，会产生哈希冲突而导致防御失效。
3. 本防御策略未对状态攻击进行考虑，因此仍存在不少改进空间。