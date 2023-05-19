# SYN+ ECMP

## Idea

### ECMP:

根据数据包传输路径和地址来计算哈希值，并对哈希值进行求模运算，将值与端口进行映射，来达到随机情况下的链路数据包的负载均衡。

### SYN Defense

基于P4的寄存器来对SYN进行计数，防御策略请阅读[SYN DEFENSE](https://github.com/dmucby/P4-Defense/tree/master/SYN%20Flood%20Defence)，在此处我们进行对防御流表周期性的替换，让攻击者难以获取防御节点和防御策略，通过`P4-Utils`控制器来对交换机的流表进行随即替换。



## Topology

![multi_hop_topo](https://personal-drawing-bed.oss-cn-beijing.aliyuncs.com/img/multi_hop_topo.png)

* `s1` `s6` 交换机负责安装负载均衡计算流表
* `s2 ` `s3` `s4` `s5` 负责进行数据包的清洗



## P4 Switch

### ECMP Implementation

使用[v1mode](https://github.com/p4lang/p4c/blob/main/p4include/v1model.p4)内置哈希函数进行哈希值的计算，通过对`ipv4.srcAddr`、`ipv4.dstAddr`、`tcp.srcPort` `tcp.dstPort` 、`ipv4.protocol`进行哈希计算，通过设置最大值`4`，将结果控制在0~3之间。然后在流表中建立端口与哈希值的单值映射。

#### P4 Code:

```p4
hash(meta.ecmp_hash,
	    HashAlgorithm.crc16,
	    (bit<1>)0,
	    {
          hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol
        },
	      num_nhops);
```

**详细参数如下：**

```p4
@pure
extern void hash<O, T, D, M>(out O result, in HashAlgorithm algo, in T base, in D data, in M max);
```

#### Table rule

```txt
table_add ecmp_group_to_nhop set_nhop 1 0 =>  00:00:00:02:01:00 2
table_add ecmp_group_to_nhop set_nhop 1 1 =>  00:00:00:03:01:00 3
table_add ecmp_group_to_nhop set_nhop 1 2 =>  00:00:00:04:01:00 4
table_add ecmp_group_to_nhop set_nhop 1 3 =>  00:00:00:05:01:00 5
```

在流表中，我们将哈希值`0`与`2`号端口映射，其余值类推可得。

### SYN-Defense

核心代码与[SYN DEFENSE](https://github.com/dmucby/P4-Defense/tree/master/SYN%20%E9%98%B2%E6%B4%AA)类似，在此不再赘述。



## Controller

借用`P4-Utils`天生对`P4`交换机的支持，我们进行如下设定，在一段周期内，控制器将随机对`s2 ` `s3` `s4` `s5` 交换机进行随机选择两个交换机部署防御流表规则，在进行下一周期时，交换机需要重置，因此我们需要补充转发流表规则。

### Defense deployment

```python
nums = [0,0,0,0,0,0]
table1 = random.randint(1,4)
table2 = random.randint(1,4)
nums[table1] = 1
nums[table2] = 1

for i in range(6):
   if(nums[i] == 1):
      sw = "s" + str(i)
      self.controller[sw].table_add("syn_counters", "syn_defence_action", ["1"])
```



## Experimental 

我们使用同样的攻击工具`hping3`，让`h1`对`h2`发动`SYN-Flood`的`DDoS`攻击，通过监控数据包的流量来查看防御效果，由于个人电脑内存限制，我们只进行**百万数据包**级别的攻击测试。

在`h1`终端使用如下攻击命令：

```bash
hping3 -q -n -S -p 5001 --faster 10.0.6.2 
```



### Result

![微信截图_20220429180843](https://personal-drawing-bed.oss-cn-beijing.aliyuncs.com/img/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20220429180843.png)

通过实验结果可看出，`h1`向`s1-eth1`端口发出攻击数据包，然后`s2` `s3` `s4` `s4` 均衡收集到数据包，并从出口`eth2`看出数据包进行清洗，`s6`从`eth2`端口收到了少量的攻击包。



## Experimental summary

由于策略的设定，主机可能会收到少部分攻击流数据包，但由于只部署部分防御流表规则，大大减少了防御开销，对于这样的结果，也可以接受。但本实验存在一定漏洞，需要在后续工作中进行改正。
