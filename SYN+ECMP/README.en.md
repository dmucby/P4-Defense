# SYN+ ECMP

[中文](README.md) | **English**

## Idea

### ECMP

Compute a hash from the packet's transmission path and addresses, take the hash modulo the number of paths, and map the resulting value to a port to distribute packets across links under random traffic conditions.

### SYN defense

Use P4 registers to count SYN packets. For the defense strategy, see [SYN DEFENSE](https://github.com/dmucby/P4-Defense/tree/master/SYN%20Flood%20Defence). Here, we periodically replace the defense flow table rules to make it difficult for attackers to identify the defense nodes and strategies. The `P4-Utils` controller randomly replaces the switches' flow table rules.

## Topology

![multi_hop_topo](https://personal-drawing-bed.oss-cn-beijing.aliyuncs.com/img/multi_hop_topo.png)

* Switches `s1` and `s6` install flow table rules for load-balancing calculations.
* Switches `s2 `, `s3`, `s4`, and `s5` perform traffic scrubbing.

## P4 switch

### ECMP implementation

Use the built-in hash function in [v1mode](https://github.com/p4lang/p4c/blob/main/p4include/v1model.p4) to hash `ipv4.srcAddr`, `ipv4.dstAddr`, `tcp.srcPort`, `tcp.dstPort`, and `ipv4.protocol`. Setting the maximum value to `4` constrains the result to the range 0–3. Then create a one-to-one mapping between hash values and ports in the flow table.

#### P4 code

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

**The detailed parameters are as follows:**

```p4
@pure
extern void hash<O, T, D, M>(out O result, in HashAlgorithm algo, in T base, in D data, in M max);
```

#### Table rules

```txt
table_add ecmp_group_to_nhop set_nhop 1 0 =>  00:00:00:02:01:00 2
table_add ecmp_group_to_nhop set_nhop 1 1 =>  00:00:00:03:01:00 3
table_add ecmp_group_to_nhop set_nhop 1 2 =>  00:00:00:04:01:00 4
table_add ecmp_group_to_nhop set_nhop 1 3 =>  00:00:00:05:01:00 5
```

In the flow table, hash value `0` maps to port `2`; the other values follow the same pattern.

### SYN defense

The core code is similar to [SYN DEFENSE](https://github.com/dmucby/P4-Defense/tree/master/SYN%20Flood%20Defence), so it is not repeated here.

## Controller

Using the built-in support for `P4` switches in `P4-Utils`, we configure the controller to randomly select two switches from `s2 `, `s3`, `s4`, and `s5` during each period and deploy defense flow table rules on them. The switches need to be reset for the next period, so we must also restore the forwarding flow table rules.

> **Source note:** The description selects two switches from `s2`–`s5`, but the code below independently calls `random.randint(1,4)` twice, producing indices for `s1`–`s4` and potentially selecting the same switch twice. The original description and code are retained for comparison.

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

## Experiment

We use the same attack tool, `hping3`, to launch a `SYN-Flood` `DDoS` attack from `h1` against `h2`. We monitor packet traffic to assess the defense. Due to memory limitations on the personal computer, we test attacks only at the **million-packet** scale.

Run the following attack command in the `h1` terminal:

```bash
hping3 -q -n -S -p 5001 --faster 10.0.6.2 
```

### Results

![微信截图_20220429180843](https://personal-drawing-bed.oss-cn-beijing.aliyuncs.com/img/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20220429180843.png)

The experimental results show that `h1` sends attack packets to port `s1-eth1`. Switches `s2`, `s3`, `s4`, and `s4` receive balanced shares of the packets, and traffic at the `eth2` egress ports shows that packets are scrubbed. Switch `s6` receives a small number of attack packets through port `eth2`.

> **Source note:** The source repeats `s4` here, whereas the topology above lists `s2`, `s3`, `s4`, and `s5`. The original experimental description is retained.

## Experimental summary

The strategy allows a small number of attack packets to reach the host. However, deploying only part of the defense flow table rules greatly reduces defense overhead, making this result acceptable. The experiment still has weaknesses that need to be addressed in future work.
