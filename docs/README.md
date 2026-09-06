# DDSS 项目报告 / Project Reports

| 语言 / Language | 报告 / Report |
| --- | --- |
| **中文原版 / Chinese original** | [DDSS-project-report.pdf](DDSS-project-report.pdf) |
| **English translation / 英文译版** | [DDSS-project-report-en.pdf](DDSS-project-report-en.pdf) |

中文报告保留原文件。英文报告完整翻译正文、公式、算法、图表标签和参考文献；原始图表数据保持不变。英文版末尾的译注说明原文中的符号或表述不一致，没有将其作为新的实验结果或修订后的研究结论。

The Chinese report is the original file. The English edition translates all sections, formulas, algorithms, figure labels, and references while preserving the original plotted data. Translation notes at the end identify inconsistencies in the source; they do not introduce new experimental results or revised research conclusions.

## 专业术语 / Technical Terminology

| 中文 | English |
| --- | --- |
| 分布式拒绝服务攻击 | distributed denial-of-service (DDoS) attack |
| 链路 DDoS 攻击 | link-flooding DDoS attack |
| 流量清洗 | traffic scrubbing |
| 可编程数据平面 | programmable data plane |
| 移动目标防御 | moving target defense (MTD) |
| 虚拟网络功能 | virtual network function (VNF) |
| 网络功能虚拟化 | network function virtualization (NFV) |
| 软件定义网络 | software-defined networking (SDN) |
| 匹配-动作 | match-action |
| 流表 | flow table |
| 等价多路径 | equal-cost multipath (ECMP) |
| 往返时延 | round-trip time (RTT) |
| 纳什均衡 | Nash equilibrium |
| 混合策略 | mixed strategy |
| 效用 / 收益 / 成本 | payoff / benefit / cost |
| 无锁环形队列 / 内存池 | lockless ring / memory pool |

P4 is the packet-processing language; a P4-programmable switch is the device. VNF is a network function implemented in software, while NFV is the virtualization approach. In the report's game model, **payoff = benefit − cost**, so these terms are kept distinct.

Terminology references: [P4 language specification](https://p4.org/wp-content/uploads/sites/53/2024/10/P4-16-spec-v1.2.5.html), [Poseidon paper](https://www.ndss-symposium.org/ndss-paper/poseidon-mitigating-volumetric-ddos-attacks-with-programmable-switches/), [DPDK Kernel NIC Interface](https://doc.dpdk.org/guides-21.11/prog_guide/kernel_nic_interface.html), [DPDK ring library](https://doc.dpdk.org/guides-21.11/prog_guide/ring_lib.html).
