# P4-DDoS Defense

本存储库是基于`P4`在数据层面实现的防御策略，鉴于`P4`部署在交换机上超高的数据包清洗能力，建设此存储库来记录自身学习，如果各位能提供意见，我将十分感谢。



## 目录结构

* SYN Flood Defence ：SYN泛洪攻击防御
* SYN + ECMP : SYN泛洪防御+ECMP负载均衡
* DDSS ：Dynamic DDoS traffic Scrubbing System (参考 [Poseidon: Mitigating Volumetric DDoS Attacks with Programmable Switches](https://www.ndss-symposium.org/ndss-paper/poseidon-mitigating-volumetric-ddos-attacks-with-programmable-switches/))
