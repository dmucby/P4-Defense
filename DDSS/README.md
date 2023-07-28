# DDSS

> Dynamic DDoS traffic Scrubbing System

The link DDoS attack utilizes traffic flooding to disrupt the connection between the target network and the Internet, resulting in widespread network paralysis and posing a significant threat to Internet security. Traffic Scrubbing is a common defense method employed against link DDoS attacks. However, existing traffic Scrubbing methods often rely on static scrubbing rules, making it challenging to handle dynamic link DDoS attacks. To address these issues, this paper presents a programmable data plane-based link DDoS traffic scrubbing system (DDSS) that leverages the programmable data plane. This approach incorporates the concept of moving target defense (MTD) into traffic scrubbing by periodically and dynamically deploying scrubbing rules. By doing so, it renders attackers unable to launch effective attacks. Experimental results demonstrate that the proposed DDSS effectively mitigates dynamic link DDoS attacks with minimal introduction overhead.

Keywords: Traffic Scrubbing, Moving Target Defense, Link DDoS, P4, programmable data plane

## 系统复现

本仓库代码为复现[Poseidon: Mitigating Volumetric DDoS Attacks with Programmable Switches](https://www.ndss-symposium.org/ndss-paper/poseidon-mitigating-volumetric-ddos-attacks-with-programmable-switches/)系统，由于本人能力有限，只复现了P4代码与服务器部分代码，并未涉及原语复现，部分代码功能讲解可查看[SYN Flood防御](https://github.com/dmucby/P4-Defense/tree/master/SYN%20Flood%20Defence)。
