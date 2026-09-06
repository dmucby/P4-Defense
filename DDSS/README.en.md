# DDSS

[中文](README.md) | **English**

> Dynamic DDoS traffic Scrubbing System

Link-flooding DDoS attacks disrupt the connection between a target network and the Internet by flooding network links with traffic, causing widespread network outages and posing a serious threat to Internet security. Traffic scrubbing is a common defense against these attacks. However, existing approaches often rely on static scrubbing rules and struggle to counter dynamic link-flooding DDoS attacks. To address this problem, this paper presents DDSS, a traffic scrubbing system built on a programmable data plane. DDSS incorporates moving target defense (MTD) into traffic scrubbing by periodically changing the deployment of scrubbing rules, preventing attackers from launching effective attacks. Experimental results show that DDSS effectively mitigates dynamic link-flooding DDoS attacks with little additional overhead.

Keywords: traffic scrubbing, moving target defense, link-flooding DDoS attacks, P4, programmable data plane

## Project report

[DDSS 中文竞赛项目报告 / Chinese competition project report (PDF)](../docs/DDSS-project-report.pdf) | [DDSS English competition project report (PDF)](../docs/DDSS-project-report-en.pdf)

## Reproducing the system

This system's code draws on and reproduces [Poseidon: Mitigating Volumetric DDoS Attacks with Programmable Switches](https://www.ndss-symposium.org/ndss-paper/poseidon-mitigating-volumetric-ddos-attacks-with-programmable-switches/). Due to the limits of my expertise, I reproduced only the P4 code and part of the server code; the primitives were not reproduced. For explanations of some of the code's functionality, see [SYN Flood Defense](https://github.com/dmucby/P4-Defense/tree/master/SYN%20Flood%20Defence).
