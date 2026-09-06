# DDSS

**中文** | [English](README.en.md)

> 动态 DDoS 流量清洗系统（Dynamic DDoS traffic Scrubbing System）

链路 DDoS 攻击通过流量泛洪破坏目标网络与互联网之间的连接，导致大范围网络瘫痪，对互联网安全构成重大威胁。流量清洗是应对链路 DDoS 攻击的常用防御方法。然而，现有流量清洗方法通常依赖静态清洗规则，难以应对动态链路 DDoS 攻击。为解决这些问题，本文利用可编程数据平面，提出一种基于可编程数据平面的链路 DDoS 流量清洗系统（DDSS）。该方法将移动目标防御（MTD）理念融入流量清洗，通过周期性、动态地部署清洗规则，使攻击者无法发起有效攻击。实验结果表明，所提出的 DDSS 能够以较小的额外开销有效缓解动态链路 DDoS 攻击。

关键词：流量清洗，移动目标防御，链路 DDoS 攻击，P4，可编程数据平面

## 项目报告

[DDSS 中文竞赛项目报告（PDF）](../docs/DDSS-project-report.pdf) | [DDSS English competition project report (PDF)](../docs/DDSS-project-report-en.pdf)

## 系统复现

本系统代码参考并复现了[Poseidon: Mitigating Volumetric DDoS Attacks with Programmable Switches](https://www.ndss-symposium.org/ndss-paper/poseidon-mitigating-volumetric-ddos-attacks-with-programmable-switches/)系统，由于本人能力有限，只复现了P4代码与服务器部分代码，并未涉及原语复现，部分代码功能讲解可查看[SYN Flood防御](https://github.com/dmucby/P4-Defense/tree/master/SYN%20Flood%20Defence)。
