# P4-DDoS Defense

[中文](README.md) | **English**

This repository contains defense strategies implemented in the data plane using `P4`. I created it to document my learning about high-throughput traffic scrubbing on P4-programmable switches. I would appreciate any feedback or suggestions.

## Directory structure

* SYN Flood Defence: SYN flood attack defense
* SYN + ECMP: SYN flood defense + equal-cost multipath (ECMP) load balancing
* DDSS: Dynamic DDoS traffic Scrubbing System (based on [Poseidon: Mitigating Volumetric DDoS Attacks with Programmable Switches](https://www.ndss-symposium.org/ndss-paper/poseidon-mitigating-volumetric-ddos-attacks-with-programmable-switches/)) · [中文项目报告 / Chinese project report (PDF)](docs/DDSS-project-report.pdf) | [English project report (PDF)](docs/DDSS-project-report-en.pdf)
