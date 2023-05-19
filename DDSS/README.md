# DDSS

> Dynamic DDoS traffic Scrubbing System

The link DDoS attack utilizes traffic flooding to disrupt the connection between the target network and the Internet, resulting in widespread network paralysis and posing a significant threat to Internet security. Traffic Scrubbing is a common defense method employed against link DDoS attacks. However, existing traffic Scrubbing methods often rely on static scrubbing rules, making it challenging to handle dynamic link DDoS attacks. To address these issues, this paper presents a programmable data plane-based link DDoS traffic scrubbing system (DDSS) that leverages the programmable data plane. This approach incorporates the concept of moving target defense (MTD) into traffic scrubbing by periodically and dynamically deploying scrubbing rules. By doing so, it renders attackers unable to launch effective attacks. Experimental results demonstrate that the proposed DDSS effectively mitigates dynamic link DDoS attacks with minimal introduction overhead.

Keywords: traffic cleansing, moving target defense, link DDoS, P4, programmable data plane