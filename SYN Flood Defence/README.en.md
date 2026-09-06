# SYN Flood Defense

[中文](README.md) | **English**

## Introduction

The code in this repository is intended for deployment on `p4` switches to scrub SYN flood traffic and provide simple, preliminary SYN flood defense.

SYN flood attacks exploit the TCP three-way handshake. Attackers typically use tools or compromised hosts to send a massive number of TCP SYN packets with changing source IP addresses or source ports to a server. After responding to these packets, the server creates a large number of half-open connections. Once its resources are exhausted, it can no longer provide normal service.

## Defense strategy

Taking advantage of switch capabilities, we combine first-packet dropping with source authentication to scrub traffic and provide preliminary defense.

### Blocking source IP addresses

Based on the characteristics of SYN flood attacks, we count `SYN` and `ACK` packets and set a threshold. If the threshold is exceeded, we add the corresponding `IP` to a blocklist and reject packets from that `IP`.

### First-packet dropping

During a SYN flood attack, the vast majority of SYN packets sent by an attacker have **changing source addresses**. To the switch, each of these SYN packets is a first packet and is dropped immediately. This can substantially reduce attack traffic and strengthen the source `IP` defense strategy.

## P4 implementation

### Experimental environment

We deployed the experiment on `ubuntu16.04` with the following tools installed:

* `p4c`: compiler for P4 code
* `Bmv2`: software switch
* `mininet`: virtual network
* `p4-utils` or `p4app`: development tools that simplify the creation of `p4` networks and switches
* `hping3`: tool for simulating SYN flood attacks
* `wireshark`: packet capture tool

### Code logic

#### Topology

![image](https://user-images.githubusercontent.com/80476712/158025459-abdffddf-188d-4542-a718-b7cdf6ea1eab.png)

#### Code structure

1. Add packet headers for the switch, including `ethernet`, `ipv4`, and `tcp`, together with metadata.

2. Write a parser to parse the packet protocols.

3. Implement the processing logic in the switch's `Ingress`, using two registers for source `IP` blocking and first-packet dropping.

4. Write the application logic:

   1. Drop a packet if it is the first packet received from a given `IP`:

      ```p4
      first_drop();
      if(meta.counter_three == (bit<32>)1){
          drop();
           return;
      }
      ```

   2. Update the registers and check whether the difference between the `SYN` and `ACK` counts exceeds the threshold. Drop the packet if it does; otherwise, allow it through.

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

5. Implement the switch's `checksum` and `Deparser` logic to emit the packet.

## Experimental results

1. Start the topology and compile the `p4` program:

   ```bash
   sudo p4run
   ```

2. Check whether `ping` works:

   ```mininet
   mininet> pingall
   ```

![image](https://user-images.githubusercontent.com/80476712/158025471-c407237d-b4e1-4a26-bcac-e8e54715aae2.png)

3. Open terminals for the virtual hosts:

   ```mininet
   mininet> xterm h1 h2
   ```

4. Open the packet capture tool to monitor traffic:

   ```bash
   sudo wireshark
   ```

5. On host `h1`, use `hping3` to simulate a SYN flood attack against `h2`:

   ```bash
   hping3 -q -n --rand-source -S -p 5001 --faster 10.0.2.2
   ```

   * rand-source: spoof random source `IP` addresses

   * flood: send 100 packets per second

   > **Source note:** The source labels 100 packets per second as `flood`, but the example command uses `--faster`; the option names do not match. The original command and numeric claim are retained here.

6. Observe the `wireshark` graphs:

   **First experiment:**

   ![image](https://user-images.githubusercontent.com/80476712/158025514-2300d618-b44d-486e-aefc-6b54cdd8424a.png)

   **Second experiment:**

   ![image](https://user-images.githubusercontent.com/80476712/158025526-0358e2b3-5a8e-48aa-9150-5ccfbd87be75.png)

   > Because SYN flood experiments are demanding on the machine, we performed only two experiments, each lasting less than one minute.
   >
   > The packet graphs show that the attack packets sent by `h1` pass through port `s1-eth1`, while `h2` receives packets through port `s2-eth1`. The defense works well initially. As the number of packets increases, hash collisions gradually occur, allowing some attack packets to evade timely filtering.

7. Check whether a normal TCP connection can be established between `h3` and `h2`:

   ```bash
   iperf -s
   ```

   ```bash
   iperf -c 10.0.2.2
   ```

![image](https://user-images.githubusercontent.com/80476712/158025532-f0b4a2eb-989e-410e-a77d-759111b50bf1.png)

   The bandwidth measurements from `iperf` show that `h3` and `h2` can still maintain a normal connection during the attack.

## Experimental summary

1. The traffic scrubbing strategy deployed on the `p4` switch provides effective defense against basic `SYN-Flood` attacks.
2. The defense strategy has inherent limitations: excessive packet volume causes hash collisions that can make the defense fail.
3. This defense strategy does not account for state-based attacks, so there is still considerable room for improvement.
