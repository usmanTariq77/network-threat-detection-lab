# Detection Analysis

## 1. Scope

This document provides the technical analysis behind the detections implemented in the Network Threat Detection & PCAP Investigation Lab.

The objective was to demonstrate a complete defensive network-monitoring workflow:

**Traffic Generation → Network Capture → IDS Detection → Alert Investigation → Packet Analysis → Correlation → Detection Tuning → Offline Validation**

All activity was performed inside an isolated VirtualBox laboratory environment.

---

## 2. Lab Environment

The lab uses two virtual machines connected through a VirtualBox Host-only network.

| Host | IP Address | Role |
|---|---|---|
| Kali Linux | `192.168.103.9` | Traffic generator / reconnaissance source |
| Ubuntu Linux | `192.168.103.10` | Suricata sensor + Apache HTTP target |

### Network

`192.168.103.0/24`

### Suricata Monitoring Interface

`enp0s8`

### Key Components

- Kali Linux
- Ubuntu Linux
- Suricata 7.0.3
- Apache2
- Wireshark
- tcpdump
- Nmap
- PCAP analysis
- Custom Suricata signatures
- Suricata `eve.json` alerts

The Ubuntu host intentionally performs two roles in this lab: it acts as the network sensor running Suricata and hosts the Apache HTTP service used as the investigation target.

---

## 3. Detection and Investigation Workflow

The technical workflow used throughout the project was:

    Controlled Traffic
            ↓
    Monitored Network Interface
            ↓
    tcpdump / PCAP Capture
            ↓
    Suricata Detection
            ↓
    eve.json Alert
            ↓
    Wireshark Investigation
            ↓
    Flow Correlation
            ↓
    Detection Tuning
            ↓
    Offline PCAP Replay
            ↓
    Detection Validation

The goal was not simply to generate alerts, but to demonstrate how an analyst can move from an alert to packet-level evidence and then validate the detection logic.

---

# 4. Detection 1 — ICMP Traffic

## Objective

The first test established basic network visibility between the Kali traffic generator and the Ubuntu sensor.

Kali generated controlled ICMP traffic toward Ubuntu.

Source:

`192.168.103.9`

Destination:

`192.168.103.10`

The traffic was visible on Ubuntu's monitored interface and detected by Suricata.

## Suricata Rule

    alert icmp any any -> $HOME_NET any (msg:"LAB ICMP traffic detected"; sid:1000001; rev:1;)

## Detection Result

Suricata generated:

`LAB ICMP traffic detected`

The alert confirmed that traffic reaching the monitored interface was visible to the IDS.

## Security Interpretation

ICMP traffic is not inherently malicious.

This test was primarily used to establish sensor visibility and verify the basic detection pipeline before investigating more security-relevant behavior.

---

# 5. Detection 2 — TCP SYN Scan

## Objective

The second test simulated reconnaissance activity against network services.

Kali performed a TCP SYN scan against ports 22, 80, and 443 on the Ubuntu host.

Command:

    sudo nmap -sS -p 22,80,443 192.168.103.10

The scan identified port 80 as open while ports 22 and 443 were not open.

---

## Detection Rule

The custom Suricata rule was:

    alert tcp any any -> $HOME_NET any (msg:"LAB TCP SYN scan detected"; flags:S; threshold:type threshold, track by_src, count 3, seconds 10; sid:1000003; rev:1;)

### Rule Logic

The rule checks for TCP packets containing the SYN flag.

A threshold is also applied:

- Track activity by source IP
- Require three matching packets
- Observe the activity within ten seconds

This reduces the likelihood that a single SYN packet will be treated as a scan.

---

## Detection Result

Suricata generated:

`LAB TCP SYN scan detected`

Observed source:

`192.168.103.9`

Observed destination:

`192.168.103.10`

The alert demonstrated that repeated connection attempts associated with the controlled scan could be identified by the IDS.

---

## MITRE ATT&CK Mapping

**T1046 — Network Service Scanning**

The mapping is based on the controlled Nmap scan against multiple service ports.

---

# 6. Detection 3 — HTTP Traffic

## Objective

The HTTP scenario was designed to demonstrate application-layer visibility and detection engineering.

Apache2 was running on the Ubuntu host.

Kali generated an HTTP request using:

    curl -v http://192.168.103.10/

The server returned:

`HTTP/1.1 200 OK`

The resulting network exchange was captured and investigated using Wireshark.

---

# 7. Initial HTTP Detection

The initial HTTP detection was intentionally broad:

    alert tcp any any -> 192.168.103.10 80 (msg:"LAB HTTP traffic detected"; sid:1000002; rev:1;)

## Problem With the Initial Rule

The initial rule detected TCP traffic directed toward port 80.

Although this provided basic visibility, it did not establish that the traffic actually contained an HTTP request.

For example, a TCP connection to port 80 does not necessarily mean that an HTTP GET request occurred.

This creates the possibility of unnecessary or noisy alerts.

The initial rule therefore served as a useful baseline for detection tuning.

---

# 8. HTTP Detection Tuning

The HTTP rule was refined to:

    alert tcp any any -> $HOME_NET 80 (msg:"LAB HTTP GET request detected"; flow:to_server,established; http.method; content:"GET"; sid:1000002; rev:2;)

The revised rule introduced additional conditions.

## `$HOME_NET`

Restricts the destination to the configured monitored network.

## Destination Port 80

Focuses the detection on the HTTP service.

## `flow:to_server,established`

Requires traffic to be part of an established client-to-server flow.

## `http.method`

Uses Suricata's HTTP protocol inspection rather than relying only on the TCP destination port.

## `content:"GET"`

Requires the HTTP method to contain `GET`.

---

## Detection Engineering Rationale

The change moved the detection from:

**"TCP traffic is going to port 80"**

toward:

**"An established client-to-server flow contains an HTTP GET request to the monitored network."**

This increases specificity and demonstrates the importance of detection tuning.

---

# 9. Packet Capture

The HTTP traffic was captured on the Ubuntu sensor using tcpdump:

    sudo tcpdump -i enp0s8 -w ~/network-investigation.pcap

The resulting PCAP was used as the packet-level evidence source for the investigation.

The capture contained traffic between:

`192.168.103.9`

and:

`192.168.103.10`

over TCP port 80.

---

# 10. Wireshark Investigation

The HTTP traffic was isolated in Wireshark using:

    ip.addr == 192.168.103.9 && ip.addr == 192.168.103.10 && tcp.port == 80

The capture showed the TCP connection establishment followed by application data.

The HTTP session was reconstructed using Wireshark's Follow TCP Stream functionality.

The reconstructed request contained:

    GET / HTTP/1.1
    Host: 192.168.103.10
    User-Agent: curl/8.20.0

The server response contained:

    HTTP/1.1 200 OK
    Server: Apache/2.4.58 (Ubuntu)
    Content-Type: text/html

This confirmed that the observed TCP flow contained an actual HTTP GET request followed by a successful Apache response.

---

# 11. Packet-Level Interpretation

The HTTP exchange demonstrated several useful investigation points.

### TCP Connection

The client first established the TCP session with the server.

### HTTP Request

The client sent:

`GET / HTTP/1.1`

### Server Response

The Apache server responded:

`HTTP/1.1 200 OK`

### Application Metadata

The stream also exposed:

- Host header
- User-Agent
- HTTP status
- Server software
- Content type
- Returned HTML content

This illustrates why packet capture can provide context that is not available from a simple IDS signature alone.

---

# 12. Suricata Alert Investigation

Suricata writes structured security events to:

    /var/log/suricata/eve.json

The relevant alert fields included:

- Timestamp
- Alert signature
- Source IP
- Source port
- Destination IP
- Destination port
- Protocol

These fields can be used as investigation pivots.

For example, an analyst can begin with a Suricata alert and then use the source and destination information to locate the corresponding network flow in packet data.

---

# 13. Alert-to-PCAP Correlation

The Suricata alert for the HTTP traffic contained:

    Source:      192.168.103.9:46708
    Destination: 192.168.103.10:80
    Protocol:    TCP

The same flow was identified during the Wireshark investigation.

The source port was particularly useful as a correlation value.

The evidence therefore established the following relationship:

    Kali
    192.168.103.9:46708
            ↓
    Ubuntu
    192.168.103.10:80
            ↓
    TCP connection
            ↓
    HTTP GET /
            ↓
    HTTP 200 OK
            ↓
    Suricata HTTP alert

Matching the source IP, destination IP, source port, destination port, and protocol provided strong evidence that the IDS alert and Wireshark session represented the same network flow.

---

# 14. Why Correlation Matters

An IDS alert by itself may provide only limited context.

Packet-level investigation can answer additional questions:

- Who initiated the connection?
- Which destination was contacted?
- Which service was targeted?
- Which protocol was used?
- What request was sent?
- Did the server respond?
- Was the communication successful?

Correlation between Suricata and Wireshark therefore produces a stronger investigation result than relying on either data source alone.

---

# 15. Structured Alert Extraction

The Suricata JSON log was filtered to extract the relevant fields from alert events.

The investigation focused on alerts with the custom `LAB` signatures.

Example fields extracted from the alert data:

    Timestamp
    Alert signature
    Source IP
    Source port
    Destination IP
    Destination port
    Protocol

This allowed the IDS output to be reviewed in a compact analyst-friendly format rather than manually reading the complete JSON event stream.

---

# 16. Offline Detection Validation

After tuning the HTTP rule, the recorded PCAP was replayed through Suricata.

The validation command was:

    sudo suricata -r ~/network-investigation.pcap -c /etc/suricata/suricata.yaml -l ~/suricata-validation-k -k none

The `-k none` option disables checksum validation during offline replay.

This was relevant because checksum offloading in virtualized network environments can result in checksum observations that do not accurately represent the packet's original network processing.

The replay successfully processed the captured traffic.

The resulting Suricata alert was:

`LAB HTTP GET request detected`

The alert contained:

    Source:      192.168.103.9:46708
    Destination: 192.168.103.10:80
    Protocol:    TCP

This matched the previously investigated HTTP flow.

---

# 17. Offline Validation Significance

The offline replay provided an additional validation layer.

The process was:

    Original HTTP Traffic
            ↓
    PCAP Capture
            ↓
    Wireshark Analysis
            ↓
    Tuned Suricata Rule
            ↓
    Offline PCAP Replay
            ↓
    Expected HTTP GET Alert

This demonstrated that the final detection logic was not only active during live traffic generation but could also identify the expected behavior when applied to recorded network evidence.

---

# 18. Detection Validation Matrix

| Detection | Test Input | Expected Result | Actual Result |
|---|---|---|---|
| ICMP | Controlled ping traffic | ICMP alert | Detected |
| SYN scan | Nmap SYN scan | SYN scan alert | Detected |
| HTTP | HTTP GET request | HTTP GET alert | Detected |
| Tuned HTTP | Captured PCAP replay | HTTP GET alert | Successfully validated |

---

# 19. Detection Engineering Assessment

The project demonstrates several levels of network visibility.

## Network-Level Visibility

ICMP traffic and TCP flags provide basic information about network communication.

## Transport-Level Visibility

Source and destination addresses, ports, and TCP behavior provide flow-level context.

## Application-Level Visibility

HTTP inspection provides additional information such as the HTTP method and request structure.

The HTTP rule demonstrates why application-aware detection can be more useful than relying only on a destination port.

A port-based rule can identify where traffic is going.

A protocol-aware rule can provide more evidence about what the traffic actually contains.

---

# 20. Detection Quality Considerations

Detection rules should balance:

**Coverage**

against

**Specificity**

A rule that is too broad can produce unnecessary alerts.

A rule that is too restrictive can miss relevant activity.

The HTTP detection illustrates this trade-off.

### Baseline

The initial rule matched TCP traffic to port 80.

### Tuned Rule

The revised rule required:

- TCP traffic
- Destination port 80
- Established flow
- Traffic directed toward the server
- HTTP protocol inspection
- HTTP GET method

The tuning process therefore improved the contextual quality of the detection.

---

# 21. MITRE ATT&CK Mapping

## T1046 — Network Service Scanning

### Observed Behavior

Controlled Nmap SYN scan against multiple service ports.

### Evidence

- Nmap SYN scan
- Multiple destination ports
- Suricata SYN detection
- Source and destination IP correlation

### Assessment

The activity represents reconnaissance behavior within the controlled laboratory environment.

---

## T1071.001 — Web Protocols

### Observed Behavior

HTTP communication between Kali and the Ubuntu Apache server.

### Evidence

- HTTP GET request
- HTTP 200 OK response
- Wireshark TCP stream
- Suricata HTTP detection

### Assessment

The mapping represents observed use of the web protocol.

The HTTP request itself is not classified as malicious.

---

# 22. Analyst Findings

The investigation established that Kali generated network traffic toward the Ubuntu host.

The controlled SYN scan demonstrated reconnaissance-style activity and was successfully detected by Suricata.

The HTTP scenario demonstrated application-layer visibility.

Wireshark reconstructed the HTTP GET request and successful Apache response, while Suricata generated a corresponding alert.

The original HTTP detection was intentionally broad and was subsequently refined to identify established HTTP GET requests.

The tuned rule was then validated against the recorded PCAP through offline Suricata replay.

The combined evidence provided three useful perspectives:

1. **Suricata** — detection and structured alert data
2. **Wireshark** — packet and protocol-level investigation
3. **PCAP replay** — repeatable detection validation

---

# 23. SOC Investigation Perspective

If this were observed in a production SOC, the alert would not automatically be classified as malicious.

An analyst would first establish context.

Recommended investigation sequence:

1. Identify the source host.
2. Determine whether the source is authorized to communicate with or scan the destination.
3. Review additional traffic from the source.
4. Identify services exposed by the destination.
5. Look for exploitation or follow-on activity.
6. Correlate the source IP with endpoint, authentication, or other available telemetry.
7. Determine whether the activity is expected, suspicious, or malicious.
8. If unauthorized and confirmed malicious, follow the organization's incident-response process.
9. Tune the detection if legitimate scanning or monitoring infrastructure is generating unnecessary alerts.

This separates **detection** from **analyst judgment**.

An alert is evidence requiring investigation, not automatically proof of compromise.

---

# 24. Limitations

## Sensor Placement

Suricata can only inspect traffic that is visible on its monitored interface.

Traffic that does not traverse or reach the monitored interface will not be detected.

## Signature-Based Detection

Signature-based detection can produce false positives, particularly when matching conditions are too broad.

The HTTP tuning exercise demonstrated the importance of balancing coverage and specificity.

## Encrypted Traffic

HTTPS encrypts application-layer content.

This limits straightforward inspection of HTTP methods and request contents unless additional visibility mechanisms are available.

## Controlled Environment

All traffic in this project was generated intentionally inside an isolated laboratory.

The findings therefore demonstrate detection and investigation techniques rather than evidence of a real-world compromise.

---

# 25. Reproducibility

## Verify Suricata Configuration

    sudo suricata -T -c /etc/suricata/suricata.yaml

## View Custom Rules

    sudo cat /etc/suricata/rules/local.rules

## View Suricata Alerts

    sudo jq -R -r 'fromjson? | select(.event_type=="alert") | [.timestamp, .alert.signature, .src_ip, .src_port, .dest_ip, .dest_port, .proto] | @tsv' /var/log/suricata/eve.json

## Capture Network Traffic

    sudo tcpdump -i enp0s8 -w ~/network-investigation.pcap

## Replay PCAP Through Suricata

    sudo suricata -r ~/network-investigation.pcap -c /etc/suricata/suricata.yaml -l ~/suricata-validation-k -k none

## Extract LAB Alerts From Validation

    sudo jq -R -r 'fromjson? | select(.event_type=="alert" and (.alert.signature | startswith("LAB"))) | [.timestamp, .alert.signature, .src_ip, .src_port, .dest_ip, .dest_port, .proto] | @tsv' ~/suricata-validation-k/eve.json

---

# 26. Technical Lessons Learned

## Visibility Comes First

Before designing detections, the analyst needs to understand which interface is actually carrying the traffic.

## Detection Depends on Context

A destination port alone does not necessarily identify the application behavior occurring over that port.

## Packet Data Provides Investigation Depth

Wireshark can expose the actual protocol exchange behind an IDS event.

## Correlation Improves Confidence

Matching IP addresses, ports, protocol, and session details helps connect different evidence sources to the same network event.

## Detection Tuning Is Part of Detection Engineering

A working rule is not necessarily a good rule.

The detection should be evaluated for specificity, usefulness, and potential noise.

## Validation Should Be Repeatable

Saving a PCAP makes it possible to replay known traffic and verify whether detection logic continues to behave as expected.

---

# 27. Final Technical Conclusion

The lab demonstrated a complete network threat-detection and investigation workflow using controlled traffic.

Network activity was captured at the interface level, analyzed using packet inspection, detected using custom Suricata signatures, investigated through structured alerts and Wireshark, correlated using flow identifiers, and used to refine detection logic.

The HTTP detection was improved from a broad TCP/80 signature to a more specific application-aware rule targeting established HTTP GET requests.

The final rule was successfully validated against the recorded PCAP through offline Suricata replay.

The resulting workflow demonstrates the relationship between:

**Network Visibility → Detection → Investigation → Correlation → Detection Engineering → Validation**

The primary value of the project is therefore not the individual tools, but the demonstrated analytical process connecting network evidence to detection decisions.
