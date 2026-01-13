# Table of Contents

- [External Recon and Enumeration Principles](#external-recon-and-enumeration-principles)
  - [What Are We Looking For?](#what-are-we-looking-for)
  - [Where Are We Looking?](#where-are-we-looking)
    - [Finding Address Spaces](#finding-address-spaces)
    - [DNS](#dns)
    - [Public Data](#public-data)
  - [Example Enumeration Process](#example-enumeration-process)
- [Initial Enumeration of the Domain](#initial-enumeration-of-the-domain)
  - [TTPs (Tactics, Techniques, and Procedures)](#ttps-tactics-techniques-and-procedures)
    - [Identifying Hosts](#identifying-hosts)
      - [Wireshark/tcpdump](#wiresharktcpdump)
      - [Responder](#responder)
      - [Fping](#fping)
      - [Nmap](#nmap)
    - [Identifying Users](#identifying-users)
      - [Kerbrute - Internal AD Username Enumeration](#kerbrute---internal-ad-username-enumeration)
      - [Install Kerbrute](#install-kerbrute)
    - [Identifying Potential Vulnerabilities](#identifying-potential-vulnerabilities)
  - [A Word Of Caution](#a-word-of-caution)

---

# External Recon and Enumeration Principles

Before starting a pentest, perform external reconnaissance to:

* Validate client-provided scoping information
* Confirm you're targeting the correct scope when working remotely
* Find publicly accessible information that could impact testing (e.g., leaked credentials)

The goal is understanding the target landscape to deliver comprehensive testing while identifying potential information leaks and breach data. This ranges from simple tasks like discovering username formats on company websites or social media, to deeper investigation including scanning GitHub repos for exposed credentials, searching documents for intranet links or remote sites, and gathering any intel revealing how the enterprise environment is configured.

---

## What Are We Looking For?

During external reconnaissance, search for key information that may be publicly accessible. Even if not everything is available, understanding what's out there is valuable. When stuck during a pentest, revisiting passive recon findings—like password breach data for VPN or external service access—can provide the breakthrough needed to progress. The table below highlights the "**What**" in what we would be searching for during this phase of our engagement.

|Data Point	|Description|
|-|-|
|**`IP Space`**|	Valid ASN for our target, netblocks in use for the organization's public-facing infrastructure, cloud presence and the hosting providers, DNS record entries, etc.|
|**`Domain Information`**	|Based on IP data, DNS, and site registrations. <br>- Who administers the domain? <br>- Are there any subdomains tied to our target? <br>- Are there any publicly accessible domain services present? (Mailservers, DNS, Websites, VPN portals, etc.) <br>- Can we determine what kind of defenses are in place? (SIEM, AV, IPS/IDS in use, etc.)|
|**`Schema Format`**	|- Can we discover the organization's email accounts, AD usernames, and even password policies? <br>- Anything that will give us information we can use to build a valid username list to test external-facing services for password spraying, credential stuffing, brute forcing, etc.|
|**`Data Disclosures`**	|For data disclosures we will be looking for publicly accessible files ( .pdf, .ppt, .docx, .xlsx, etc. ) for any information that helps shed light on the target. <br>For example, any published files that contain `intranet` site listings, user metadata, shares, or other critical software or hardware in the environment (credentials pushed to a public GitHub repo, the internal AD username format in the metadata of a PDF, for example.)|
|**`Breach Data`**	|Any publicly released usernames, passwords, or other critical information that can help an attacker gain a foothold.|

---

## Where Are We Looking?

Our list of data points above can be gathered in many different ways. There are many different websites and tools that can provide us with some or all of the information above that we could use to obtain information vital to our assessment.

|Resource	|Examples|
|-|-|
|**`ASN / IP registrars`**	|[IANA](https://www.iana.org/), [arin](https://www.arin.net/) for searching the Americas, [RIPE](https://www.ripe.net/) for searching in Europe, [BGP Toolkit](https://bgp.he.net/)|
|**`Domain Registrars & DNS`**	|[Domaintools](https://www.domaintools.com/), [PTRArchive](https://securitytrails.com/), [ICANN](https://lookup.icann.org/en), manual DNS record requests against the domain in question or against well known DNS servers, such as `8.8.8.8`.|
|**`Social Media`**	|Searching Linkedin, Twitter, Facebook, your region's major social media sites, news articles, and any relevant info you can find about the organization.|
|**`Public-Facing Company Websites`**	|Often, the public website for a corporation will have relevant info embedded. News articles, embedded documents, and the "About Us" and "Contact Us" pages can also be gold mines.|
|**`Cloud & Dev Storage Spaces`**	|GitHub, [AWS S3 buckets & Azure Blog storage containers](https://grayhatwarfare.com/), [Google searches using "Dorks"](https://www.exploit-db.com/google-hacking-database)|
|**`Breach Data Sources`**	|[HaveIBeenPwned](https://haveibeenpwned.com/) to determine if any corporate email accounts appear in public breach data, [Dehashed](https://www.dehashed.com/) to search for corporate emails with cleartext passwords or hashes we can try to crack offline. We can then try these passwords against any exposed login portals (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, custom applications, etc.) that may use AD authentication.|

---

### Finding Address Spaces

<img width="967" height="459" alt="image" src="https://github.com/user-attachments/assets/5bf46dfd-5368-4d0b-ab0a-2decaf17ebb4" />

The BGP-Toolkit by Hurricane Electric is excellent for researching address blocks and ASNs assigned to organizations. Enter a domain or IP to find available results.

**Key Considerations:**

* **Large corporations** often self-host infrastructure with their own ASN
* **Smaller organizations** typically host on third-party platforms (Cloudflare, Google Cloud, AWS, Azure)

Understanding infrastructure location is critical—you must avoid testing out-of-scope systems. Testing a smaller organization without care could inadvertently harm others sharing that infrastructure. Your agreement is with the client only, not other tenants or providers.

**Important:** Self-hosted vs. third-party hosting should be clarified during scoping and documented clearly.

**Third-Party Approvals:**

Some clients need written provider approval before testing. Providers have varying policies:
* **AWS:** No prior approval needed for some services
* **Oracle:** Requires Cloud Security Testing Notification

Your management, legal, or contracts team should handle these steps. **When in doubt, escalate.** Always ensure explicit written permission exists for all hosts (internal and external) before attacking. Clarifying scope never hurts.

### DNS

DNS helps validate scope and discover reachable hosts not disclosed in scoping documents. Use sites like [domaintools](https://whois.domaintools.com/) and [viewdns.info](https://viewdns.info/) to gather DNS records and data—from resolution to DNSSEC testing and accessibility in restricted countries.

You may discover:
* **Additional hosts** appearing out of scope but worth investigating—bring these to your client to potentially add to scope
* **Interesting subdomains** not listed in scoping documents but residing on in-scope IPs, making them fair game for testing

<img width="1336" height="736" alt="image" src="https://github.com/user-attachments/assets/71547154-7e86-45a3-bbb7-375d4dbb3518" />

This is also a great way to validate some of the data found from our IP/ASN searches. Not all information about the domain found will be current, and running checks that can validate what we see is always good practice.

### Public Data

Social media and job sites like **LinkedIn, Indeed.com, and Glassdoor** reveal valuable organizational insights—structure, equipment, software/security implementations, schemas, and more.

**Example:** A SharePoint Administrator job posting can disclose:
* The company has a mature SharePoint program (mentions security programs, backup/disaster recovery)
* Likely uses **SharePoint 2013 and 2016**, suggesting in-place upgrades
* Potential vulnerabilities from older versions may still exist
* Expect to encounter different SharePoint versions during engagement

Simple job postings often reveal significant technical details about a company's infrastructure and practices.

<img width="1021" height="392" alt="image" src="https://github.com/user-attachments/assets/822a79da-8bce-4c47-8504-0ba688c2323f" />

Never overlook job postings or social media—well-intentioned posts can reveal data valuable to penetration testers.

**Organization Websites** provide:
* Contact emails, phone numbers, organizational charts, published documents
* Embedded documents often containing links to internal infrastructure or intranet sites otherwise unknown
* Quick insights into domain structure

**Data Leaks on Public Platforms:**

With platforms like **GitHub, AWS cloud storage**, and similar services, data gets unintentionally leaked—developers may accidentally hardcode credentials or notes in code releases.

Finding this data can provide easy wins, potentially offering:
* Immediate foothold with developer credentials (which may have elevated permissions)
* Avoiding hours/days of password spraying or brute-forcing

**Useful Tools:**
* [Trufflehog](https://github.com/trufflesecurity/truffleHog) - for finding leaked credentials
* [Greyhat Warfare](https://buckets.grayhatwarfare.com/) - for discovering exposed data

These breadcrumbs can make the difference between prolonged attacks and quick access.

---

## Example Enumeration Process

We will practice our enumeration tactics on the `inlanefreight.com` domain without performing any heavy scans (such as Nmap or vulnerability scans which are out of scope). We will start first by checking our Netblocks data and seeing what we can find.

<img width="962" height="581" alt="image" src="https://github.com/user-attachments/assets/20ddc1b1-52c3-447b-9423-12d0d89c7e52" />

From this first look, we have already gleaned some interesting info. BGP.he is reporting:

- IP Address: 134.209.24.248
- Mail Server: mail1.inlanefreight.com
- Nameservers: NS1.inlanefreight.com & NS2.inlanefreight.com

For now, this is what we care about from its output. Inlanefreight is not a large corporation, so we didn't expect to find that it had its own ASN. Now let's validate some of this information.

<img width="1014" height="435" alt="image" src="https://github.com/user-attachments/assets/9d7dd4ca-2073-428d-a49b-7c05e4d7552a" />

In the request above, we utilized `viewdns.info` to validate the IP address of our target. Both results match, which is a good sign. Now let's try another route to validate the two nameservers in our results.

```
$ nslookup ns1.inlanefreight.com

Server:		192.168.186.1
Address:	192.168.186.1#53

Non-authoritative answer:
Name:	ns1.inlanefreight.com
Address: 178.128.39.165

nslookup ns2.inlanefreight.com
Server:		192.168.86.1
Address:	192.168.86.1#53

Non-authoritative answer:
Name:	ns2.inlanefreight.com
Address: 206.189.119.186
```

We now have `two` new IP addresses to add to our list for validation and testing. Before taking any further action with them, ensure they are in-scope for your test. For our purposes, the actual IP addresses would not be in scope for scanning, but we could passively browse any websites to hunt for interesting data. For now, that is it with enumerating domain information from DNS. Let's take a look at the publicly available information.

Inlanefreight is a fictitious company that we are using for this example, so there is no real social media presence. However, we would check sites like LinkedIn, Twitter, Instagram, and Facebook for helpful info if it were real. Instead, we will move on to examining the website `inlanefreight.com`.

The first check we ran was looking for any documents. Using `filetype:pdf inurl:inlanefreight.com` as a search, we are looking for PDFs.

<img width="922" height="377" alt="image" src="https://github.com/user-attachments/assets/c66e8ceb-31e7-44cb-a8ac-1136d8e2b02c" />

One document popped up, so we need to ensure we note the document and its location and download a copy locally to dig through. It is always best to save files, screenshots, scan output, tool output, etc., as soon as we come across them or generate them. This helps us keep as comprehensive a record as possible and not risk forgetting where we saw something or losing critical data. Next, let's look for any email addresses we can find.

<img width="889" height="420" alt="image" src="https://github.com/user-attachments/assets/d2cdf86c-04f7-4ca2-8912-af3ccc083998" />

Using the dork `intext:"@inlanefreight.com" inurl:inlanefreight.com`, we are looking for any instance that appears similar to the end of an email address on the website. One promising result came up with a contact page. When we look at the page (pictured below), we can see a large list of employees and contact info for them. This information can be helpful since we can determine that these people are at least most likely active and still working with the company.

**E-mail Dork Results**

Browsing the contact page, we can see several emails for staff in different offices around the globe. We now have an idea of their email naming convention (first.last) and where some people work in the organization. This could be handy in later password spraying attacks or if social engineering/phishing were part of our engagement scope.

<img width="1161" height="552" alt="image" src="https://github.com/user-attachments/assets/2fed6afc-75dc-4cef-9a20-28a70d8c38e6" />

**Username Harvesting**

We can use a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to scrape data from a company's LinkedIn page and create various mashups of usernames (flast, first.last, f.last, etc.) that can be added to our list of potential password spraying targets.

**Credential Hunting**

[Dehashed](https://dehashed.com/) is an excellent tool for hunting for cleartext credentials and password hashes in breach data. We can search either on the site or using a script that performs queries via the API. Typically we will find many old passwords for users that do not work on externally-facing portals that use AD auth (or internal), but we may get lucky! This is another tool that can be useful for creating a user list for external or internal password spraying.

Note: For our purposes, the sample data below is fictional.

```
$ sudo python3 dehashed.py -q inlanefreight.local -p

id : 5996447501
email : roger.grimes@inlanefreight.local
username : rgrimes
password : Ilovefishing!
hashed_password : 
name : Roger Grimes
vin : 
address : 
phone : 
database_name : ModBSolutions

id : 7344467234
email : jane.yu@inlanefreight.local
username : jyu
password : Starlight1982_!
hashed_password : 
name : Jane Yu
vin : 
address : 
phone : 
database_name : MyFitnessPal

<SNIP>
```

**Note**: The script used in the example above can be found [here](https://github.com/mrb3n813/Pentest-stuff/blob/master/dehashed.py). Due to changes in the API structure of DeHashed, modifications may be necessary. Alternatively, the following [script](https://github.com/sm00v/Dehashed) could be used. Before executing the script, it is crucial to become familiar with its functionality.

---

# Initial Enumeration of the Domain

We are at the very beginning of our AD-focused penetration test against Inlanefreight. We have done some basic information gathering and gotten a picture of what to expect from the customer via the scoping documents.

---

Below are some of the key data points that we should be looking for at this time and noting down into our notetaking tool of choice and saving scan/tool output to files whenever possible.

|Data Point|Description|
|-|-|
|`AD Users`|	We are trying to enumerate valid user accounts we can target for password spraying.|
|`AD Joined Computers`|	Key Computers include Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers, etc.|
|`Key Services`|	Kerberos, NetBIOS, LDAP, DNS|
|`Vulnerable Hosts and Services`|	Anything that can be a quick win. ( a.k.a an easy host to exploit and gain a foothold)|

## TTPs (Tactics, Techniques, and Procedures)

Enumerating an AD environment requires a structured plan to avoid being overwhelmed by the abundance of data. Without a progressive, staged approach, you'll waste time and miss critical findings.

**Develop Your Methodology:**
Everyone works differently—gain experience to build your own repeatable process. However, starting points and key data targets remain consistent across approaches.

**Standard Enumeration Flow:**

1. **Passive identification** - Discover hosts on the network
2. **Active validation** - Probe hosts for services, names, potential vulnerabilities
3. **Data gathering** - Extract interesting information from discovered hosts
4. **Regroup and analyze** - Review findings to identify credentials, target user accounts, or opportunities for:
   - Foothold on domain-joined hosts
   - Credentialed enumeration from your Linux attack host

**Practice Tip:** Reproduce every example with multiple tools to learn different syntax, approaches, and discover what works best for you.

### Identifying Hosts

Start by passively listening to the network to understand what's happening. Use **`Wireshark`** and **`TCPDump`** to capture network traffic and identify hosts—especially valuable for black box assessments.

**What You'll Observe:**
* ARP requests and replies
* MDNS traffic
* Basic layer two packets (limited to current broadcast domain on switched networks)

This initial reconnaissance provides valuable insights into the customer's network setup and serves as a foundation for further enumeration.

#### Wireshark/tcpdump

**Start Wireshark:**
```
$sudo -E wireshark

11:28:20.487     Main Warn QStandardPaths: runtime directory '/run/user/1001' is not owned by UID 0, but a directory permissions 0700 owned by UID 1001 GID 1002
<SNIP>
```

<img width="871" height="399" alt="image" src="https://github.com/user-attachments/assets/09c2f381-9433-4d52-87d8-98025240bd95" />

- ARP packets make us aware of the hosts: 172.16.5.5, 172.16.5.25 172.16.5.50, 172.16.5.100, and 172.16.5.125.

<img width="1026" height="247" alt="image" src="https://github.com/user-attachments/assets/d8b9461c-0c4c-4a57-8144-b1903511b859" />

- MDNS makes us aware of the ACADEMY-EA-WEB01 host.

If we are on a host without a GUI (which is typical), we can use `tcpdump`, `net-creds`, and `NetMiner`, etc., to perform the same functions. We can also use tcpdump to save a capture to a .pcap file, transfer it to another host, and open it in Wireshark.

```
$ sudo tcpdump -i ens224
```

Multiple tools can capture network traffic—**Wireshark** and **tcpdump** are simply the most accessible and widely known. Depending on your host, built-in tools like **pktmon.exe** (available on all Windows 10 editions) may already be available.

**Best Practice:** Always save captured PCAP traffic for later review and to include as supporting documentation in reports.

#### Responder

Initial traffic observation revealed hosts via **MDNS** and **ARP**. Next, use **Responder** to analyze traffic and discover additional domain hosts.

**Responder Overview:**
* Listens, analyzes, and can poison **LLMNR, NBT-NS, and MDNS** requests/responses
* **Analyze mode:** Passively listens without sending poisoned packets—ideal for initial reconnaissance

This passive approach helps identify more hosts without alerting the network. 

**Starting Responder:**
```
sudo responder -I ens224 -A
```

As we start Responder with passive analysis mode enabled, we will see requests flow in our session. Notice below that we found a few unique hosts not previously mentioned in our Wireshark captures. It's worth noting these down as we are starting to build a nice target list of IPs and DNS hostnames.

Our passive checks have given us a few hosts to note down for a more in-depth enumeration. Now let's perform some active checks starting with a quick ICMP sweep of the subnet using `fping`.

#### Fping

**Fping** functions similarly to standard ping using ICMP requests/replies, but offers key advantages:

* **Batch querying:** Issues ICMP packets against multiple hosts simultaneously from a list
* **Round-robin approach:** Queries hosts cyclically rather than waiting for multiple requests to one host before moving on
* **Scriptability:** Easily integrated into automated workflows

**Use Case:**
Helps determine active hosts on the internal network. While ICMP isn't comprehensive, it provides a quick initial picture of what exists. Combine with scans for open ports and active protocols to identify additional hosts for later targeting.

**FPing Active Checks:**

Here we'll start `fping` with a few flags: `a` to show targets that are alive, `s` to print stats at the end of the scan, `g` to generate a target list from the CIDR network, and `q` to not show per-target results.
```
$ fping -asgq 172.16.5.0/23

172.16.5.5
172.16.5.25
172.16.5.50
172.16.5.100
172.16.5.125
172.16.5.200
172.16.5.225
172.16.5.238
172.16.5.240

     510 targets
       9 alive
     501 unreachable
       0 unknown addresses

    2004 timeouts (waiting for response)
    2013 ICMP Echos sent
       9 ICMP Echo Replies received
    2004 other ICMP received

 0.029 ms (min round trip time)
 0.396 ms (avg round trip time)
 0.799 ms (max round trip time)
       15.366 sec (elapsed real time)

```

The command above validates which hosts are active in the `/23` network and does it quietly instead of spamming the terminal with results for each IP in the target list. We can combine the successful results and the information we gleaned from our passive checks into a list for a more detailed scan with Nmap. From the `fping` command, we can see 9 "live hosts," including our attack host.

#### Nmap

Now that we have a list of active hosts within our network, we can enumerate those hosts further. We are looking to determine what services each host is running, identify critical hosts such as `Domain Controllers` and `web servers`, and identify potentially vulnerable hosts to probe later. 

With our focus on AD, after doing a broad sweep, it would be wise of us to focus on standard protocols typically seen accompanying AD services, such as DNS, SMB, LDAP, and Kerberos name a few. 

Below is a quick example of a simple Nmap scan.

```
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```

The -A (Aggressive scan options) scan will perform several functions. One of the most important is a quick enumeration of well-known ports to include web services, domain services, etc. For our hosts.txt file, some of our results from Responder and fping overlapped (we found the name and IP address), so to keep it simple, just the IP address was fed into hosts.txt for the scan.

**NMAP Result Highlights:**
```
Nmap scan report for inlanefreight.local (172.16.5.5)
Host is up (0.069s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-04-04 15:12:06Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
|_ssl-date: 2022-04-04T15:12:53+00:00; -1s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
| Issuer: commonName=INLANEFREIGHT-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-03-30T22:40:24
| Not valid after:  2023-03-30T22:40:24
| MD5:   3a09 d87a 9ccb 5498 2533 e339 ebe3 443f
|_SHA-1: 9731 d8ec b219 4301 c231 793e f913 6868 d39f 7920
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
<SNIP>  
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: INLANEFREIGHT
|   NetBIOS_Domain_Name: INLANEFREIGHT
|   NetBIOS_Computer_Name: ACADEMY-EA-DC01
|   DNS_Domain_Name: INLANEFREIGHT.LOCAL
|   DNS_Computer_Name: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
|   DNS_Tree_Name: INLANEFREIGHT.LOCAL
|   Product_Version: 10.0.17763
|_  System_Time: 2022-04-04T15:12:45+00:00
<SNIP>
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: ACADEMY-EA-DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Our scans have provided us with the naming standard used by NetBIOS and DNS, we can see some hosts have RDP open, and they have pointed us in the direction of the primary `Domain Controller` for the INLANEFREIGHT.LOCAL domain (ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL).

**Analyzing Scan Results:**

**Legacy Systems:** 
Discovering outdated OS versions (Windows 7/8, Server 2008) indicates legacy systems in the AD environment—potential targets for older exploits like **EternalBlue** or **MS08-067** that can provide SYSTEM-level shells.

**Why Legacy Systems Persist:**
Common in large enterprises due to production equipment, HVAC, or critical processes built on older OS versions. Taking them offline is costly and disruptive, so they remain protected by layered security (firewalls, IDS/IPS, monitoring).

**Important:** Before exploiting legacy systems, get written client approval—attacks may cause instability or downtime. The client may prefer observation and reporting only.

**Next Steps**

Scan results reveal domain service hosts (DC01, MX01, WS01, etc.). Use these to:
* Poll servers and enumerate users
* Find a path to domain user credentials or SYSTEM-level access on domain-joined hosts

**Best Practice:** Use `-oA` flag with Nmap to save results in multiple formats for logging and tool integration.

**Critical Warning:** Understand your scans before running them. Some Nmap scripts actively test vulnerabilities and could cause system instability or downtime. Discovery scans against sensors or logic controllers may overload industrial equipment, causing product loss or capability disruption.

Save results for later enumeration—your goal is gaining a foothold to begin deeper exploitation.

---

### Identifying Users

If our client does not provide us with a user to start testing with (which is often the case), we will need to find a way to establish a foothold in the domain by either obtaining clear text credentials or an NTLM password hash for a user, a SYSTEM shell on a domain-joined host, or a shell in the context of a domain user account. 

Obtaining a valid user with credentials is critical in the early stages of an internal penetration test. This access (even at the lowest level) opens up many opportunities to perform enumeration and even attacks. 

#### Kerbrute - Internal AD Username Enumeration

[Kerbrute](https://github.com/ropnop/kerbrute) can be a stealthier option for domain account enumeration. It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts. 

We will use Kerbrute in conjunction with the `jsmith.txt` or `jsmith2.txt` user lists from [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames). This repository contains many different user lists that can be extremely useful when attempting to enumerate users when starting from an unauthenticated perspective. 

We can point Kerbrute at the DC we found earlier and feed it a wordlist. The tool is quick, and we will be provided with results letting us know if the accounts found are valid or not, which is a great starting point for launching attacks such as password spraying, which we will cover in-depth later.

#### Install Kerbrute

To get started with [Kerbrute](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3), we can download precompiled binaries for the tool for testing from Linux, Windows, and Mac, or we can compile it ourselves. This is generally the best practice for any tool we introduce into a client environment. To compile the binaries to use on the system of our choosing, we first clone the repo:

**Cloning Kerbrute GitHub Repo:**
```
$ sudo git clone https://github.com/ropnop/kerbrute.git

Cloning into 'kerbrute'...
remote: Enumerating objects: 845, done.
remote: Counting objects: 100% (47/47), done.
remote: Compressing objects: 100% (36/36), done.
remote: Total 845 (delta 18), reused 28 (delta 10), pack-reused 798
Receiving objects: 100% (845/845), 419.70 KiB | 2.72 MiB/s, done.
Resolving deltas: 100% (371/371), done.
```

- Typing `make help` will show us the compiling options available.
```
$ make help

help:            Show this help.
windows:  Make Windows x86 and x64 Binaries
linux:  Make Linux x86 and x64 Binaries
mac:  Make Darwin (Mac) x86 and x64 Binaries
clean:  Delete any binaries
all:  Make Windows, Linux and Mac x86/x64 Binaries
```

We can choose to compile just one binary or type `make all` and compile one each for use on Linux, Windows, and Mac systems (an x86 and x64 version for each).

**Compiling for Multiple Platforms and Architectures:**
```
$ sudo make all

go: downloading github.com/spf13/cobra v1.1.1
go: downloading github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
go: downloading github.com/ropnop/gokrb5/v8 v8.0.0-20201111231119-729746023c02
go: downloading github.com/spf13/pflag v1.0.5
go: downloading github.com/jcmturner/gofork v1.0.0
go: downloading github.com/hashicorp/go-uuid v1.0.2
go: downloading golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
go: downloading github.com/jcmturner/rpc/v2 v2.0.2
go: downloading github.com/jcmturner/dnsutils/v2 v2.0.0
go: downloading github.com/jcmturner/aescts/v2 v2.0.0
go: downloading golang.org/x/net v0.0.0-20200114155413-6afb5195e5aa
cd /tmp/kerbrute
rm -f kerbrute kerbrute.exe kerbrute kerbrute.exe kerbrute.test kerbrute.test.exe kerbrute.test kerbrute.test.exe main main.exe
rm -f /root/go/bin/kerbrute
Done.
Building for windows amd64..

<SNIP>
```

The newly created `dist` directory will contain our compiled binaries.

**Listing the Compiled Binaries in dist:**
```
$ ls dist/

kerbrute_darwin_amd64  kerbrute_linux_386  kerbrute_linux_amd64  kerbrute_windows_386.exe  kerbrute_windows_amd64.exe
```

- We can then test out the binary to make sure it works properly. We will be using the x64 version on the supplied Parrot Linux attack host in the target environment.

**Testing the kerbrute_linux_amd64 Binary**
```
$ ./kerbrute_linux_amd64 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

This tool is designed to assist in quickly bruteforcing valid Active Directory accounts through Kerberos Pre-Authentication.
It is designed to be used on an internal Windows domain with access to one of the Domain Controllers.
Warning: failed Kerberos Pre-Auth counts as a failed login and WILL lock out accounts

Usage:
  kerbrute [command]
  
  <SNIP>
```

- We can add the tool to our PATH to make it easily accessible from anywhere on the host.

**Adding the Tool to our Path:**
```
$ echo $PATH
/home/htb-student/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/snap/bin:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/home/htb-student/.dotnet/tools

$ sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

- We can now type kerbrute from any location on the system and will be able to access the tool. Now let's run through an example of using the tool to gather an initial username list.

**Enumerating Users with Kerbrute:**
```
$ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users

2021/11/17 23:01:46 >  Using KDC(s):
2021/11/17 23:01:46 >   172.16.5.5:88
2021/11/17 23:01:46 >  [+] VALID USERNAME:       jjones@INLANEFREIGHT.LOCAL
2021/11/17 23:01:46 >  [+] VALID USERNAME:       sbrown@INLANEFREIGHT.LOCAL
2021/11/17 23:01:46 >  [+] VALID USERNAME:       tjohnson@INLANEFREIGHT.LOCAL
2021/11/17 23:01:50 >  [+] VALID USERNAME:       evalentin@INLANEFREIGHT.LOCAL

 <SNIP>
 
2021/11/17 23:01:51 >  [+] VALID USERNAME:       sgage@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       jshay@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       jhermann@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       whouse@INLANEFREIGHT.LOCAL
2021/11/17 23:01:51 >  [+] VALID USERNAME:       emercer@INLANEFREIGHT.LOCAL
2021/11/17 23:01:52 >  [+] VALID USERNAME:       wshepherd@INLANEFREIGHT.LOCAL
2021/11/17 23:01:56 >  Done! Tested 48705 usernames (56 valid) in 9.940 seconds
```

We can see from our output that we validated 56 users in the INLANEFREIGHT.LOCAL domain and it took only a few seconds to do so. Now we can take these results and build a list for use in targeted password spraying attacks.

---

### Identifying Potential Vulnerabilities

**NT AUTHORITY\SYSTEM** is a built-in Windows account with the highest OS-level access. It runs most Windows services and commonly runs third-party services by default.

**Key Point:** On `domain-joined` hosts, `SYSTEM` can enumerate Active Directory by impersonating the computer account (essentially another user account). SYSTEM-level access in a domain environment is nearly equivalent to having a domain user account.

**Gaining SYSTEM Access**

Methods include:
* Remote exploits: MS08-067, EternalBlue, BlueKeep
* Service abuse: Exploiting `services running as SYSTEM` or using `SeImpersonate` privileges (using `Juicy Potato`—works on older Windows OS, limited on Server 2019)
* Local privilege escalation: Windows OS vulnerabilities (e.g., Windows 10 Task Scheduler 0-day)
* Admin-to-SYSTEM: Gaining local admin on domain-joined host, then using Psexec to launch SYSTEM cmd window

**What SYSTEM Access Enables**

With SYSTEM on a domain-joined host, you can:
* Enumerate domain using built-in or offensive tools (BloodHound, PowerView)
* Execute Kerberoasting/ASREPRoasting attacks
* Run Inveigh for Net-NTLMv2 hashes or SMB relay attacks
* Perform token impersonation to hijack privileged domain accounts
* Carry out ACL attacks

---

## A Word Of Caution

Consider the **scope and style** of your test when selecting tools:

**Non-Evasive Tests:**
When conducting open penetration tests where the customer's staff knows you're testing, noise level typically doesn't matter.

**Evasive/Red Team Engagements:**
During evasive tests, adversarial assessments, or red team engagements, you're mimicking real attacker TTPs—**stealth is critical**. Tools like Nmap scanning entire networks are loud and will trigger alerts for prepared SOCs or blue teamers. Many standard pentest tools will set off alarms.

**Best Practice:** Always clarify assessment goals with the client **in writing** before beginning to ensure your approach aligns with their expectations and requirements.
