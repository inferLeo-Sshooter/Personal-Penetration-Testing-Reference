


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

