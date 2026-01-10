# Table of Contents

- [Active Directory Protocols](#active-directory-protocols)
  - [Kerberos](#kerberos)
  - [DNS](#dns)
  - [LDAP](#ldap)
  - [MSRPC](#msrpc)
- [NTLM Authentication](#ntlm-authentication)
  - [LM](#lm)
  - [NTHash (NTLM)](#nthash-ntlm)
  - [NTLMv1 (Net-NTLMv1)](#ntlmv1-net-ntlmv1)
  - [NTLMv2 (Net-NTLMv2)](#ntlmv2-net-ntlmv2)
  - [Domain Cached Credentials (MSCache2)](#domain-cached-credentials-mscache2)

---

# Active Directory Protocols

While Windows operating systems use a variety of protocols to communicate, Active Directory specifically requires `Lightweight Directory Access Protocol (LDAP)`, Microsoft's version of `Kerberos`, `DNS` for authentication and communication, and `MSRPC` which is the Microsoft implementation of `Remote Procedure Call (RPC)`, an interprocess communication technique used for client-server model-based applications.

- DNS - Name resolution (finding Domain Controllers and servers by hostname)
- Kerberos - Authentication (proving user identity via tickets)
- LDAP - Directory queries (retrieving user attributes, groups, permissions)
- MSRPC - Communication framework (enables remote calls to services like SAMR, DRSUAPI)

## Kerberos

Kerberos has been the default authentication protocol for domain accounts since Windows 2000. It's an open standard enabling interoperability and uses mutual authentication where both user and server verify identities. Unlike password-based systems, Kerberos uses a ticket-based, stateless protocol.

In Active Directory, Domain Controllers run a Kerberos Key Distribution Center (KDC). The authentication flow works as follows: When users log in, their client requests a ticket from the KDC with a password-encrypted request. If the KDC successfully decrypts this request (AS-REQ), it issues a Ticket Granting Ticket (TGT). Users then present the TGT to request a Ticket Granting Service (TGS) ticket, encrypted with the service's NTLM password hash. Finally, the client presents the TGS to access the desired service, which decrypts it for verification.

This process ensures credentials aren't transmitted over the network when accessing resources. The KDC doesn't record transactions; instead, it relies on valid TGT possession as proof of authenticated identity.

**Kerberos Authentication Process:**

1. When a user logs in, their password is used to encrypt a timestamp, which is sent to the Key Distribution Center (KDC) to verify the integrity of the authentication by decrypting it. The KDC then issues a Ticket-Granting Ticket (TGT), encrypting it with the secret key of the krbtgt account. This TGT is used to request service tickets for accessing network resources, allowing authentication without repeatedly transmitting the user's credentials. This process decouples the user's credentials from requests to resources.
2. The KDC service on the DC checks the authentication service request (AS-REQ), verifies the user information, and creates a Ticket Granting Ticket (TGT), which is delivered to the user.
3. The user presents the TGT to the DC, requesting a Ticket Granting Service (TGS) ticket for a specific service. This is the TGS-REQ. If the TGT is successfully validated, its data is copied to create a TGS ticket.
4. The TGS is encrypted with the NTLM password hash of the service or computer account in whose context the service instance is running and is delivered to the user in the TGS_REP.
5. The user presents the TGS to the service, and if it is valid, the user is permitted to connect to the resource (AP_REQ).

<img width="967" height="830" alt="image" src="https://github.com/user-attachments/assets/7ac39404-a342-41f3-8289-57fd8531a28c" />

The Kerberos protocol uses port 88 (both TCP and UDP). When enumerating an Active Directory environment, we can often locate Domain Controllers by performing port scans looking for open port 88 using a tool such as Nmap.

---

## DNS

Active Directory Domain Services (AD DS) uses DNS to enable clients (workstations, servers, and other systems) to locate Domain Controllers and facilitate communication between Domain Controllers themselves. DNS resolves hostnames to IP addresses across internal networks and the internet.

AD maintains a database of network services through service records (SRV), allowing clients to locate needed resources like file servers, printers, or Domain Controllers. Dynamic DNS automatically updates IP address changes in the database, eliminating manual entry errors and ensuring clients can locate and communicate with hosts using correct IP addresses.

When a client joins the network, it queries the DNS service to retrieve an SRV record containing the Domain Controller's hostname, then uses that hostname to obtain the Domain Controller's IP address. DNS operates on TCP and UDP port 53, defaulting to UDP but switching to TCP when messages exceed 512 bytes or communication issues arise.

<img width="1080" height="593" alt="image" src="https://github.com/user-attachments/assets/ec355c00-7fea-4435-8ad4-8b74e6a26958" />

### Forward DNS Lookup

We can perform a `nslookup` for the domain name and retrieve all Domain Controllers' IP addresses in a domain.
```
PS C:\htb> nslookup INLANEFREIGHT.LOCAL

Server:  172.16.6.5
Address:  172.16.6.5

Name:    INLANEFREIGHT.LOCAL
Address:  172.16.6.5
```

### Reverse DNS Lookup

If we would like to obtain the DNS name of a single host using the IP address, we can do this as follows:
```
PS C:\htb> nslookup 172.16.6.5

Server:  172.16.6.5
Address:  172.16.6.5

Name:    ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
Address:  172.16.6.5
```

### Finding IP Address of a Host

If we would like to find the IP address of a single host, we can do this in reverse. We can do this with or without specifying the FQDN.
```
PS C:\htb> nslookup ACADEMY-EA-DC01

Server:   172.16.6.5
Address:  172.16.6.5

Name:    ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
Address:  172.16.6.5
```

---

## LDAP

Active Directory supports Lightweight Directory Access Protocol (LDAP) for directory lookups. LDAP is an open-source, cross-platform protocol used for authentication against various directory services, including AD. The current specification is Version 3 (RFC 4511). Understanding LDAP is crucial for both attackers and defenders. LDAP uses port 389, while LDAP over SSL (LDAPS) uses port 636.

AD stores user account information and security data like passwords, sharing this information across the network. LDAP is the language applications use to communicate with directory service servers—essentially how network systems "speak" to AD.

An LDAP session starts by connecting to an LDAP server (Directory System Agent). In AD environments, the Domain Controller actively listens for LDAP requests, including security authentication requests.

<img width="1204" height="617" alt="image" src="https://github.com/user-attachments/assets/cbfa0ff3-b184-43ad-bd31-30a3386ec39d" />

The relationship between AD and LDAP can be compared to Apache and HTTP. The same way Apache is a web server that uses the HTTP protocol, Active Directory is a directory server that uses the LDAP protocol.

While uncommon, you may come across organization while performing an assessment that do not have AD but are using LDAP, meaning that they most likely use another type of LDAP server such as OpenLDAP.

### AD LDAP Authentication

LDAP is set up to authenticate credentials against AD using a "BIND" operation to set the authentication state for an LDAP session. There are two types of LDAP authentication.

1. `Simple Authentication`: This includes anonymous authentication, unauthenticated authentication, and username/password authentication. Simple authentication means that a username and password create a BIND request to authenticate to the LDAP server.

2. `SASL Authentication`: The Simple Authentication and Security Layer (SASL) framework uses other authentication services, such as Kerberos, to bind to the LDAP server and then uses this authentication service (Kerberos in this example) to authenticate to LDAP. The LDAP server uses the LDAP protocol to send an LDAP message to the authorization service, which initiates a series of challenge/response messages resulting in either successful or unsuccessful authentication. SASL can provide additional security due to the separation of authentication methods from application protocols.

LDAP authentication messages are sent in cleartext by default so anyone can sniff out LDAP messages on the internal network. It is recommended to use TLS encryption or similar to safeguard this information in transit.

---

## MSRPC

As mentioned above, MSRPC is Microsoft's implementation of Remote Procedure Call (RPC), an interprocess communication technique used for client-server model-based applications. Windows systems use MSRPC to access systems in Active Directory using four key RPC interfaces.

|Interface Name	|Description|
|-|-|
|`lsarpc`| A set of RPC calls to the Local Security Authority (LSA) system which manages the local security policy on a computer, controls the audit policy, and provides interactive authentication services. LSARPC is used to perform management on domain security policies.|
|`netlogon`|Netlogon is a Windows process used to authenticate users and other services in the domain environment. It is a service that continuously runs in the background.|
|`samr`|Remote SAM (samr) provides management functionality for the domain account database, storing user and group information. The protocol enables IT administrators to create, read, update, and delete security principal information for users, groups, and computers. Attackers and pentesters can exploit samr for domain reconnaissance using tools like `BloodHound` to map AD networks and visualize attack paths toward administrative access or domain compromise. By default, all authenticated domain users can perform remote SAM queries, allowing them to gather extensive AD domain information. Organizations can mitigate this reconnaissance risk by modifying a Windows registry key to restrict remote SAM queries to administrators only.|
|`drsuapi`|DRSUAPI is the Microsoft API implementing the Directory Replication Service (DRS) Remote Protocol, used for replication tasks across Domain Controllers in multi-DC environments. Attackers can exploit drsuapi to create a copy of the Active Directory domain database (NTDS.dit) file, extracting password hashes for all domain accounts. These hashes can then be used for Pass-the-Hash attacks to access additional systems or cracked offline with tools like Hashcat to obtain cleartext passwords for remote access via protocols such as RDP and WinRM.|

---

# NTLM Authentication

Beyond Kerberos and LDAP, Active Directory uses several other authentication methods including LM, NTLM, NTLMv1, and NTLMv2. LM and NTLM are hash names, while NTLMv1 and NTLMv2 are authentication protocols utilizing these hashes. While imperfect, Kerberos is generally preferred when possible.

**Hash Protocol Comparison**

| Hash/Protocol | Cryptographic Technique | Mutual Authentication | Message Type | Trusted Third Party |
|---------------|------------------------|----------------------|--------------|---------------------|
| `NTLM` | Symmetric key | No | Random number | Domain Controller |
| `NTLMv1` | Symmetric key | No | MD4 hash, random number | Domain Controller |
| `NTLMv2` | Symmetric key | No | MD4 hash, random number | Domain Controller |
| `Kerberos` | Symmetric & asymmetric key | Yes | Encrypted ticket (using DES, MD5) | Domain Controller/Key Distribution Center (KDC) |

Understanding the distinction between hash types and the protocols using them is essential.

---

## LM

LAN Manager (LM or LANMAN) hashes are the oldest Windows password storage mechanism, introduced in 1987 with OS/2. They're stored in the SAM database (on hosts) or NTDS.DIT (on Domain Controllers). Due to severe security weaknesses, LM has been disabled by default since Windows Vista/Server 2008, though it still appears in large environments with legacy systems.

LM passwords are limited to 14 characters maximum, are case-insensitive (converted to uppercase), and use a 69-character keyspace, making them easy to crack with tools like Hashcat.

**Hashing Process:** A 14-character password is split into two 7-character chunks (padded with NULL if shorter). Each chunk creates a DES key, then encrypts the string `KGS!@#$%`, producing two 8-byte ciphertext values that are concatenated into the LM hash. This means attackers only brute force seven characters twice instead of fourteen. Passwords ≤7 characters always produce the same second-half hash value, making them visually identifiable.

LM can be disabled via Group Policy. Format example: `299bd128c1101fd6`.

> **Note**: Windows operating systems prior to Windows Vista and Windows Server 2008 (Windows NT4, Windows 2000, Windows 2003, Windows XP) stored both the LM hash and the NTLM hash of a user's password by default.

---

## NTHash (NTLM)

NT LAN Manager (NTLM) hashes are used on modern Windows systems. NTLM is a challenge-response authentication protocol using three messages: the client sends a `NEGOTIATE_MESSAGE`, the server responds with a `CHALLENGE_MESSAGE` to verify identity, and the client completes authentication with an `AUTHENTICATE_MESSAGE`. 

Hashes are stored in the SAM database locally or the NTDS.DIT database on Domain Controllers. The protocol can use two hashed password values for authentication: the LM hash or the NT hash. The NT hash is the MD4 hash of the little-endian UTF-16 password value, visualized as: `MD4(UTF-16-LE(password))`.

<img width="1025" height="594" alt="image" src="https://github.com/user-attachments/assets/7b9ec996-d245-4083-804f-c1d6e4715dc2" />

Even though they are considerably stronger than LM hashes (supporting the entire Unicode character set of 65,536 characters), they can still be brute-forced offline relatively quickly using a tool such as `Hashcat`. GPU attacks have shown that the entire NTLM 8 character keyspace can be brute-forced in under `3 hours`. Longer NTLM hashes can be more challenging to crack depending on the password chosen, and even long passwords (15+ characters) can be cracked using an offline dictionary attack combined with rules. NTLM is also vulnerable to the `pass-the-hash` attack, which means an attacker can use just the NTLM hash (after obtaining via another successful attack) to authenticate to target systems where the user is a local admin without needing to know the cleartext value of the password.

An NT hash takes the form of `b4b9b02e6f09a9bd760f388b67351e2b`, which is the second half of the full NTLM hash. An NTLM hash looks like this:
```
Rachel:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::
```

Looking at the hash above, we can break the NTLM hash down into its individual parts:

- `Rachel` is the username
- 500 is the Relative Identifier (RID). 500 is the known RID for the `administrator` account
- `aad3c435b514a4eeaad3b935b51304fe` is the LM hash and, if LM hashes are disabled on the system, can not be used for anything
- `e46b9e548fa0d122de7f59fb6d48eaa2` is the NT hash. This hash can either be cracked offline to reveal the cleartext value (depending on the length/strength of the password) or used for a pass-the-hash attack. Below is an example of a successful pass-the-hash attack using the CrackMapExec tool:
```
$ crackmapexec smb 10.129.41.19 -u rachel -H e46b9e548fa0d122de7f59fb6d48eaa2

SMB         10.129.43.9     445    DC01      [*] Windows 10.0 Build 17763 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.43.9     445    DC01      [+] INLANEFREIGHT.LOCAL\rachel:e46b9e548fa0d122de7f59fb6d48eaa2 (Pwn3d!)
```

> **Note**: Neither LANMAN nor NTLM uses a salt.

---

## NTLMv1 (Net-NTLMv1)

The NTLM protocol performs challenge/response authentication between server and client using the NT hash. NTLMv1 uses both NT and LM hashes, making it easier to crack offline after capturing hashes with tools like `Responder` or via `NTLM relay` attacks.

Used for network authentication, the Net-NTLMv1 hash is created through a challenge/response algorithm: the server sends an 8-byte random challenge, and the client returns a 24-byte response. These hashes **`cannot`** be used for pass-the-hash attacks.

The algorithm looks as follows:

**V1 Challenge & Response Algorithm**
```
C = 8-byte server challenge, random
K1 | K2 | K3 = LM/NT-hash | 5-bytes-0
response = DES(K1,C) | DES(K2,C) | DES(K3,C)
```

An example of a full NTLMv1 hash looks like:

**NTLMv1 Hash Example**
```
u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
```

NTLMv1 was the building block for modern NTLM authentication. Like any protocol, it has flaws and is susceptible to cracking and other attacks. 

---

## NTLMv2 (Net-NTLMv2)

NTLMv2 was introduced in Windows NT 4.0 SP4 as a stronger alternative to NTLMv1 and has been the default since Windows Server 2000. It's hardened against certain spoofing attacks that affect NTLMv1.

NTLMv2 sends two responses to the server's 8-byte challenge: The first contains a 16-byte HMAC-MD5 hash of the challenge, a randomly generated client challenge, and an HMAC-MD5 hash of the user's credentials. The second is a variable-length client challenge including the current time, an 8-byte random value, and the domain name.

The algorithm is as follows:

**V2 Challenge & Response Algorithm**
```
SC = 8-byte server challenge, random
CC = 8-byte client challenge, random
CC* = (X, time, CC2, domain name)
v2-Hash = HMAC-MD5(NT-Hash, user name, domain name)
LMv2 = HMAC-MD5(v2-Hash, SC, CC)
NTv2 = HMAC-MD5(v2-Hash, SC, CC*)
response = LMv2 | CC | NTv2 | CC*
```

An example of an NTLMv2 hash is:

**NTLMv2 Hash Example**
```
admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030
```

We can see that developers improved upon v1 by making NTLMv2 harder to crack and giving it a more robust algorithm made up of multiple stages.

---

## Domain Cached Credentials (MSCache2)

In AD environments, authentication methods typically require communication with the Domain Controller. Microsoft developed MS Cache v1 and v2 (Domain Cached Credentials or DCC) to address scenarios where domain-joined hosts cannot reach a Domain Controller due to network outages or technical issues, preventing NTLM/Kerberos authentication.

Hosts store the last **ten** hashes for domain users who successfully logged in, saved in the `HKEY_LOCAL_MACHINE\SECURITY\Cache` registry key. These hashes **cannot** be used in pass-the-hash attacks and are extremely slow to crack, even with powerful GPU rigs, requiring highly targeted efforts or reliance on weak passwords.

Attackers or pentesters can obtain these hashes after gaining local admin access. Format example: `$DCC2$10240#bjones#e4e938d12fe5974dc42a90120bd9c90f`.

Understanding hash types, their strengths, weaknesses, and abuse potential (cracking, pass-the-hash, relay attacks) is essential for penetration testers to avoid futile efforts like attempting to crack Domain Cached Credentials for extended periods.

---
