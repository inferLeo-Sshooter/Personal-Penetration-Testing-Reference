
# LLMNR/NBT-NS Poisoning - from Linux

After initial domain enumeration—gathering user/group info, identifying hosts and critical services like Domain Controllers, and understanding naming schemes—we now focus on two techniques: network poisoning and password spraying. The goal is to obtain valid cleartext credentials for a domain user account, establishing a foothold for credentialed enumeration.

This section covers acquiring credentials via Man-in-the-Middle attacks on Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) broadcasts. Depending on the network, this can yield low-privileged or administrative password hashes for offline cracking, or even cleartext credentials. While not covered here, these hashes can also enable SMB Relay attacks to authenticate with administrative privileges without cracking passwords.

---

## LLMNR & NBT-NS Primer

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Windows components that provide alternate host identification when DNS fails. When DNS resolution fails, machines use LLMNR (port `5355/UDP`) to query all local network machines for the correct host address. If LLMNR fails, NBT-NS (port `137/UDP`) will be used to attempts resolution via NetBIOS names.

The vulnerability: ANY host on the network can reply to LLMNR/NBT-NS requests. Using tools like `Responder`, we can poison these requests by spoofing an authoritative source, pretending our rogue system knows the requested host's location. When victims communicate with our system and perform authentication, we capture NetNTLM hashes for offline cracking to obtain cleartext passwords. Captured requests can also be relayed to access other hosts or protocols (like LDAP). LLMNR/NBNS spoofing combined with missing SMB signing often leads to administrative access within the domain.

---

## Quick Example - LLMNR/NBT-NS Poisoning

Quick example of the attack flow at a very high level:

1. A host attempts to connect to the print server at `\\print01.inlanefreight.local`, but accidentally types in `\\printer01.inlanefreight.local`.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of `\\printer01.inlanefreight.local`.
4. The attacker (us with `Responder` running) responds to the host stating that it is the `\\printer01.inlanefreight.local` that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and `NTLMv2 password hash`.
6. This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.

---

## TTPs

We are performing these actions to collect authentication information sent over the network in the form of NTLMv1 and NTLMv2 password hashes. 

NTLMv1 and NTLMv2 are authentication protocols that utilize the LM or NT hash. We will then take the hash and attempt to crack them offline using tools such as Hashcat or John with the goal of obtaining the account's cleartext password to be used to gain an initial foothold or expand our access within the domain if we capture a password hash for an account with more privileges than an account that we currently possess.

Several tools can be used to attempt LLMNR & NBT-NS poisoning:

|Tool	|Description|
|-|-|
|[Responder](https://github.com/lgandx/Responder)	|Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.|
|[Inveigh](https://github.com/Kevin-Robertson/Inveigh)	|Inveigh is a cross-platform MITM platform that can be used for spoofing and poisoning attacks.|
|[Metasploit](https://www.metasploit.com/)	|Metasploit has several built-in scanners and spoofing modules made to deal with poisoning attacks.|

Later below will show examples of using `Responder` and `Inveigh` to capture password hashes and attempt to crack them offline. We commonly start an internal penetration test from an anonymous position on the client's internal network with a Linux attack host. Tools such as `Responder` are great for establishing a foothold that we can later expand upon through further enumeration and attacks. `Responder` is written in Python and typically used on a Linux attack host, though there is a .exe version that works on Windows. `Inveigh` is written in both C# and PowerShell (considered legacy). Both tools can be used to attack the following protocols:
* LLMNR
* DNS
* MDNS
* NBNS
* DHCP
* ICMP
* HTTP
* HTTPS
* SMB
* LDAP
* WebDAV
* Proxy Auth

**`Responder`** also has support for:
* MSSQL
* DCE-RPC
* FTP, POP3, IMAP, and SMTP auth

---

### Responder In Action

`Responder` is a relatively straightforward tool, but is extremely powerful and has many different functions. In the previous **Initial Enumeration** section, we utilized Responder in **Analysis (passive) mode**. This means it listened for any resolution requests, but did not answer them or send out poisoned packets.

Let's look at some options available by typing `responder -h` into our console.
```
$ responder -h
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

Usage: responder -I eth0 -w -r -f
or:
responder -I eth0 -wrf

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -A, --analyze         Analyze mode. This option allows you to see NBT-NS,
                        BROWSER, LLMNR requests without responding.
  -I eth0, --interface=eth0
                        Network interface to use, you can use 'ALL' as a
                        wildcard for all interfaces
  -i 10.0.0.21, --ip=10.0.0.21
                        Local IP to use (only for OSX)
  -e 10.0.0.22, --externalip=10.0.0.22
                        Poison all requests with another IP address than
                        Responder's one.
  -b, --basic           Return a Basic HTTP authentication. Default: NTLM
  -r, --wredir          Enable answers for netbios wredir suffix queries.
                        Answering to wredir will likely break stuff on the
                        network. Default: False
  -d, --NBTNSdomain     Enable answers for netbios domain suffix queries.
                        Answering to domain suffixes will likely break stuff
                        on the network. Default: False
  -f, --fingerprint     This option allows you to fingerprint a host that
                        issued an NBT-NS or LLMNR query.
  -w, --wpad            Start the WPAD rogue proxy server. Default value is
                        False
  -u UPSTREAM_PROXY, --upstream-proxy=UPSTREAM_PROXY
                        Upstream HTTP proxy used by the rogue WPAD Proxy for
                        outgoing requests (format: host:port)
  -F, --ForceWpadAuth   Force NTLM/Basic authentication on wpad.dat file
                        retrieval. This may cause a login prompt. Default:
                        False
  -P, --ProxyAuth       Force NTLM (transparently)/Basic (prompt)
                        authentication for the proxy. WPAD doesn't need to be
                        ON. This option is highly effective when combined with
                        -r. Default: False
  --lm                  Force LM hashing downgrade for Windows XP/2003 and
                        earlier. Default: False
  -v, --verbose         Increase verbosity.
```

- The `-A` flag puts us into analyze mode, allowing us to see NBT-NS, BROWSER, and LLMNR requests in the environment without poisoning any responses. We must always supply either an interface or an IP.
- Some common options we'll typically want to use are `-wf`; this will start the WPAD rogue proxy server, while `-f` will attempt to fingerprint the remote host operating system and version.
- We can use the `-v` flag for increased verbosity if we are running into issues, but this will lead to a lot of additional data printed to the console.
- Other options such as `-F` and `-P` can be used to force NTLM or Basic authentication and force proxy authentication, but may cause a login prompt, so they should be used sparingly.
- The use of the `-w` flag utilizes the built-in WPAD proxy server. 

With this configuration shown above, Responder will listen and answer any requests it sees on the wire. If you are successful and manage to capture a hash, Responder will print it out on screen and write it to a log file per host located in the `/usr/share/responder/logs` directory. 

Hashes are saved in the format `(MODULE_NAME)-(HASH_TYPE)-(CLIENT_IP).txt`, and one hash is printed to the console and stored in its associated log file unless `-v` mode is enabled. 

For example, a log file may look like `SMB-NTLMv2-SSP-172.16.5.25`. Hashes are also stored in a SQLite database that can be configured in the `Responder.conf` config file, typically located in `/usr/share/responder` unless we clone the Responder repo directly from GitHub.

We must run the tool with `sudo` privileges or as root and make sure the following ports are available on our attack host for it to function best: 
```UDP 137, UDP 138, UDP 53, UDP/TCP 389,TCP 1433, UDP 1434, TCP 80, TCP 135, TCP 139, TCP 445, TCP 21, TCP 3141,TCP 25, TCP 110, TCP 587, TCP 3128, Multicast UDP 5355 and 5353```

Any of the rogue servers (i.e., SMB) can be disabled in the `Responder.conf` file.

### Starting Responder with Default Settings

`sudo responder -I ens224 `

![responder_hashes](https://github.com/user-attachments/assets/1645797a-2428-4f7e-8ee3-825a3756ca07)

Typically we should start Responder and let it run for a while in a tmux window while we perform other enumeration tasks to maximize the number of hashes that we can obtain. 

Once we are ready, we can pass these hashes to Hashcat using hash mode `5600` for NTLMv2 hashes that we typically obtain with Responder. We may at times obtain NTLMv1 hashes and other types of hashes and can consult the [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page to identify them and find the proper hash mode. If we ever obtain a strange or unknown hash, this site is a great reference to help identify it. 

Once we have enough, we need to get these hashes into a usable format for us right now. NetNTLMv2 hashes are very useful once cracked, but cannot be used for techniques such as pass-the-hash, meaning we have to attempt to crack them offline. We can do this with tools such as Hashcat and John.

```
$ hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80baa52d732719dbf62c34cc:010100000000000080f519d1432cd80136f3af14556f047800000000020008004900340046004e0001001e00570049004e002d0032004e004c005100420057004d00310054005000490004003400570049004e002d0032004e004c005100420057004d0031005400500049002e004900340046004e002e004c004f00430041004c00030014004900340046004e002e004c004f00430041004c00050014004900340046004e002e004c004f00430041004c000700080080f519d1432cd80106000400020000000800300030000000000000000000000000300000227f23c33f457eb40768939489f1d4f76e0e07a337ccfdd45a57d9b612691a800a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e0035002e003200320035000000000000000000:Klmcargo2
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80ba...000000
Time.Started.....: Mon Feb 28 15:20:30 2022 (11 secs)
Time.Estimated...: Mon Feb 28 15:20:41 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1086.9 kH/s (2.64ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10967040/14344385 (76.46%)
Rejected.........: 0/10967040 (0.00%)
Restore.Point....: 10960896/14344385 (76.41%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: L0VEABLE -> Kittikat

Started: Mon Feb 28 15:20:29 2022
Stopped: Mon Feb 28 15:20:42 2022
```

Looking at the results above, we can see we cracked the NET-NTLMv2 hash for user `FOREND`, whose password is `Klmcargo2`. Lucky for us our target domain allows weak 8-character passwords. This hash type can be "slow" to crack even on a GPU cracking rig, so large and complex passwords may be more difficult or impossible to crack within a reasonable amount of time.
