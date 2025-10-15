# Table of Contents

- [Interacting with Common Services](#interacting-with-common-services)
  - [1. File Share Services](#1-file-share-services)
    - [Server Message Block (SMB)](#server-message-block-smb)
      - [1.1 - Windows](#11---windows)
        - [Dir](#dir)
        - [Findstr](#findstr)
      - [1.2 - Windows PowerShell](#12---windows-powershell)
        - [Get-ChildItem, New-PSDrive](#get-childitem-new-psdrive)
        - [Select-String](#select-string)
      - [1.3 - Linux](#13---linux)
        - [Mount](#mount)
        - [Find](#find)
  - [2. Other Services](#2-other-services)
    - [2.1 - Email](#21---email)
    - [2.2 - Databases](#22---databases)
      - [MSSQL](#mssql)
      - [MySQL](#mysql)
      - [GUI Application](#gui-application)
  - [3. Tools](#3-tools)


---
# Interacting with Common Services

To find vulnerabilities in services, you need to:

1. **Understand what you're attacking** - Know the service's purpose and how it works
2. **Learn interaction methods** - Master the tools and techniques for engaging with it
3. **Stay adaptable** - Continuously learn new technologies as the landscape evolves

The key insight: successful exploitation requires deep familiarity with your target - understanding both its intended functionality and how to communicate with it effectively.

## 1. File Share Services

**File sharing services** enable computer file transfers and storage. They've evolved in two waves:

**Traditional (Internal):**
- SMB, NFS, FTP, TFTP, SFTP
- Operated within company networks

**Modern (Cloud):**
- Consumer: Dropbox, Google Drive, OneDrive, SharePoint
- Enterprise storage: AWS S3, Azure Blob Storage, Google Cloud Storage

**Key shift:** Businesses have moved from purely internal file-sharing protocols to hybrid environments that include third-party cloud services, expanding the attack surface for security professionals to understand and test.

## Server Message Block (SMB)

`SMB` is commonly used in Windows networks, and we will often find share folders in a Windows network. We can interact with SMB using the GUI, CLI, or tools. Let us cover some common ways of interacting with SMB using Windows & Linux.

### 1.1 - Windows

There are different ways we can interact with a shared folder using Windows, and we will explore a couple of them. On Windows GUI, we can press `[WINKEY] + [R]` to open the Run dialog box and type the file share location, e.g.: `\\192.168.220.129\Finance\`

<img width="1025" height="573" alt="image" src="https://github.com/user-attachments/assets/79947b71-d584-4686-adff-b6dd3bc59324" />

Suppose the shared folder allows anonymous authentication, or we are authenticated with a user who has privilege over that shared folder. In that case, we will not receive any form of authentication request, and it will display the content of the shared folder.

<img width="1024" height="577" alt="image" src="https://github.com/user-attachments/assets/7d023c2f-8ddf-45b4-a426-16a21ea0495f" />

If we do not have access, we will receive an authentication request.

<img width="1023" height="578" alt="image" src="https://github.com/user-attachments/assets/8be4e674-719c-4bcd-a4a9-cff16dac2c6a" />

---
#### Dir

Some commands to interact with file share using Command Shell (CMD) and PowerShell:

**Windows CMD - DIR**:
```
C:\htb> dir \\192.168.220.129\Finance\

Volume in drive \\192.168.220.129\Finance has no label.
Volume Serial Number is ABCD-EFAA

Directory of \\192.168.220.129\Finance

02/23/2022  11:35 AM    <DIR>          Contracts
               0 File(s)          4,096 bytes
               1 Dir(s)  15,207,469,056 bytes free
```

**Windows CMD - Net Use:**
```
C:\htb> net use n: \\192.168.220.129\Finance

The command completed successfully.
```
The command `net` use connects a computer to or disconnects a computer from a shared resource or displays information about computer connections. We can connect to a file share with the command and map its content to the drive letter `n`.

We can also provide a username and password to authenticate to the share.

```
C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123

The command completed successfully.
```

With the shared folder mapped as the `n drive`, we can execute Windows commands as if this shared folder is on our local computer. 

Let's find how many **files the shared folder and its subdirectories contain**:

**Windows CMD - DIR:**
```
C:\htb> dir n: /a-d /s /b | find /c ":\"

29302
```

We found 29,302 files. Let's walk through the command:

|Syntax	|Description|
|-|-|
|`dir`|	Application|
|`n:`	|Directory or drive to search|
|`/a-d`	|`/a` is the attribute and `-d` means not directories|
|`/s`	|Displays files in a specified directory and all subdirectories|
|`/b`	|Uses bare format (no heading information or summary)|

The following command `| find /c ":\\"` process the output of `dir n: /a-d /s /b` to count how many files exist in the directory and subdirectories. You can use `dir /?` to see the full help. Searching through 29,302 files is time consuming, scripting and command line utilities can help us speed up the search. With `dir` we can search for specific names in files such as:
* cred
* password
* users
* secrets
* key
Common File Extensions for source code such as: `.cs`, `.c`, `.go`, `.java`, `.php`, `.asp`, `.aspx`, `.html`.

```
C:\htb>dir n:\*cred* /s /b

n:\Contracts\private\credentials.txt


C:\htb>dir n:\*secret* /s /b

n:\Contracts\private\secret.txt
```

---

#### Findstr

If we want to search for a specific word within a text file, we can use `findstr`.

**Windows CMD - Findstr:**
```
c:\htb>findstr /s /i cred n:\*.*

n:\Contracts\private\secret.txt:file with all credentials
n:\Contracts\private\credentials.txt:admin:SecureCredentials!
```

More `findstr` usge: [here](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/findstr#examples)

---

### 1.2 - Windows PowerShell

`PowerShell` was designed to extend the capabilities of the Command shell to run PowerShell commands called `cmdlets`. Cmdlets are similar to Windows commands but provide a more extensible scripting language.

#### Get-ChildItem, New-PSDrive

```
PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\

    Directory: \\192.168.220.129\Finance

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/23/2022   3:27 PM                Contracts
```

Instead of `net use`, we can use `New-PSDrive` in PowerShell.

```
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"

Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
----           ---------     --------- --------      ----                                               ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```

To provide a username and password with Powershell, we need to create a PSCredential object. It offers a centralized way to manage usernames, passwords, and credentials.

```
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

Name           Used (GB)     Free (GB) Provider      Root                                                              CurrentLocation
----           ---------     --------- --------      ----                                                              ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```

In PowerShell, we can use the command `Get-ChildItem` or the short variant `gci` instead of the command `dir`.

```
PS C:\htb> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count

29302
```

We can use the property `-Include` to find specific items from the directory specified by the Path parameter.

```
PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File

    Directory: N:\Contracts\private

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/23/2022   4:36 PM             25 credentials.txt
```

#### Select-String

The `Select-String` cmdlet uses regular expression matching to search for text patterns in input strings and files. We can use `Select-String` similar to `grep` in UNIX or `findstr.exe` in Windows.

```
PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List

N:\Contracts\private\secret.txt:1:file with all credentials
N:\Contracts\private\credentials.txt:1:admin:SecureCredentials!
```

### 1.3 - Linux

Linux (UNIX) machines can also be used to browse and mount SMB shares. Note that this can be done whether the target server is a Windows machine or a Samba server.

#### Mount
```
$ sudo mkdir /mnt/Finance
$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```
As an alternative, we can use a credential file.
```
$ mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```
The file `credentialfile` has to be structured like this:
```
username=plaintext
password=Password123
domain=.
```

Once a shared folder is mounted, you can use common Linux tools such as `find` or `grep` to interact with the file structure. 

#### Find

```
$ find /mnt/Finance/ -name *cred*

/mnt/Finance/Contracts/private/credentials.txt
```

Next, let's find files that contain the string `cred`:

```
$ grep -rn /mnt/Finance/ -ie cred

/mnt/Finance/Contracts/private/credentials.txt:1:admin:SecureCredentials!
/mnt/Finance/Contracts/private/secret.txt:1:file with all credentials
```
---

## 2. Other Services

There are other file-sharing services such as FTP, TFTP, and NFS that we can attach (mount) using different tools and commands. However, once we mount a file-sharing service, we must understand that we can use the available tools in Linux or Windows to interact with files and directories. As we discover new file-sharing services, we will need to investigate how they work and what tools we can use to interact with them.

### Email

We typically need two protocols to send and receive messages, one for sending and another for receiving. The Simple Mail Transfer Protocol (SMTP) is an email delivery protocol used to send mail over the internet. Likewise, a supporting protocol must be used to retrieve an email from a service. There are two main protocols we can use POP3 and IMAP.

We can use a mail client such as `Evolution` (`$ sudo apt-get install evolution`), the official personal information manager, and mail client for the GNOME Desktop Environment. We can interact with an email server to send or receive messages with a mail client. 

**Note:** If an error appears when starting evolution indicating "bwrap: Can't create file at ...", use this command to start `evolution export WEBKIT_FORCE_SANDBOX=0 && evolution`.

[Video - Connecting to IMAP and SMTP using Evolution](https://youtu.be/xelO2CiaSVs?si=nIUzQoEuxg-cKyNz)

We can use the domain name or IP address of the mail server. If the server uses SMTPS or IMAPS, we'll need the appropriate encryption method (TLS on a dedicated port or STARTTLS after connecting). We can use the `Check for Supported Types` option under authentication to confirm if the server supports our selected method.

---

### Databases

Databases are typically used in enterprises, and most companies use them to store and manage information. There are different types of databases, such as Hierarchical databases, NoSQL (or non-relational) databases, and SQL relational databases.

Focus on SQL relational databases and the two most common relational databases called `MySQL` & `MSSQL`. We have three common ways to interact with databases:

1.	Command Line Utilities (`mysql` or `sqsh`)
2.	Programming Languages
3.	A GUI application to interact with databases such as HeidiSQL, MySQL Workbench, or SQL Server Management Studio.

#### MSSQL

To interact with `MSSQL` (Microsoft SQL Server) with Linux we can use `sqsh` or `sqlcmd` if you are using Windows. Sqsh is much more than a friendly prompt. It is intended to provide much of the functionality provided by a command shell, such as variables, aliasing, redirection, pipes, back-grounding, job control, history, command substitution, and dynamic configuration. We can start an interactive SQL session as follows:

**Linux - SQSH:**
`$ sqsh -S 10.129.20.13 -U username -P Password123`

The `sqlcmd` utility lets you enter Transact-SQL statements, system procedures, and script files through a variety of available modes:
* At the command prompt.
* In Query Editor in SQLCMD mode.
* In a Windows script file.
* In an operating system (Cmd.exe) job step of a SQL Server Agent job.

**Windows - SQLCMD:**
`C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123`

#### MySQL

To interact with `MySQL`, we can use MySQL binaries for Linux (`mysql`) or Windows (`mysql.exe`). Start an interactive SQL Session using Linux:

**Linux - MySQL:**
`$ mysql -u username -pPassword123 -h 10.129.20.13`

We can easily start an interactive SQL Session using Windows:

**Windows - MySQL:**
`C:\htb> mysql.exe -u username -pPassword123 -h 10.129.20.13`

#### GUI Application

Database engines commonly have their own GUI application. `MySQL` has `MySQL Workbench` and `MSSQL` has `SQL Server Management Studio` or `SSMS`, we can install those tools in our attack host and connect to the database. SSMS is only supported in Windows. An alternative is to use community tools such as `dbeaver`. 

`dbeaver` is a multi-platform database tool for Linux, macOS, and Windows that supports connecting to multiple database engines such as MSSQL, MySQL, PostgreSQL, among others, making it easy for us, as an attacker, to interact with common database servers.

To install `dbeaver` using a Debian package we can download the release .deb package from (https://github.com/dbeaver/dbeaver/releases) and execute the following command:

`$ sudo dpkg -i dbeaver-<version>.deb`

To start the application use:

`$ dbeaver &`

To connect to a database, we will need a set of `credentials`, the `target IP` and `port number of the database`, and the `database engine` we are trying to connect to (MySQL, MSSQL, or another).

[Video - Connecting to MSSQL DB using dbeaver](https://youtu.be/gU6iQP5rFMw?si=cLJ8EYZyRVlV7mOP)

[Video - Connecting to MSSQL DB using dbeaver](https://youtu.be/PeuWmz8S6G8?si=kW1Gps_tj_REzWbS)

Once we have access to the database using a command-line utility or a GUI application, we can use common Transact-SQL statements to enumerate databases and tables containing sensitive information such as usernames and passwords. If we have the correct privileges, we could potentially execute commands as the MSSQL service account.

---

## 3. Tools

|SMB	|FTP	|Email	|Databases|
|-|-|-|-|
|smbclient|	ftp|	Thunderbird|	mssql-cli|
|CrackMapExec|	lftp|	Claws|	mycli|
|SMBMap|	ncftp|	Geary|	mssqlclient.py|
|Impacket|	filezilla	|MailSpring|	dbeaver|
|psexec.py|	crossftp|	mutt|	MySQL Workbench|
|smbexec.py||		mailutils|	SQL Server Management Studio or SSMS|
|||	sendEmail||
|||	swaks||
|||	sendmail||



