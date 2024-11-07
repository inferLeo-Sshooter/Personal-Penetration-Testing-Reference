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
# SQLmap
