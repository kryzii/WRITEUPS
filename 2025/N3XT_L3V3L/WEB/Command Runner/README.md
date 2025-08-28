<img width="609" height="338" alt="Screenshot 2025-08-27 154817" src="https://github.com/user-attachments/assets/daf2a613-4fff-4be5-b6ae-f259bba21d86" />

# Challenge 

The page presented a minimal interface: a text box where you could enter system commands to execute. The hint was in the description:

<img width="929" height="489" alt="image" src="https://github.com/user-attachments/assets/2cc96e57-9dd4-4d5a-b4a4-ae84c050906b" />

*“Many common commands and characters are restricted.”*

Looking at the HTML source revealed the blacklist:

```
<!--
    $blacklist = [';', '&', '|', '`', '$', '(', ')', '<', '>', '{', '}', 'cat', 'more', 'less', 'head', 'tail', 'nl', 'ls', 'dir', 'sh', 'bash', 'python', 'perl', 'php', 'ruby', 'nc', 'netcat', 'wget', 'curl', 'rm', 'mv', 'cp', 'echo', 'printf', 'awk', 'sed', 'grep', 'cut', 'sort', 'base64', 'rev', 'tac'
    
    ,'uniq','xdd']
    -->
```

## Solution

Directly typing `ls` or `cat` was blocked.

But blacklists often fail when you add whitespace tricks like tabs `%09` or unexpected characters. I even thought about using the classic IFS bypass (`${IFS}`), but since both `{}` and `$` were filtered out in this challenge, that wasn’t an option. Luckily, `%09` worked right away and was much simpler.

For example:

```
l\s%09-lah%09
```

This bypassed the `ls` filter and listed the current directory:

<img width="780" height="545" alt="image" src="https://github.com/user-attachments/assets/2d5415eb-19ca-4bb3-ad44-4dfd211a24bf" />

I checked inside the `fein` folder, but there was nothing useful there. In fact, this challenge was a bit messy some players had already dumped files.

I MEANT, **THAT MESSY**: 

<img width="940" height="632" alt="image" src="https://github.com/user-attachments/assets/a245b272-a4db-4505-9aa3-f82b348b4f82" />

<img width="368" height="801" alt="image" src="https://github.com/user-attachments/assets/af9e3a38-c058-4201-926a-2000b49dc350" /><img width="718" height="675" alt="image" src="https://github.com/user-attachments/assets/c930516c-cf10-4885-8bf3-7f3de7f20309" />

Fake `flag.txt` files, joke names like **flag[your_ass]**, and troll notes like **note_i_have_a_shell_there_is_no_flag** were everywhere.Since the blacklist was weak, it was trivial for players to bypass it and create junk files, so the place quickly got flooded with distractions. The chaos made the challenge look harder than it really was, even though the real solution was much simpler.

At first, I wasted time chasing these distractions. Trying find, opening bogus `flag2.txt`, even grepping for *"n3xt"*. But none of it led anywhere. The noise just made the challenge look way harder than it actually was.

In reality, the flag wasn’t hidden under all that clutter. It was sitting in `/root`, untouched, waiting for a proper bypass. 

Navigating upward also worked:

```
l\s%09-lah%09/
```

<img width="798" height="897" alt="image" src="https://github.com/user-attachments/assets/6dc44616-9a68-4ebe-ae41-2d1c949a3007" />

This gave full directory listings, including `/root` and interesting scripts.

While poking around, I stumbled on `watchdog.sh`. Reading through it, I noticed it had a simple loop that would restore `index.php` from **/root/backup/index.php** if it was ever deleted. Interesting detail - not directly part of the solve, but it hinted that **/root/backup** might hold something important.

```
ca\t%09/watchdog.s\h
```

<img width="852" height="670" alt="image" src="https://github.com/user-attachments/assets/3398a8dc-262d-4ac0-a5f3-442726b9a62b" />

`/var/www/html/index.php` → the application source

`/root/backup/index.php` → a backup copy

But with the heavy blacklist in place, every attempt either got blocked or returned nothing useful. It felt like the flag was deliberately hidden out of reach.

At this stage though, the challenge environment felt chaotic. With all the troll files floating around, I honestly thought maybe some kids had escalated access and even deleted the real flag without the author noticing. For a few hours I second-guessed myself, even pinged the author for a quick sanity check and then took a Netflix break to reset my brain.

When I came back, I shifted my approach. Instead of brute-forcing the filesystem with find, grep, or searching for *"n3xt"*, I decided to look at `/root/backup/index.php`.

<img width="866" height="615" alt="image" src="https://github.com/user-attachments/assets/21c66c99-ad96-47c7-9307-f037ebb59e2e" />

That was the turning point. Seeing that the backup copy of the app lived inside `/root`, it clicked: *if backups are stored here, maybe the flag is too.*

## Flag

So I tried reading `/root/flag.txt` directly, using a tab-injected bypass for cat:

<img width="873" height="553" alt="image" src="https://github.com/user-attachments/assets/bcbc7389-1e3a-45b2-9a36-86064386a357" />

```
ca\t%09/root/flag.txt
```

And it worked!! 🚩

```
n3xt{C0mm@nd_Inj3ct!0n_success_sorry_for_fucking_error}
```
