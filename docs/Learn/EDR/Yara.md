# Yara
# yara筆記

# **Writing YARA rules**

- starts with the keyword “rule”
- follow the same lexical conventions of the C programming language
- the first character cannot be a digit
- cannot exceed 128 characters
- The following keywords are reserved cannot use

| all | and | any | ascii | at | base64 | base64wide | condition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| contains | endswith | entrypoint | false | filesize | for | fullword | global |
| import | icontains | iendswith | iequals | in | include | int16 | int16be |
| int32 | int32be | int8 | int8be | istartswith | matches | meta | nocase |
| none | not | of | or | private | rule | startswith | strings |
| them | true | uint16 | uint16be | uint32 | uint32be | uint8 | uint8be |
| wide | xor | defined |  |  |  |  |  |

## String

### **Hexadecimal strings**

可以用問號取代你不知道的值 他會可以配對任意值

```
rule WildcardExample
{
strings:
        $hex_string = { E2 34 ?? C8 A? FB }

condition:
        $hex_string
}
```

也可以用not指定不是哪些字

```
rule NotExample
{
strings:
        $hex_string = { F4 23 ~00 62 B4 }
        $hex_string2 = { F4 23 ~?0 62 B4 }
condition:
        $hex_stringand $hex_string2
}
```

[4-6]代表中間的字元有四到六組也能配對 但[x-y] 中要小到大 而[10-]代表10到無限 [-]代表0到無限

```
rule JumpExample
{
strings:
        $hex_string = { F4 23 [4-6] 62 B4 }

condition:
        $hex_string
}
-------------------------------
F4 23 01 02 03 04 62 B4
F4 23 00 00 00 00 00 62 B4
F4 23 15 82 A3 04 45 22 62 B4
```

### **Text strings**

| \" | Double quote |
| --- | --- |
| \\ | Backslash |
| \r | Carriage return |
| \t | Horizontal tab |
| \n | New line |
| \xdd | Any byte in hexadecimal notation |

\x41 → 0x41 =A , \x41\x42\x43 = ABC

```
rule TextExample
{
    strings:
        $text_string = "foobar"

    condition:
        $text_string
}
```

### **Case-insensitive strings**

use `nocase` can Ignore  ****lower case and up case

- Foobar/FOObar/FoOBar…

```
rule CaseInsensitiveTextExample
{
    strings:
        $text_string = "foobar" nocase

    condition:
        $text_string
}
```

### **Wide-character strings/XOR strings**

```
rule XorExample3
{
    strings:
        $xor_string = "This program cannot" xor wide ascii
    condition:
        $xor_string
}
```

### **Base64 strings**

`base64` : search for strings that have been base64 encoded

can custom your base64 alphabet

```
rule Base64Example2
{
    strings:
        $a = "This program cannot" base64/base64wide ("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")

    condition:
        $a
}
```

### **Searching for full words**

`fullword` : match only if it appears in the file delimited by non-alphanumeric characters

ex: “domain” cant match “mydomain.com” but it matches 

“my-domain.com” and ”domain.com”

## **Regular expressions**

match email

1. [A-Z0-9.*-]+ is the recipient's name. The + symbol means that [A-Z0-9.*-] must appear at least once, but is unlimited in length, and the content is English, numbers, and specific symbols ( . - _ ).
2. One @ symbol.
3. The [A-Z0-9._-]+, same as here, has the same rules for host names as it does for recipient names.
4. \. [A-Z]{2,4} means the host address only accepts English letters, and can have 2 to 4 columns, delimited by . symbol as delimiter.

```
rule EmailDetection
{
			strings:
					$email = /[A-Z0-9._-]+@[A-Z0-9.-]+\.[A-Z]{2,4}/
			condition:
			    $email
}
```

match phone_numbber

1. ^ means start 
2. \d means number and {2} means only two 
3. ? means the - can exist or not
4. $ is the end

```
rule URLDetection
{
		strings:
				$phone_number = /^09\d{2}-?\d{3}-?\d{3}$/
		condition:
			   $phone_number 
}
```

[http://ccckmit.wikidot.com/regularexpression](http://ccckmit.wikidot.com/regularexpression)

[https://www.runoob.com/regexp/regexp-tutorial.html](https://www.runoob.com/regexp/regexp-tutorial.html)

| keyword | 作用 | 限制 |
| --- | --- | --- |
| nocase | 忽略大小寫 | xor, base64, base64wide |
| wide | 寬字串UTF16 |  |
| ascii | 配對ascii 字串 |  |
| xor | 單字節 xor decode | nocase, base64, base64wide |
| base64 | 配對base64後的結果 | nocase, xor, fullword |
| base64wide | 配對base64後的寬字串 | nocase, xor, fullword |
| fullword | 嚴格配對完整字串 | base64, base64wide |

[參考內容](https://blog.csdn.net/abel_big_xu/article/details/125381650?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522171924681316777224464129%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fall.%2522%257D&request_id=171924681316777224464129&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~first_rank_ecpm_v1~rank_v31_ecpm-15-125381650-null-null.142%5Ev100%5Epc_search_result_base9&utm_term=YARA%E8%A6%8F%E5%89%87)

## Condition

### **Counting strings**

```
rule CountExample
{
    strings:
        $a = "dummy1"
        $b = "dummy2"

    condition:
        #a == 6 and #b > 10
        #a in (filesize-500..filesize) == 2 
}
```

### **String offsets or virtual addresses**

```
rule AtExample
{
    strings:
        $a = "dummy1"
        $b = "dummy2"

    condition:
        $a at 100 and $b at 200 //use to check offset or virtual addresses
}
```

```
rule InExample
{
    strings:
        $a = "dummy1"
        $b = "dummy2"

    condition:
        $a in (0..100) and $b in (100..filesize)
}
```

### **Match length**

Suppose we have a regular expression /fo*/ and we want the rule to trigger when the matched string is between 2 and 4 in length

```
rule VariableLengthRegex
{
		strings:
				$a = /fo*/
	condition:
		    !a >= 2 and !a <= 4
}
```

Wants the rule to trigger when the first match has a length of 2 and the second match has a length of 3.

```
rule MultipleMatches
{
		strings:
				$a = /fo*/
		condition:
		    !a[1] == 2 and !a[2] == 3
}
```

### **File size**

as its name indicates, the size of the file being scanned.

only makes sense when the rule is applied to a file. If the rule is applied to a running process it won’t ever match

```
rule FileSizeExample
{
    condition:
        filesize > 200KB
}
```

### **Accessing data at a given position**

There are many situations in which you may want to write conditions that depend on data stored at a certain file offset or virtual memory address, depending on if we are scanning a file or a running process.

```jsx
The `intXX` functions read 8, 16, and 32 bits signed integers 
`int8/16/32(<offset **or** virtual address>)`

uinxx read 8, 16, and 32 bits unsigned integers 
`uint8/16/32(<offset **or** virtual address>)`

be is means read from big-endian
`int/uint8/16/32be(<offset **or** virtual address>)`
```

uint16(0): read a 16-bit unsigned integer from offset 0 of the file
uint32(uint32(0x3C)): first read a 32-bit unsigned integer from offset 0x3C of the file (this is the offset of the PE signature in the MZ header), and then read another 32-bit unsigned integer from the offset, here check the PE file signature.

```jsx
rule IsPE
{
    condition:
        // MZ signature at offset 0 and ...
        uint16(0) == 0x5A4D and
        // ... PE signature at offset stored in MZ header at 0x3C
        uint32(uint32(0x3C)) == 0x00004550
}
```

### **Sets of strings**

It wil have many strings in file, but not all are but not all of them are needed. 

we can use `of` keywords

ex: 

```

rule OfExample1
{
    strings:
        $a = "dummy1"
        $b = "dummy2"
        $c = "dummy3"

    condition:
        2 of ($a,$b,$c) // just need to match two out of three.
}
```

```
rule OfExample3
{
    strings:
        $foo1 = "foo1"
        $foo2 = "foo2"

        $bar1 = "bar1"
        $bar2 = "bar2"

    condition:
        3 of ($foo*,$bar1,$bar2) // equivalent to 3 of (foo1-3,bar1,bar2)
}
```

```
rule OfExample4
{
    strings:
        $a = "dummy1"
        $b = "dummy2"
        $c = "dummy3"

    condition:
        1 of them // equivalent to 1 of ($*)
}
```

others keyword

```
all of them       // all strings in the rule
any of them       // any string in the rule
all of ($a*)      // all strings whose identifier starts by $a
any of ($a,$b,$c) // any of $a, $b or $c
1 of ($*)         // same that "any of them"
none of ($b*)     // zero of the set of strings that start with "$b"
```

### **Applying the same condition to many strings**

另一個與 `of` 非常相似但更強大的 `for..of` 

用法: `for expression of string_set : ( boolean_expression )`

```
rule ForOfExample2
{
    strings:
        $a = "foo1"
        $b = "foo2"
        $c = "foo3"

    condition:
        for all of them : ( # > 2 ) // occurrences time must be greater than 2
        for any of them : ( @ < 100 ) // offset < 100
        for 2 of ($a, $b, $c) : ( $ at 100 ) // Evaluate $a,$b,$c respectively.
				for all of them : ( ! > 4 ) // length > 4
}
```

### **Iterating over string occurrences**

`for..in`  `@a[i]`  
使用 `@a[i]` 的語法來訪問字串 `$a` 在文件或進程地址空間中出現的位置，其中 `i` 是指示字串 `$a` 的第幾次出現的索引（例如：`@a[1]`, `@a[2]` 等）。

```
rule Occurrences
{
    strings:
        $a = "dummy1"
        $b = "dummy2"

    condition:
        for all i in (1,2,3) : ( @a[i] + 10 == @b[i] )
} // $b 的第一個出現位置應該在 $a 的第一個出現位置之後10個字節
```

```
rule Occurrences
{
    strings:
        $a = "dummy1"

    condition:
        for all i in (1..#a) : ( @a[i] < 100 )
} // 指定 $a 的每個出現位置都應該在文件的前100個字節內。
```

### **Referencing other rules**

引用其他的rule 必須先滿足其他rule1才能滿足MainRule

```
rule Rule1
{
    strings:
        $a = "dummy1"

    condition:
        $a
}

rule Rule2
{
    strings:
        $a = "dummy2"

    condition:
        $a
}

rule MainRule
{
    strings:
        $a = "dummy2"

    condition:
        $a and Rule1
        any of (Rule*)
}
```

- Good yara rule
    - First, if you don’t have the YARA program, [download it](https://virustotal.github.io/yara/).
    - Next, determine the objective for your YARA rule. By identifying the malware you want to detect, you can identify the specific characteristics for your YARA rule; this can include hashes, registry keys, file names, and other indicators of compromise Additionally, you can use other YARA rules that other security analysts have created and shared across the security community.
    - Write your YARA rule. Using the YARA specific syntax, your rule should include descriptions of the malware based on its characteristics. Typically this would include a header, condition, and tags that categorize the rule
    - Test your YARA rule. Navigate to the directory where your test file is located and run the YARA file (or use one of the free services mentioned below).
    - If you write the YARA rule correctly, it will identify the malicious software and send you a message when it detects something.
    - Integrate the YARA rule into your cybersecurity infrastructure.
    
    https://www.veeam.com/blog/yara-rules-malware-detection-analysis.html
    

[https://github.com/InQuest/awesome-yara](https://github.com/InQuest/awesome-yara)

[https://github.com/VirusTotal/yara-python](https://github.com/VirusTotal/yara-python)