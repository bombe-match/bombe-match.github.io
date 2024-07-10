# Yara rule
YARA is a tool primarily used for identifying and classifying malware samples. It is widely utilized in cybersecurity, especially by threat hunters and researchers.

What we can do with Yara?
- Identify and classify malware
- find new malware samples and based on family-specific features
- find new exploits and zero-days
- help speeding up incident response
- classification: identify file formats, archives, packed files, known threats
- build your own private antivirus

## Recommended software when writing Yara rule
These tools can help you write YARA rules more smoothly.
- String analyzer
- PE file structure viewer
- Hex viewer
- Binary diffing tool
- IDA Pro / Ghidra

## The components of Yara 
Yara include Meta, Strings, Condition
- Meta: The meta section contains metadata about the rule. It's not used for matching but provides useful information.
- String: The strings section lists the patterns the rule is looking for in the files.
- Condition: The condition section defines the criteria for the rule to match.

## Example of Yara rule
```C
rule ExampleRule {
    meta:
        author = "Bobo"
        type = "APT"
        description = "This rule detects a specific malicious file based on known strings."
        date = "2024-07-01"
    strings:
        $string1 = "malicious_string_1"
        $string2 = "malicious_string_2"
        $hex_string = { 6D 61 6C 69 63 69 6F 75 73 }
    condition:
        (uint16(0) == 0x4D5A) and (any of ($string*)) (filesize < 5000000) and ($hex_string)
}
```
In the above example : 
- The meta section includes information about this rule such as the author's name, category, a brief description, and the creation date
- The strings section includes what the rule looking for :
    - $string1: This string identifier looks for the ASCII string "malicious_string_1". 
    - $string2: This string identifier looks for the ASCII string "malicious_string_2". 
    - $hex_string: This identifier looks for a specific sequence of hexadecimal bytes (which translates to the ASCII string "malicious").
- In this condition, it means that it should successfully match certain conditions.
    - uint16(0) == 0x4D5A: This checks if the first two bytes of the file are 0x4D5A, which is the magic number for a Windows executable (MZ header).
    - any of ($string*): This checks if any of the strings defined in the strings section (with identifiers starting with $string) are present in the file.
    - the filesize can't > 5MB
    - ($hex_string): This checks if the specific hexadecimal string is present in the file.

To run this rule, open the terminal and type : 
```c
yara -r -s ExampleRule.yara  game.exe
```
`-r` is used to check all the directory recursively.
`-s` is used to show the matched strings.
ExampleRule.yara is the rule file we made earlier.
game.exe is the malware file we check for matching strings.

For more detailed information about YARA rule keywords and methods, please refer to its documentation.
https://yara.readthedocs.io/en/stable/index.html


## Using Yara from Python
Here's a simple example of writing a YARA scanner in Python using the yara-python library. This script will compile a YARA rule, scan a file for matches, and print the results.

Before you start, make sure you have the yara-python library installed. You can install it using pip:
```
pip install yara-python
```
The Yara rule using what we have just created:
```C
rule ExampleRule {
    meta:
        author = "Bobo"
        type = "APT"
        description = "This rule detects a specific malicious file based on known strings."
        date = "2024-07-01"
    strings:
        $string1 = "malicious_string_1"
        $string2 = "malicious_string_2"
        $hex_string = { 6D 61 6C 69 63 69 6F 75 73 }
    condition:
        (uint16(0) == 0x4D5A) and (any of ($string*)) (filesize < 5000000) and ($hex_string)
}
```
Next, create a Python script named yara_scanner.py:
```python
import yara

# Define the path to the YARA rule file and the file to scan
rule_file = 'example_rule.yar'
file_to_scan = 'sample_file.exe'

# Compile the YARA rule
rules = yara.compile(filepath=rule_file)

# Scan the file
matches = rules.match(file_to_scan)

# Print the results
if matches:
    print(f"YARA rule matched! Details:\n{matches}")
else:
    print("No matches found.")
```
To run the script, save it as yara_scanner.py and run it in your terminal:
```python
python yara_scanner.py
```
Make sure you have a file named sample_file.exe to scan in the same directory as the script or provide the correct path to a file you want to scan.

For more detailed information about Yara-python  keywords and methods, please refer to its documentation
https://yara.readthedocs.io/en/stable/yarapython.html

## Tools
https://github.com/VirusTotal/yara
https://github.com/VirusTotal/yara-python
https://github.com/InQuest/awesome-yara
https://github.com/100DaysofYARA

## Resource
https://www.brighttalk.com/webcast/15591/388802
https://www.picussecurity.com/resource/glossary/what-is-a-yara-rule
https://www.varonis.com/blog/yara-rules
