# Rules for EDR

## Task

Compile all functions into a single Windows EXE executable. The executable should automatically complete all required tasks without user interaction or parameter input. Identify the malicious program in the environment and upload the answer along with the user ID to the specified location.

EDR must reside in the system and cannot terminate after execution.

## Answer Upload API Location

- API: https://x.bombe.digitalplaguedoctors.com/submitEdrAns

This API location can only be accessed within the competition's internal network.

## Answer Format

```json
{
  "answer": "malware filename",
  "secret": "your secret"
}
```

Each answer submission must include a `secret`.  
You will get a `secret` after you signup on our contest website.  
Answers can only be submitted once.

## Malware Name Format

Malware name is: `BOMBE_EDR_FLAG_xxx`, where `xxx` is a combination of 32 digits and letters.

There will be many other normal programs with the same above format as filenames in the environment. EDR must find the malware among them.

## Prohibitions

- Tampering with or making the target file unreadable.
- Causing a system blue screen (BSOD).
- Destroying the system environment, causing the program to be unable to execute.
- Interrupting network connections.

## Victory Conditions

Find the malware in the environment and submit the malware name to the specified API.
