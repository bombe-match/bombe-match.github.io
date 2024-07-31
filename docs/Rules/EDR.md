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
  "answer": "Malicious program filename",
  "secret": "User ID"
}
```

Each answer submission must include a secret.

Answers can only be submitted once.

## Malicious Program Name Format

The malicious program name is: `BOMBE_EDR_FLAG_xxx`, where `xxx` is a combination of 32 digits and letters.

There will be many programs with the above format as filenames in the environment. EDR must find the genuine malicious program among them.

## Prohibitions

- Tampering with or making the target file unreadable.
- Causing a system blue screen (BSOD).
- Destroying the system environment, causing the program to be unable to execute.
- Interrupting network connections.

## Victory Conditions and Scoring Method

- Victory Condition: Find the only malicious program in the environment and submit the answer to the specified API.
- Scoring Method: Score will be updated using the ELO scoring system.
