# Rules

This competition aims to simulate the offensive and defensive confrontations between malware and Endpoint Detection and Response (EDR) systems. Participants can choose to participate as either malware or an EDR system. As the malware, the objective is to successfully steal specific target data and transmit it under the surveillance of the EDR. On the other hand, as the EDR, the goal is to effectively monitor the system and detect any malware lurking within.

## Competition Format

### Knockout Match

The knockout match is held every hour, where participants are paired based on their roles (Malware or EDR). The side that meets the victory conditions in the competition will be retained. If the number of Malware and EDR participants is unequal, there may be one-to-many situations. For example, when the number of Malware is less than EDR, one Malware participant will face multiple EDR participants. In this case, as long as the Malware participant wins in one of the matches, they can advance to the next round. When only one participant remains on one side, all remaining participants will advance to the second stage of the tournament and be awarded prizes.

Participants must actively sign up for the knockout match. The version of the malware or EDR used will be the latest version uploaded by the participant. Newly uploaded malware and EDR can only be used in subsequent knockout matches.

### Tournament

In the tournament stage, participants will be paired with opponents with similar score for the competition. The results of each match will be updated based on the ELO point system. The competition will continue until the end of the event, with medals awarded to the top three participants with the highest score.

Participants advancing to the tournament from the knockout match do not need to sign up actively. The version of the malware or EDR used will be the latest version used by the participant at the start of the tournament.

## Execution Environment

- AMI: `ami-02f9041628cc2f753 (64-bit (x86))`
- OS Name: `Microsoft Windows Server 2022 Datacenter`
- OS Version: `10.0.20348 N/A Build 20348`
- OS Manufacturer: `Microsoft Corporation`
- OS Configuration: `Standalone Server`
- OS Build Type: `Multiprocessor Free`
- Hotfix(s): `5 Hotfix(s) Installed., [01]: KB5039889, [02]: KB5012170, [03]: KB5040437, [04]: KB5040571, [05]: KB5034439`

Both EDR and Malware have Administrator privileges.

## EDR (Endpoint Detection and Response)

### Task

Compile all functions into a single Windows EXE executable. The executable should automatically complete all required tasks without user interaction or parameter input. Identify the malicious program in the environment and upload the answer along with the user ID to the specified location.

EDR must reside in the system and cannot terminate after execution.

### Answer Upload API Location

- API: https://x.bombe.digitalplaguedoctors.com/submitEdrAns

This API location can only be accessed within the competition's internal network.

### Answer Format

```json
{
  "answer": "Malicious program filename",
  "secret": "User ID"
}
```

Each answer submission must include a secret.

Answers can only be submitted once.

### Malicious Program Name Format

The malicious program name is: `BOMBE_EDR_FLAG_xxx`, where `xxx` is a combination of 32 digits and letters.

There will be many programs with the above format as filenames in the environment. EDR must find the genuine malicious program among them.

### Prohibitions

- Tampering with or making the target file unreadable.
- Causing a system blue screen (BSOD).
- Destroying the system environment, causing the program to be unable to execute.
- Interrupting network connections.

### Victory Conditions and Scoring Method

- Victory Condition: Find the only malicious program in the environment and submit the answer to the specified API.
- Scoring Method: Score will be updated using the ELO scoring system.

## Malware (Malicious Program)

### Task

Compile all functions into a single Windows EXE executable. The executable should automatically complete all required tasks without user interaction or parameter input. There are three targets to steal in the environment. Steal these targets and upload the answers along with the user ID to the specified location.

### Answer Upload API Location

- API: [https://x.bombe.digitalplaguedoctors.com/submitMalAns](https://x.bombe.digitalplaguedoctors.com/submitMalAns)

This API location can only be accessed within the competition's internal network.

### Answer Format

```json
{
  "answer_1": "Target 1 answer",
  "answer_2": "Target 2 answer",
  "answer_3": "Target 3 answer",
  "secret": "User ID"
}
```

`answer_1`, `answer_2`, `answer_3` can be uploaded separately or together.

Each answer submission must include a secret as user identification.

Each answer can only be submitted once.

### Target Format and Location

- Registry: `answer_1` in `HKCU:\SOFTWARE\BOMBE`
- Encrypted SQLite database: `C:\Users\bombe\AppData\Local\bhrome\Login Data`

```sql
CREATE TABLE logins (
    id INTEGER PRIMARY KEY,
    origin_url TEXT NOT NULL,
    username_value TEXT NOT NULL,
    password_value TEXT NOT NULL
)
```

Decrypt `password_value` with your secret using AES CBC.

`password_value` is a value concatenated by IV (16 bytes) and encrypted password.

`password_value` is in hex format.

- Memory of the specified process: `bsass.exe`

The target name format is: `BOMBE_MAL_FLAG_xxx`, where `xxx` is a combination of 32 digits and letters. There are three answers in total.

### Prohibitions

- Causing a system blue screen (BSOD).
- Destroying the system environment, causing the program to be unable to execute.
- Interrupting network connections.
- Prohibiting actions that close EDR (ATT&CK T1562.001 Impair Defenses: Disable or Modify Tools), including terminating (terminal) and suspending (suspend) EDR.

### Victory Conditions and Scoring Method

- Victory Condition: Find three targets in the environment as answers, submit the answers to the specified API, and not be detected by EDR.
- Scoring Method: Score will be updated using the ELO scoring system.
