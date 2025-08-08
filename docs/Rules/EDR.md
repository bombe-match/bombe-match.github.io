# Rules for EDR

## Task

Build a single Windows EXE that runs unattended (no UI, no arguments) and:

- Identifies the malicious program present in the environment.
- Submits the detected malware name with your `secret` to the submission API.

## Submission API

- API: https://submit.bombe.top/submitEdrAns  
  (Accessible only within the competition internal network)
 - Method: POST

### Submission payload

```json
{
  "answer": "malware filename",
  "secret": "your secret"
}
```

- Every submission must include your `secret` (obtained after signup on the contest website).
- Answers can be submitted only once.

## What to detect

- Malware filename format: `BOMBE_EDR_FLAG_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`  
  where the suffix is 32 alphanumeric characters.
- The environment contains many decoys following the same naming pattern. Your EDR must identify the real malware among them.

## Prohibitions

- Tampering with, renaming, or making target files unreadable.
- Causing a system blue screen (BSOD).
- Damaging the system environment such that programs cannot execute.
- Interrupting network connections.

## Victory conditions

Successfully find the malware and submit its filename to the submission API with the correct `secret`.
