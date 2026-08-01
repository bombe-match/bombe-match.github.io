# FAQ

## Q: What happens if neither Malware nor EDR answers correctly?

Each Battle evaluates four objectives: three Malware targets and one EDR
detection target. The outcome is determined in this order:

1. If the participant launch or runtime crashes the Battle environment, the
   result is `CRASH`.
2. If the EDR detection objective passes, EDR wins.
3. Otherwise, if all three Malware objectives pass, Malware wins.
4. Otherwise, the result is a draw.

This means a correct EDR detection wins even if Malware also retrieves all
three targets. If neither side completes its victory condition, the Battle is a
draw. Tournament scoring uses win rate rather than ELO.

## Q: Where should my binary submit answers?

Read `BOMBE_SUBMIT_BASE_URL` from the environment at runtime and append the
endpoint for your role. There is no stable hostname to compile into a binary.
See [Submission API](Submission-API.md).

## Q: Can I retry a submission?

Invalid JSON, missing fields, and an invalid `secret` can be corrected and
retried while the Battle is running. Once an answer slot accepts a well-formed
request with the correct secret, that slot is fixed, even if the answer is
wrong. Malware has three independent answer slots; EDR has one.

## Q: Can Malware and EDR install kernel drivers?

The competition rules do not restrict participants from installing kernel drivers, but participants need to solve the signature issue of kernel driver installation by themselves. Participants are allowed to use the Bring Your Own Vulnerable Driver (BYOVD) method to install kernel drivers. However, participants need to ensure the stability of the environment. Multiple BSOD situations will be blocked as appropriate.

## Q: Why can't Malware terminate EDR? What happens if EDR is terminated?

In this competition, we focus on the detection capabilities of EDR (Endpoint Detection and Response) and the evasion techniques of malware. In real scenarios, malware entering a system protected by EDR needs to perform privilege escalation to gain the same privileges as EDR. However, to simplify the offensive and defensive processes in the competition, we grant malware the same privileges as EDR directly, making it more challenging for EDR to protect itself from termination.

To maintain fairness and challenge in the competition, we have established an important rule: malware must not terminate EDR. This rule is intended to encourage participants to focus on technical confrontation rather than relying on terminating security defenses to achieve their goals.
