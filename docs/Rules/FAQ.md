# FAQ

## Q: What happens if neither Malware nor EDR answers correctly?

In the points match stage, the focus is on updating points, so the ELO scoring system for draws will be used. In the elimination round, the focus is on eliminating unqualified participants. Participants who fail to answer correctly will be eliminated. However, EDR's judgment relies on the presence of malicious behavior by Malware. If Malware does not perform correct answers and shows no malicious behavior, it cannot be used to assess EDR's performance. In this case, if neither Malware nor EDR answers, the Malware participant will be eliminated, and the EDR participant will retain qualification. Below are the scoring and elimination conditions for various situations:

- EDR Answer Status: `O` represents a correct answer, `X` represents an incorrect answer.
- Malware Answer Status: `O` represents a correct answer, `X` represents an incorrect answer.
- Environment Check: `O` represents passing the environment check, `X` represents failing the environment check, possibly due to BSOD.

| EDR Answer Status | Malware Answer Status | Environment Check | Result | Elimination |
| ----------------- | --------------------- | ----------------- | ------ | ----------- |
| O                 | O                     | O                 | EDR    | MAL         |
| X                 | O                     | O                 | MAL    | EDR         |
| O                 | X                     | O                 | EDR    | MAL         |
| O                 | O                     | X                 | CRASH  |             |
| O                 | X                     | X                 | CRASH  |             |
| X                 | O                     | X                 | CRASH  |             |
| X                 | X                     | O                 | DRAW   | MAL         |
| X                 | X                     | X                 | CRASH  |             |

## Q: Can Malware and EDR install kernel drivers?

The competition rules do not restrict participants from installing kernel drivers, but participants need to solve the signature issue of kernel driver installation by themselves. Participants are allowed to use the Bring Your Own Vulnerable Driver (BYOVD) method to install kernel drivers. However, participants need to ensure the stability of the environment. Multiple BSOD situations will be blocked as appropriate.

## Q: Why can't Malware terminate EDR? What happens if EDR is terminated?

In this competition, we focus on the detection capabilities of EDR (Endpoint Detection and Response) and the evasion techniques of malware. In real scenarios, malware entering a system protected by EDR needs to perform privilege escalation to gain the same privileges as EDR. However, to simplify the offensive and defensive processes in the competition, we grant malware the same privileges as EDR directly, making it more challenging for EDR to protect itself from termination.

To maintain fairness and challenge in the competition, we have established an important rule: malware must not terminate EDR. This rule is intended to encourage participants to focus on technical confrontation rather than relying on terminating security defenses to achieve their goals.
