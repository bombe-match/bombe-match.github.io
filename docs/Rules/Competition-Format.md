# Competition Format

The platform has two player-facing formats: Challenge and Tournament. Every
uploaded binary must pass screening before it can be used in either format.

## Screening

Uploading a binary automatically starts a short legality and compatibility
test against a platform sample bot. Screening checks that the executable can
run, use the submission path, and avoid an obvious VM crash. It is not a score
and does not guarantee competitive performance.

A passing version becomes **Ready**. A rejected version remains in upload
history with its screening result and cannot be selected for a Challenge or
Tournament.

## Challenge

Challenge is a persistent practice track against official platform binaries.
Each challenge fixes the participant role and opponent bot, often introducing a
specific detection or evasion technique. Select any Ready binary for that role
and start the Battle manually. A challenge can be attempted multiple times with
different versions; progress and attempt history are retained.

## Tournament

A Tournament is a time-bounded event. Upcoming published events are visible,
but active binaries can be set only between the event's begin and end times.
During that window, a participant explicitly selects one Ready binary per role
as active and may switch versions while continuing to improve it.

The platform builds the complete matrix of every active Malware binary against
every active EDR binary. A participant's own Malware and EDR may face each
other. Changing an active version schedules the missing matrix Battles for that
new version; the current matrix shows the latest active combination for each
participant pair.

The role leaderboard score is the win rate over completed Battles:

```text
win rate = wins / completed Battles * 100%
```

Draws are completed Battles but are not wins. Crashed or system-error Battles
are reported separately. If a participant enters both roles, the overall score
is the average of their Malware and EDR win rates.

At the event end time, active binaries can no longer be changed. Already queued
or running Battles are allowed to finish, after which the final matrix and
leaderboards remain available as the event archive.
