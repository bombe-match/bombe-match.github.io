# Participant CLI

The BOMBE participant CLI lets a local coding agent upload a Windows binary,
wait for screening, run Challenges, and inspect Challenge or Tournament history
without controlling your web browser. It uses the same account, rate limits,
screening pipeline, and authorization checks as the competition website.

The CLI never receives AWS credentials and has no direct DynamoDB access.

## Install from the starter repository

The CLI requires Node.js 20 or newer.

```sh
git clone https://github.com/bombe-match/bombe-poc
cd bombe-poc/cli
npm install
npm run build
npm link
```

## Sign in once

Run the login command yourself in an interactive terminal:

```sh
bombe auth login
```

The password is read from a hidden prompt and is not saved. The CLI stores
renewable Cognito tokens in `~/.config/bombe/credentials.json` with user-only
permissions. A coding agent can use the authenticated CLI afterward without
receiving your password.

Use `bombe auth status` to inspect the current login and `bombe auth logout` to
delete locally cached tokens.

## Inject the participant secret

The account secret is readable only with the current player's Cognito token.
Pass it directly into a sample build without writing it into source:

```sh
BOMBE_PARTICIPANT_SECRET="$(bombe account secret --raw)" \
  dotnet publish malv1/malv1.csproj -c Release -r win-x64 \
  --self-contained false -p:PublishSingleFile=true -o artifacts/malv1
```

Do not print the value, paste it into an agent prompt, or commit it. Both sample
projects reject builds that omit `BOMBE_PARTICIPANT_SECRET`. When building for
the public test VM, explicitly pass its documented test value instead.

## Upload and wait for screening

```sh
bombe binary upload --role mal ./malware.exe --wait --json
bombe binary upload --role edr ./edr.exe --wait --json
```

Progress is written to stderr. With `--json`, stdout contains only the final
structured result, including the Binary id, version, screening status, outcome,
and available participant verdicts. A passing screening exits with status `0`;
a rejected binary or platform error uses a non-zero exit status.

Useful follow-up commands:

```sh
bombe binary list --json
bombe binary screening <binary-id> --wait --json
bombe challenge list --json
bombe challenge start <challenge-id> --binary <binary-id> --wait --json
bombe challenge history [challenge-id] --limit 20 --json
bombe challenge result <attempt-id> --json
bombe tournament list --json
bombe tournament activate <id-or-slug> --role mal --binary <binary-id> --json
bombe tournament history [id-or-slug] --role mal --result win --limit 20 --json
```

## Inspect Challenge results

`challenge start --wait --json` returns the terminal `ChallengeAttempt` and its
owner-visible `BattleParticipantView`. The JSON includes whether the Challenge
was cleared, the Battle outcome, objective feedback, submission count, opponent
metadata, and available verdicts.

A completed attempt that does not clear the Challenge exits with status `2`.
This is a player result, not by itself a platform failure. Read the returned
`attempt.status`, `attempt.completed`, `attempt.outcome`, and verdicts before
deciding what to change.

Results remain available after the command exits:

```sh
# Newest attempts across all Challenges
bombe challenge history --limit 20 --json

# Attempts for one Challenge
bombe challenge history <challenge-id> --limit 20 --json

# Full objective result for one attempt
bombe challenge result <attempt-id> --json
```

## Inspect Tournament battle history

Tournament history is scoped to the signed-in player and includes completed
battles from older or superseded binary versions:

```sh
bombe tournament history --limit 20 --json
bombe tournament history <id-or-slug> --json
bombe tournament history <id-or-slug> --role edr --result loss --limit 50 --json
```

`--role` accepts `mal` or `edr`. `--result` accepts `win`, `loss`, `draw`, or
`crash`. Omit filters to retrieve both roles and all results. Each row includes
the player's and opponent's binary versions, outcome, objective verdicts,
submission count, and completion time.

Challenge and Tournament history read participant-owned `ChallengeAttempt` and
`BattleParticipantView` records. They do not grant access to private Battle,
Execution, EC2, S3, or cleanup state. Queued and running Tournament operations
may not appear until their participant history projection is complete.

## Agent workflow

An agent should follow this loop:

1. Read the current rules and [Submission API](Rules/Submission-API.md).
2. Modify and build one unattended Windows x64 executable.
3. Upload it with `bombe binary upload --wait --json`.
4. Check the command exit status and parse the final JSON.
5. Run a Challenge and inspect it with `challenge result` when appropriate.
6. Use `tournament history` to compare completed results across binary versions.
7. Correct the implementation based on the available participant verdicts.

Do not give an agent your account password or paste Cognito tokens into a
prompt. Complete `bombe auth login` yourself and let the agent invoke only the
authenticated commands. The participant secret may pass directly from the CLI
to the build environment, but should not be printed or saved in source.

!!! note "Two different API surfaces"

    The CLI uploads through the public participant API. A Malware or EDR
    executable submits Battle answers through the private URL provided in
    `BOMBE_SUBMIT_BASE_URL`. Do not use either URL in place of the other.
