# Submission API

Participant binaries submit answers to a private API that is available only
inside the Battle VM. The API hostname is environment-specific and may change
when the platform is deployed, so **do not hard-code a hostname**.

## Runtime base URL

Before participant programs start, the platform sets the machine environment
variable:

```text
BOMBE_SUBMIT_BASE_URL=<platform-provided base URL>
```

Treat the entire value as an opaque base URL. Do not parse it or construct any
part of it yourself; read it at runtime and append only the endpoint for your
role:

| Role | Endpoint |
| --- | --- |
| Malware | `${BOMBE_SUBMIT_BASE_URL}/submitMalAns` |
| EDR | `${BOMBE_SUBMIT_BASE_URL}/submitEdrAns` |

`BOMBE_SUBMIT_BASE_URL` is routing configuration, not a secret. Your account
`secret` must still be included in every submission payload.

!!! warning "Read the URL at runtime"

    Do not compile an API Gateway URL or any other hostname or path into your
    binary. The injected value is already complete. Remove a trailing slash
    before appending the endpoint.

### C# example

```csharp
using System.Net.Http.Json;

var baseUrl = Environment.GetEnvironmentVariable("BOMBE_SUBMIT_BASE_URL")
    ?? throw new InvalidOperationException("BOMBE_SUBMIT_BASE_URL is not set");

var endpoint = $"{baseUrl.TrimEnd('/')}/submitMalAns";
using var client = new HttpClient();
var response = await client.PostAsJsonAsync(endpoint, new
{
    answer_1 = "BOMBE_MAL_FLAG_...",
    secret = "your secret",
});
response.EnsureSuccessStatusCode();
```

For an EDR, use `/submitEdrAns` and send the EDR payload described in
[Rules for EDR](EDR.md).

### C/C++ example

```cpp
#include <cstdlib>
#include <stdexcept>
#include <string>

const char* value = std::getenv("BOMBE_SUBMIT_BASE_URL");
if (value == nullptr) {
    throw std::runtime_error("BOMBE_SUBMIT_BASE_URL is not set");
}

std::string base_url(value);
while (!base_url.empty() && base_url.back() == '/') {
    base_url.pop_back();
}
std::string endpoint = base_url + "/submitEdrAns";
```

## Submission behavior

- The request body must be a JSON object.
- Every request must include the submitting participant's `secret`.
- An invalid payload or secret does not fill an answer slot; the program may
  correct the request and try again while the Battle is running.
- Each answer slot stores the first well-formed submission made with the correct
  secret. A stored wrong answer cannot be overwritten.
- A Battle may finish early after all Malware and EDR answer slots are filled.

After a Battle, the UI may show these objective verdicts:

| Verdict | Meaning |
| --- | --- |
| `PASSED` | The stored answer is correct. |
| `WRONG_ANSWER` | An answer was stored but is incorrect. |
| `INVALID_PAYLOAD` | The last request could not be accepted as a valid payload. |
| `INVALID_SECRET` | The submitted secret did not match the participant. |
| `NOT_RECEIVED` | No acceptable submission was received before finalization. |

The API is intentionally unreachable from the public internet. In a local test
environment, set `BOMBE_SUBMIT_BASE_URL` to your own compatible test harness;
the production value is injected only into platform Battle VMs.
