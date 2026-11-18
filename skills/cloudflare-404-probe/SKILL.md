---
name: cloudflare-404-probe
description: Scan 404 responses across all Cloudflare zones for scanner probes (credential files, .env, phpinfo, config and dotfiles), build a wildcard-based custom WAF rule that issues a managed challenge, and deploy it to each zone after approval. Use when asked to check 404 logs, find probe paths, or create a sensitive-file managed challenge rule.
---

# Cloudflare 404 Probe

Find scanner probes that hit 404s, turn them into one custom managed challenge rule, and apply it to every zone. This is separate from `cloudflare-spam-list-refresh`, which manages IP lists.

## Rules of the workflow

- Show the proposed rule and get explicit approval before creating anything.
- Never add a rule to a zone without first reading that zone's existing custom ruleset.
- Always show the zone's existing custom rules and ask the user whether to create a new rule or update one of them. Never silently add a sixth rule when an existing one could be extended.
- Report the result per zone. Don't claim success for a zone that errored.

## Step 1: Zones and plan

```
GET /zones?per_page=50
```

Record `name`, `id`, and `plan.legacy_id`. Free zones show `plan.legacy_id: "free"`.

Plan limits that change the design:

| Plan | Regex (`matches`) | Custom rules per zone |
|---|---|---|
| Free | No | 5 |
| Pro | No | 20 |
| Business | Yes | 100 |
| Enterprise | Yes | 1000 |

On Free, use `wildcard` (case-insensitive) or `contains`/`ends_with` with `lower()`. Do not use `matches`.

Expression length limit: every rule expression is capped at **4,096 characters**, on all plans. Appending to an existing rule can exceed this quickly. Before any create or PATCH, measure the final expression length in JS (`expr.length`). If it's over 4,096, don't send it. Create a separate rule instead, or trim patterns that the zone's existing rules already cover.

## Step 2: Pull 404s with GraphQL

One aliased query covers every zone. Use a 24-hour window unless the user asks for another.

```js
const blocks = zones.map((z, i) => `z${i}: zones(filter:{zoneTag:"${z.id}"}) {
  httpRequestsAdaptiveGroups(limit:5000,
    filter:{datetime_geq:"${start}", datetime_leq:"${end}", edgeResponseStatus:404},
    orderBy:[count_DESC]) { count dimensions { clientRequestPath clientIP } } }`).join("\n");
const query = `query { viewer { accounts(filter:{accountTag:"${accountId}"}) { ${blocks} } } }`;
await cloudflare.request({ method: "POST", path: "/graphql", body: { query } });
```

Gotchas:
- Each zone alias returns an **array**. Read `acct[`z${i}`][0]?.httpRequestsAdaptiveGroups ?? []`.
- Large results are truncated in the tool output. Aggregate inside JS and return summaries, not raw rows.
- JavaScript does not support inline `(?i)`. Pass the `"i"` flag to `new RegExp(...)`, and escape backslashes in a string, not a literal.
- Free plan fields: `clientRequestPath`, `clientIP`, `edgeResponseStatus`, `securityAction`, `userAgent`, `clientRequestHTTPHost`, `clientCountryName`. `botScore` and `clientAsn` are not available.

## Step 3: Classify

Match paths against a candidate regex, then count per zone and per unique path. Look for:
- credential and key files (`*service-account*`, `*credentials*`, `*key.json`)
- config and secrets (`.env`, `*.toml`, `*.json`, `*.yml`, `*.ini`, `*.conf`, `*.tfstate`)
- dotfiles and VCS (`/.git/`, `/.svn/`, `/.ssh/`, `/.aws/`, `/.docker/`, `/.htaccess`)
- debug and framework probes (`phpinfo`, `/_profiler/`, `/_environment`, `/actuator`)

Ignore `/cdn-cgi/` paths (normal Cloudflare behavior).

Do not classify by user agent. Scanners spoof Googlebot, ClaudeBot, and browsers.

## Step 4: Check for false positives

Probe the same patterns in **2xx/3xx** responses. This catches two problems:
- A real file the site serves (for example, a legitimate `*.json` used by the frontend).
- A soft 404: a catch-all that returns 200 for any path.

Query with `edgeResponseStatus_lt: 400` over the same window. For any 200 hit, fetch the URL. If it returns the homepage, it's a catch-all. Report it. The rule still challenges the path, but the site should return a real 404.

Before challenging an extension broadly (especially `*.json`, `*.yml`, `*.conf`, `*.log`), ask whether the site legitimately serves that file type.

## Step 5: Draft the rule

Use `wildcard` for each pattern and join with `or`. Lowercase is not needed because `wildcard` is case-insensitive.

```
(http.request.uri.path wildcard "*.toml") or (http.request.uri.path wildcard "*.json") or ...
```

Patterns used in the first deployment (adjust per request):

```
*.toml *.json *.env */.env* *.yaml *.yml *.ini *.conf *.bak *.sql *.log
*.tfstate *.tfvars *.pem *.htpasswd */.htaccess */.git/* */.svn/* */.ssh/*
*/.aws/* */.docker/* *phpinfo* */_profiler/* */_environment* */actuator*
*service-account* *serviceaccount* *service_account* *adminsdk* *credentials*
```

Present to the user:
- rule name, action (`managed_challenge`), phase (`http_request_firewall_custom`)
- the full expression
- trade-offs (broad extensions, substring matches like `*credentials*`)
- which probe paths were not covered (for example extensionless `/backup`, `/old`)

Wait for approval.

## Step 6: Read each zone's custom ruleset and list existing rules

```
GET /zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint
```

Record `result.id` (the ruleset ID), the existing rule count, and for every rule: `id`, `description`, `action`, `enabled`, and `expression`. Confirm the count is below the plan limit before adding.

Then present the existing rules to the user before changing anything. One table per zone (or one table with a zone column when the rules are identical across zones):

| # | Rule ID | Description | Action | Enabled | Expression (truncated) |
|---|---|---|---|---|---|

Follow with a recommendation and an explicit question:

- If an existing rule already targets the same class of paths (for example another sensitive-file block), recommend **updating that rule** by appending the new patterns to its expression.
- Otherwise recommend **creating a new rule**.
- If the zone is at the plan limit, updating is the only option unless the user wants to remove a rule.

Ask: "Create a new rule, or update one of the existing rules above? If updating, which rule ID?" Wait for the answer per zone. Do not assume the same choice applies to every zone; ask once and confirm it applies to all, or collect per-zone choices.

## Step 7: Create or update the rule

**Create** (only if the user chose a new rule):

```
POST /zones/{zone_id}/rulesets/{ruleset_id}/rules
{ "action": "managed_challenge", "expression": "<expression>", "description": "<short description>", "enabled": true }
```

**Update** (if the user chose an existing rule):

```
PATCH /zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}
{ "expression": "<existing expression> or <new patterns>", "description": "<updated description>" }
```

When updating:
- Preserve the existing expression verbatim and append with ` or `, wrapping the new patterns in parentheses: `(<existing>) or (http.request.uri.path wildcard "*.env") or ...`.
- Do not change the rule's `action` unless the user asks. If the existing action is not `managed_challenge`, point that out and confirm before changing it.
- Keep the existing `description` unless the user wants it changed; if you extend it, keep it short and note the change.
- Show the exact before/after expression and get approval before the PATCH.

Use the **ruleset ID from step 6**, not the zone ID. Don't create a new ruleset.

Don't add the rule twice. Before posting, check whether a rule with the same description already exists in the entrypoint response. Skip zones where it's already present. For updates, check whether the new patterns are already in the existing expression and skip if so.

## Step 8: Verify

- Re-read the entrypoint and confirm the rule is present (new rule, or updated expression on the chosen rule) and `enabled: true`, with the expected count.
- Optionally, request a challenged path on each zone and confirm the challenge response. Non-browser clients get HTTP 403 with a `cf-mitigated: challenge` header:
  `curl -sI https://<zone>/credentials.json`
  Use a known-safe path to confirm normal pages still return 200.

## Report

One table: zone, action taken (created / updated rule `<id>`), rule count after, status (ok or error with message). List the trade-offs and any soft-404 zones.

## Gotchas

| Symptom | Cause | Fix |
|---|---|---|
| `Invalid regular expression: ... Invalid group` | `(?i)` in a JS regex | Use `new RegExp(str, "i")` |
| `Cannot read properties of undefined (reading 'forEach')` | Zone alias is an array | Index `[0]` |
| Rows missing from output | Tool output truncated | Aggregate in JS, return summaries |
| `matches` operator rejected | Free plan has no regex | Use `wildcard` |
| Rule count exceeded | Free limit is 5 per zone | Update an existing rule (step 6) or upgrade |
| PATCH rejected / expression invalid | Appended patterns not parenthesized | Wrap each new pattern in `(...)` and join with `or` |
| Expression too long (over 4,096 chars) | Appending many patterns to an existing rule | Measure `expr.length` before sending. Create a separate rule instead of appending |
| Probe returns 200 | Catch-all page | Fix the site's 404 handling |

## Reference

- Custom rules overview and plan limits: https://developers.cloudflare.com/waf/custom-rules/
- Rules language operators (`wildcard`, `matches`): https://developers.cloudflare.com/ruleset-engine/rules-language/operators/
