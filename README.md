# cloudflare-attack-monitor

> Agent skills for finding spam traffic in Cloudflare logs and blocking it with WAF rules.

---

## Skills

| Skill | Path | What it does |
|---|---|---|
| **cloudflare-404-probe** | [`skills/cloudflare-404-probe/SKILL.md`](skills/cloudflare-404-probe/SKILL.md) | Scans 404s for scanner probes and deploys a sensitive-file managed challenge rule to each zone. |

### cloudflare-404-probe

Scanners constantly request sensitive paths like `.env`, `credentials.json`, `phpinfo.php`, and `/.git/`. These requests show up as 404s. This skill:

1. Pulls 404 responses across every Cloudflare zone via GraphQL.
2. Classifies the paths that look like probes.
3. Checks for false positives, such as real files or catch-all pages that return 200.
4. Builds one wildcard-based custom WAF rule that issues a managed challenge.
5. Adds it to each zone after you approve it.

**Targets:** credential and key files, config and secrets (`*.toml`, `*.yml`, `*.tfstate`), dotfiles and VCS folders (`/.git/`, `/.aws/`, `/.ssh/`), and debug probes (`phpinfo`, `/_profiler/`, `/actuator`).

**Safeguards:**
- Shows the proposed rule and waits for approval before changing anything.
- Reads each zone's existing custom ruleset first, and offers to extend an existing rule instead of adding a new one.
- Checks expression length (4,096-character cap) and plan rule limits before writing.
- Reports results per zone.

## Cloudflare MCP permissions

Create a **user profile API token** (My Profile → API Tokens), not an account-owned token, and grant it:

- Zone Observability: Read
- Zone WAF: Edit
- Zone WAF: Read
- Zone: Read
- Logs: Read
- Analytics: Read

## Install

Install the skill with the [Skills CLI](https://skills.sh):

```
npx skills add https://github.com/rishabkapadia/cloudflare-attack-monitor-skills \
  --skill cloudflare-404-probe
```

## Usage

Ask your agent: 
```
scan for 404 responses on cloudflare
```

## License

See [LICENSE](LICENSE).
