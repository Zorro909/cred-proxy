# Agent Integration

cred-proxy ships with ready-made configuration files that teach AI agents how to work with the proxy. This page explains what they are and how to install them.

## What's Included

| File | Purpose |
|------|---------|
| `agent-skill/SKILL.md` | Claude Code skill — explains the proxy, credential rules, and how to discover/request credentials. |
| `agent-skill/API-REFERENCE.md` | Detailed `/__auth/*` endpoint documentation with request/response schemas. Referenced from SKILL.md. |
| `agent-claude-md.md` | A short CLAUDE.md snippet (~6 lines) providing the essential rules as always-loaded context. |

## Setup

Install **both** the skill and the CLAUDE.md snippet. They serve different purposes:

- The **CLAUDE.md snippet** is always loaded into the agent's context window, so the core rules are always present.
- The **skill** provides deeper reference (credential discovery API, request flow, full API docs) that the agent can consult when needed.

### Step 1: Install the Skill

Copy the `agent-skill/` directory into your agent project's `.claude/skills/` as `cred-proxy/`:

```bash
cp -r agent-skill /path/to/agent-project/.claude/skills/cred-proxy
```

The resulting layout should be:

```
agent-project/
  .claude/
    skills/
      cred-proxy/
        SKILL.md
        API-REFERENCE.md
```

### Step 2: Add the CLAUDE.md Snippet

Copy the contents of `agent-claude-md.md` into your project's `CLAUDE.md` or a file in `.claude/rules/`:

```bash
# Append to existing CLAUDE.md
cat agent-claude-md.md >> /path/to/agent-project/CLAUDE.md

# Or create a rules file
cp agent-claude-md.md /path/to/agent-project/.claude/rules/cred-proxy.md
```

## Verifying It Works

After installing, you can verify the agent has the context by asking it:

> "How do you handle authentication for HTTP requests?"

It should mention cred-proxy, placeholder credentials, and the `/__auth/*` API.
