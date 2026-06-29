# GitHub Milestone Monitor

Check LumaLine's GitHub stars and auto-tweet if a milestone is hit.

**Sheet ID:** `1KGOOP2PnD3_OX4kr-1IcgDWn7U1N-YT1E1N4AtfYRu4`

## Tools required

Use Composio tool: `TWITTER_CREATION_OF_A_POST`

## Process

1. Fetch current stars:
   - GET `https://api.github.com/repos/JaamesBond/LumaLine`
   - Field: `stargazers_count`

2. Read LAST_STAR_COUNT from Config tab:
   - Sheet ID: `1KGOOP2PnD3_OX4kr-1IcgDWn7U1N-YT1E1N4AtfYRu4`
   - Tab: Config
   - Find the row where column A = "LAST_STAR_COUNT", read value from column B

3. Check if current count crossed any milestone since last check:
   - Milestones: 50, 100, 250, 500, 1000, 2500, 5000, 10000
   - A milestone is crossed if: LAST_STAR_COUNT < milestone AND current_count >= milestone

4. If a milestone was crossed:
   - Compose a milestone tweet (see template below)
   - Post immediately via `TWITTER_CREATION_OF_A_POST` — no approval needed
   - Update LAST_STAR_COUNT in Config tab column B to current_count
   - Write 1 row to Queue tab for the record:
     - Column A (ID): MILESTONE-[YYYYMMDD]-[milestone_number]
     - Column B (Type): TWEET
     - Column C (Platform): Twitter
     - Column D (Content): the tweet text that was posted
     - Column F (Status): POSTED
     - Column H (Posted_At): current timestamp
     - Column J (Notes): "Auto-posted milestone tweet — [milestone] stars"

5. If no milestone was crossed:
   - Update LAST_STAR_COUNT in Config tab column B to current_count silently
   - Do not post anything

## Milestone tweet template

Vary the wording — never post the same copy twice. Always include:
- The star count as a number
- Something honest about where the project is right now (what's built, what isn't)
- A link to the repo (github.com/JaamesBond/LumaLine) OR luma-line.lovable.app

Tone: one developer talking to other developers. Honest, not hyping. Show where things actually stand.

**Example for 100 stars:**
```
100 people starred LumaLine on GitHub.

We're still in beta — the feed runs, the signed line appears, payouts aren't live yet.

But 100 people think this is worth watching.

If you're one of them: github.com/JaamesBond/LumaLine
```

**Example for 500 stars:**
```
500 stars.

Built this in [X] weeks. Zero dependencies. Zero bundle patching. Just a signed status line that pays developers for their Claude Code wait-time.

Founding publisher waitlist: luma-line.lovable.app
```

Adapt the tone and honesty for the actual milestone — what is genuinely true about the project at that moment?

## Queue tab column reference

- A = ID
- B = Type
- C = Platform
- D = Content
- E = Media_URL
- F = Status
- G = Approved_At
- H = Posted_At
- I = Post_URL
- J = Notes

## Run every 6 hours

## Schedule: 0 */6 * * *
