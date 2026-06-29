# Twitter Conversation Monitor

Find 3 Twitter conversations where @patrascu_matei can add genuine value — NOT spam the LumaLine link.

**Sheet ID:** `1KGOOP2PnD3_OX4kr-1IcgDWn7U1N-YT1E1N4AtfYRu4`

## Tools required

Use Composio tool: `TWITTER_SEARCH_RECENT_TWEETS`

## Search for tweets about (search each query)

- "Claude Code" (last 24h, min 5 likes)
- "claude code status bar"
- "kickbacks ai" OR "kickbacks.ai"
- "monetize ai wait time"
- "developer ads" OR "dev marketing"

## Reply philosophy

- Only reply where there's something GENUINE to add
- A reply that mentions LumaLine must earn it — the comment must stand alone as valuable first
- If the thread is about a problem LumaLine solves, lead with the insight, mention LumaLine second
- If someone mentions Kickbacks.ai with concerns about safety, this is a perfect honest reply moment — LumaLine uses the official statusLine API, zero bundle patching
- Never reply with just a link
- Never say "can't block it" — say "chose to see it" if referencing developer consent

## Evaluate each candidate tweet

Pick 3 tweets where a reply would:
1. Add genuine insight or perspective the original commenter didn't have
2. Start a real conversation (not end it)
3. Position @patrascu_matei as a thoughtful builder, not a promoter

## Draft 3 replies. For each include

- The original tweet URL
- The proposed reply text (under 240 chars)
- Why this reply adds value (1 sentence)

## Output

Write 3 rows to Google Sheets Queue tab (append after last row).

**Sheet ID:** `1KGOOP2PnD3_OX4kr-1IcgDWn7U1N-YT1E1N4AtfYRu4`
**Tab:** Queue

Column mapping for each of the 3 rows:
- Column A (ID): REPLY-[YYYYMMDD]-[1/2/3]
- Column B (Type): TWEET_REPLY
- Column C (Platform): Twitter
- Column D (Content): [original tweet URL] followed by two newlines, then [reply text]
- Column E (Media_URL): leave blank
- Column F (Status): DRAFT
- Column G (Approved_At): leave blank
- Column H (Posted_At): leave blank
- Column I (Post_URL): leave blank
- Column J (Notes): why this reply adds value (1 sentence)

## Schedule: 0 12 * * *
