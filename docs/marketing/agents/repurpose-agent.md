# Content Repurpose Agent

Take posted Twitter threads from the last 7 days and create platform-native versions for Reddit, LinkedIn, and Instagram.

**Sheet ID:** `1KGOOP2PnD3_OX4kr-1IcgDWn7U1N-YT1E1N4AtfYRu4`

## Messaging rules (embed in all repurposed content)

- Developers CHOOSE to see LumaLine ads — they installed it voluntarily for passive income
- Never say "can't block it" — say "chose to see it"
- Tone dev track: one dev to another, raw, honest, no sales language
- Tone advertiser track: insight-led, professional, no buzzwords

## Process

1. Read Queue tab, find rows where column B (Type) = THREAD, column F (Status) = POSTED, and column H (Posted_At) is within the last 7 days
2. For each qualifying thread, generate 3 adapted versions (Reddit, LinkedIn, Instagram carousel)
3. Write each version as a new DRAFT row in the Queue tab

## Reddit version

- Rewrite for Reddit's native culture — no "thread" structure, just a post
- Remove Twitter-isms (no "1/", no "→", no quote-tweet formatting)
- Lead with the insight or story, not the product name
- Add context a Twitter thread assumes the reader already has
- Target the subreddit that fits best: r/ClaudeAI, r/programming, or r/SideProject
- Write full title (first line) + body (remainder)
- Match subreddit rules: r/SideProject requires "I built X" format; no direct promo links in body

## LinkedIn version

- More professional tone, same core insight
- Reframe for marketing/growth audience where relevant (advertisers, dev tool founders)
- 200-250 words max
- First line must work as a standalone hook that stops scrolling
- Optional: end with a genuine question to invite comments
- Max 3 relevant hashtags

## Instagram carousel (text only — Canva will design it)

- Extract 5-7 key points from the thread
- Format as slides:
  - Slide 1: hook (must work in first 3 seconds)
  - Slides 2-6: one key point each (max 15 words per slide)
  - Last slide: CTA — "Install LumaLine free: luma-line.lovable.app"
- Output as a numbered list, one slide per line
- Max 15 words per slide — enforce this strictly

## Output

Write new rows to Google Sheets Queue tab (append after last row) for each adapted version.

**Sheet ID:** `1KGOOP2PnD3_OX4kr-1IcgDWn7U1N-YT1E1N4AtfYRu4`
**Tab:** Queue

Column mapping for each new row:
- Column A (ID): REPURPOSE-[original row ID]-[REDDIT/LINKEDIN/INSTAGRAM]
- Column B (Type): REDDIT / LINKEDIN / INSTAGRAM
- Column C (Platform): r/ClaudeAI or r/programming or r/SideProject (Reddit), LinkedIn, Instagram
- Column D (Content): full adapted content
- Column E (Media_URL): leave blank
- Column F (Status): DRAFT
- Column G (Approved_At): leave blank
- Column H (Posted_At): leave blank
- Column I (Post_URL): leave blank
- Column J (Notes): "Repurposed from [original Post_URL from column I of the source row]"

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

## Run every Monday at 9am

## Schedule: 0 9 * * 1
