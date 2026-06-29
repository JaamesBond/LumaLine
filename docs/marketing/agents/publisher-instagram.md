# Instagram Publisher Agent

Post approved video content to Instagram Reels.

**Sheet ID:** `1KGOOP2PnD3_OX4kr-1IcgDWn7U1N-YT1E1N4AtfYRu4`

## Tools required

Use Composio tool: `INSTAGRAM_CREATE_MEDIA`

## Process

1. Read Queue tab rows where column B (Type) = INSTAGRAM and column F (Status) = APPROVED
2. For each row:
   - Column E (Media_URL) must contain the edited video URL (Higgsfield output) — skip any row where Media_URL is blank and add a note to column J (Notes): "Missing Media_URL — skipped"
   - Post via `INSTAGRAM_CREATE_MEDIA` with the video URL from column E and caption from column D (Content)
3. After successful post, update the row:
   - Column F (Status): POSTED
   - Column H (Posted_At): current timestamp in ISO 8601 format
   - Column I (Post_URL): Instagram post URL returned by the API
4. If post fails, update column J (Notes) with the error and leave Status as APPROVED — do NOT retry

## Caption format rules

- First 125 characters must be the hook (shown before "more" cutoff on Instagram) — verify this before posting
- Maximum 3 hashtags per post
- No generic hashtags — use specific ones only: #ClaudeCode, #AITools, #BuildInPublic, #IndieHacker, #DevTools
- Do not add hashtags if the content already has 3 or more

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

## Run at 11am daily

## Schedule: 0 11 * * *
