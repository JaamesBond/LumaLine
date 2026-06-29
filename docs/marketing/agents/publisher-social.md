# Social Publisher Agent

Post approved content from Google Sheets Queue tab to Twitter, Reddit, and LinkedIn.

**Sheet ID:** `1KGOOP2PnD3_OX4kr-1IcgDWn7U1N-YT1E1N4AtfYRu4`

## Tools required

Use Composio tools:
- `TWITTER_CREATION_OF_A_POST` — for Type=TWEET
- `TWITTER_CREATION_OF_A_POST` with reply_to parameter — for Type=TWEET_REPLY
- `REDDIT_SUBMIT_POST` — for Type=REDDIT
- `LINKEDIN_CREATE_POST` — for Type=LINKEDIN

## Process

1. Read all rows from Queue tab where column F (Status) = APPROVED
2. For each row, check column B (Type):
   - **TWEET** → post via `TWITTER_CREATION_OF_A_POST` with content from column D
   - **TWEET_REPLY** → extract parent tweet URL from first line of column D (Content), post as reply via `TWITTER_CREATION_OF_A_POST` with reply_to set to the parent tweet ID
   - **REDDIT** → extract subreddit from column C (Platform), post via `REDDIT_SUBMIT_POST` with title = first line of column D and body = everything after first `\n`
   - **LINKEDIN** → post via `LINKEDIN_CREATE_POST` with content from column D
3. After a successful post, update the row in the Queue tab:
   - Column F (Status): POSTED
   - Column H (Posted_At): current timestamp in ISO 8601 format
   - Column I (Post_URL): URL returned by the platform API
4. If a post fails, update column J (Notes) with the error message and leave column F (Status) as APPROVED — do NOT retry automatically

## Critical rules

- NEVER post a row with Status != APPROVED — always check column F before posting
- NEVER post a row that already has Status = POSTED
- For Reddit: title = first line of Content (column D), body = everything after the first `\n`
- For Twitter threads (Type=THREAD): post first tweet, then post each subsequent paragraph as a reply to the previous tweet's ID
- Do not modify DRAFT or REJECTED rows in any way
- Process rows in order (lowest row number first)

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

## Run at 10am and 6pm daily (two windows to pick up morning and afternoon approvals)

## Schedule: 0 10,18 * * *
