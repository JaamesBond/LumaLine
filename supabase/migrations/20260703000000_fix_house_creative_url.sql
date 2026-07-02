-- lumaline — fix the house self-promo creative's destination URL.
-- The seeded house creative pointed at the raw Lovable marketing site
-- (https://luma-line.lovable.app); it must point at the branded domain
-- (https://lumaline.dev) — that is where the tokenized click (c.lumaline.dev/c/<token>)
-- 302-redirects when a developer clicks the sponsored line. Data-only, idempotent:
-- scoped to the known house creative id and conditioned on the old value.
update public.creatives
   set dest_url = 'https://lumaline.dev'
 where id = '5e470000-0000-4000-8000-00000000e001'
   and dest_url = 'https://luma-line.lovable.app';
