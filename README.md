# AffiliateLab SaaS — Authenticated MVP

This is the production-oriented conversion of the AffiliateLab GUI prototype.

## Included

- Creator signup and login
- HTTP-only signed auth cookie
- CSRF protection for product writes
- Login/signup rate limiting
- Per-user product privacy
- PostgreSQL persistence
- Duplicate-safe upsert per user + product URL
- Server-side Opportunity Score
- Product score history
- Dashboard
- Product intake
- Product list/detail pages
- Top Opportunities
- Avatar module shell
- Creative Studio shell
- Optional n8n webhook after each product save
- Helmet security headers
- Parameterized PostgreSQL queries
- Dockerfile for Coolify

## Uses your existing AffiliateLab PostgreSQL database

On startup it adds:
- `users`
- `products.user_id`
- product metadata fields needed by the GUI
- a per-user unique index on `(user_id, product_url)`

Your old test products remain with `user_id = NULL` and are not shown to logged-in users.

## Deploy on the RackNerd/Coolify server you already configured

1. Upload this folder to a GitHub repository.
2. In Coolify: My first project → production → New resource → Application.
3. Connect the repository.
4. Use the included Dockerfile.
5. Internal application port: `3000`.
6. Attach the app to the predefined Coolify network so it can reach your private PostgreSQL resource.
7. Add a domain. Suggested temporary choice: `https://app.eastleah.com`.
8. In Namecheap add an A record:
   - Host: `app`
   - Value: `192.210.152.97`
9. Set environment variables:
   - `DATABASE_URL=postgresql://affiliatelab:YOUR_PASSWORD@YOUR_INTERNAL_POSTGRES_HOST:5432/affiliatelab`
   - `JWT_SECRET=` generate a strong 32+ byte secret
   - `APP_URL=https://app.eastleah.com`
   - `PGSSL=false`
   - `N8N_PRODUCT_WEBHOOK=` leave blank until the webhook exists
10. Deploy.

Generate JWT secret on the VPS:
`openssl rand -hex 32`

## n8n integration

When we build the product intake webhook, set:
`N8N_PRODUCT_WEBHOOK=https://n8n.eastleah.com/webhook/YOUR_PATH`

Every product save will POST:
- event = `product.saved`
- user_id
- product_id
- normalized product fields
- AffiliateLab score and recommendation

## Kalodata

V1 accepts manual Kalodata metrics. This is intentional. Before commercial launch, use a permitted API/export/CSV path rather than depending on unauthorized scraping of another paid SaaS.

## Next modules

1. Avatar Identity Profile
2. AI hooks/scripts
3. Seedance / Higgsfield / HeyGen connectors
4. TikTok performance tracking
5. SCALE / ITERATE / KILL engine
6. Stripe Creator Pro billing at $49/month
7. Usage/video credits
