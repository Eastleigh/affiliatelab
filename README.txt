AffiliateLab — Kalodata CSV Import Upgrade

WHAT THIS ADDS
- New sidebar item: Import CSV
- Upload a Kalodata CSV in the browser
- Automatic header matching for common column names
- Manual column mapping dropdowns when Kalodata headers differ
- 5-row preview before import
- Bulk import and scoring (up to 1,500 rows per batch)
- Duplicate-safe upsert by user + Product URL
- Handles $, %, commas, K/M/B number abbreviations
- Adds source=kalodata_csv to imported products
- Immediately ranks imported products under Top Opportunities

HOW TO DEPLOY
1. In GitHub open Eastleigh/affiliatelab.
2. Open src/server.js.
3. Replace it with the server.js in this package (or upload and overwrite it).
4. Commit the change to main.
5. Coolify should detect the commit. If it does not auto-deploy, click Deploy manually.
6. After deployment, sign in to AffiliateLab and click Import CSV in the sidebar.

NO NEW NPM PACKAGES OR ENVIRONMENT VARIABLES ARE REQUIRED.

IMPORTANT
The importer intentionally uses flexible column mapping instead of depending on a fixed Kalodata export schema. This makes it usable if Kalodata renames or rearranges CSV columns.
