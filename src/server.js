import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const DATABASE_URL = process.env.DATABASE_URL;
const isProd = process.env.NODE_ENV === "production";

if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be at least 32 characters.");
if (!DATABASE_URL) throw new Error("DATABASE_URL is required.");

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 10,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : false,
});
pool.on("error", err => console.error("PostgreSQL pool error:", err.message));

app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
    },
  },
}));
app.use(express.urlencoded({extended:false,limit:"100kb"}));
app.use(express.json({limit:"5mb"}));
app.use(cookieParser());
app.use("/static", express.static(path.join(__dirname,"..","public"), {maxAge:isProd?"1d":0}));
app.use(["/login","/signup"], rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:"draft-8",legacyHeaders:false}));

const esc=(v="")=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const money=v=>Number(v||0).toLocaleString("en-US",{style:"currency",currency:"USD"});
const num=v=>Number(v||0).toLocaleString("en-US");

function sessionFrom(req){
  const token=req.cookies.affiliatelab_session;
  if(!token) return null;
  try{return jwt.verify(token,JWT_SECRET,{issuer:"affiliatelab"});}catch{return null;}
}
function setSession(res,user){
  const csrf=crypto.randomBytes(24).toString("hex");
  const token=jwt.sign({sub:user.id,email:user.email,name:user.name,csrf},JWT_SECRET,{expiresIn:"7d",issuer:"affiliatelab"});
  res.cookie("affiliatelab_session",token,{httpOnly:true,secure:isProd,sameSite:"lax",maxAge:7*24*3600*1000,path:"/"});
}
async function requireAuth(req,res,next){
  const s=sessionFrom(req);
  if(!s)return res.redirect("/login");
  try{
    const q=await pool.query("SELECT id,name,email,plan,role,status FROM users WHERE id=$1",[+s.sub]);
    const u=q.rows[0];
    if(!u||u.status==="disabled"){res.clearCookie("affiliatelab_session",{path:"/"});return res.redirect("/login");}
    req.user={...s,...u,sub:u.id};
    next();
  }catch(e){next(e);}
}
function requireCsrf(req,res,next){const s=sessionFrom(req),t=req.body?._csrf||req.get("x-csrf-token");if(!s||!t||t!==s.csrf)return res.status(403).send("Invalid CSRF token");req.user={...(req.user||{}),...s};next();}
async function requireAdmin(req,res,next){
  try{
    if(!req.user)return res.redirect("/login");
    const q=await pool.query("SELECT role,status FROM users WHERE id=$1",[+req.user.sub]);
    const u=q.rows[0];
    if(!u||u.status==="disabled"||u.role!=="admin")return res.status(403).send(shell({title:"Access denied",user:req.user,body:`<div class="header"><div><h2>Admin access required</h2><p>This area is reserved for AffiliateLab administrators.</p></div><a class="btn" href="/dashboard">Back to dashboard</a></div>`}));
    req.user.role=u.role;
    next();
  }catch(e){next(e);}
}

function shell({title,user,active="",body}){
  const nav=(u,l,k,i)=>`<a class="${active===k?"active":""}" href="${u}">${i} ${l}</a>`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · AffiliateLab</title><link rel="stylesheet" href="/static/app.css"></head><body>
  <div class="app"><aside class="sidebar"><div class="brand"><div class="logo">⚗</div><div><h1>AffiliateLab</h1><small>Creator Intelligence</small></div></div>
  <nav class="nav">${nav("/dashboard","Dashboard","dashboard","▣")}${nav("/products","My Products","products","▤")}${nav("/products/new","Add Product","new","＋")}${nav("/imports/kalodata","Import CSV","import","⇧")}${nav("/opportunities","Top Opportunities","opportunities","▥")}${nav("/avatar","My Avatar","avatar","◉")}${nav("/creatives","Creative Studio","creatives","▻")}${nav("/settings","Settings","settings","⚙")}${user.role==="admin"?nav("/admin","Admin","admin","◆"):""}</nav>
  <div class="sidebar-bottom"><div class="userbox"><b>${esc(user.name||"Creator Pro")}</b><div class="email">${esc(user.email)}</div><a class="logout" href="/logout">Sign out</a></div></div></aside><main class="main">${body}</main></div></body></html>`;
}
function authPage(title,content){
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · AffiliateLab</title><link rel="stylesheet" href="/static/app.css"></head><body class="authbody"><div class="authcard"><div class="authbrand"><div class="logo">⚗</div><h1>AffiliateLab</h1><div class="muted">AI-powered affiliate operating system</div></div>${content}</div></body></html>`;
}

let SCORE_CONFIG={sales_weight:24,commission_weight:20,competition_weight:16,visual_weight:16,impulse_weight:14,problem_weight:10,priority_threshold:80,test_threshold:68,watch_threshold:55};
function scoreProduct(p){
  const price=+p.price||0,comm=+p.commission_percent||0,s7=+p.sales_7d||0,s30=+p.sales_30d||0,creators=+p.creator_count||0,videos=+p.video_count||0;
  const salesMomentum=Math.max(0,Math.min(100,Math.round((s7*4/Math.max(1,s30))*70+Math.min(30,s7/100))));
  const competition=Math.max(5,Math.min(100,Math.round(100-(Math.min(60,creators/50)+Math.min(35,videos/150)))));
  const commission=Math.min(100,Math.round(comm*4));
  const priceScore=price<=15?95:price<=40?90:price<=70?78:price<=120?62:45;
  const visual=82,problem=78,impulse=Math.round((priceScore+commission)/2);
  const weights=[SCORE_CONFIG.sales_weight,SCORE_CONFIG.commission_weight,SCORE_CONFIG.competition_weight,SCORE_CONFIG.visual_weight,SCORE_CONFIG.impulse_weight,SCORE_CONFIG.problem_weight].map(Number);
  const denom=Math.max(1,weights.reduce((a,b)=>a+b,0));
  const total=Math.max(0,Math.min(100,Math.round((salesMomentum*weights[0]+commission*weights[1]+competition*weights[2]+visual*weights[3]+impulse*weights[4]+problem*weights[5])/denom)));
  const recommendation=total>=SCORE_CONFIG.priority_threshold?"PRIORITY TEST":total>=SCORE_CONFIG.test_threshold?"TEST":total>=SCORE_CONFIG.watch_threshold?"WATCH":"PASS";
  return {salesMomentum,competition,commission,visual,problem,impulse,total,recommendation};
}

function numberish(value){
  if(value===null||value===undefined||value==="") return 0;
  let s=String(value).trim().replace(/[$,%£€\s]/g,"").replace(/,/g,"");
  const m=s.match(/^(-?\d+(?:\.\d+)?)([kmb])?$/i);
  if(!m) return Number(s)||0;
  const mult={k:1e3,m:1e6,b:1e9};
  return Number(m[1])*(m[2]?mult[m[2].toLowerCase()]:1);
}
function mapped(row,key,mapping){
  const header=mapping?.[key];
  return header ? row?.[header] : undefined;
}
function normalizedImportedProduct(row,mapping){
  const statusRaw=String(mapped(row,"status",mapping)||"new").trim().toLowerCase();
  return {
    name:String(mapped(row,"name",mapping)||"").trim().slice(0,250),
    product_url:String(mapped(row,"product_url",mapping)||"").trim().slice(0,2000),
    category:String(mapped(row,"category",mapping)||"").trim().slice(0,150),
    description:String(mapped(row,"description",mapping)||"").trim().slice(0,3000),
    price:numberish(mapped(row,"price",mapping)),
    commission_percent:numberish(mapped(row,"commission_percent",mapping)),
    sales_7d:Math.round(numberish(mapped(row,"sales_7d",mapping))),
    sales_30d:Math.round(numberish(mapped(row,"sales_30d",mapping))),
    revenue_30d:numberish(mapped(row,"revenue_30d",mapping)),
    creator_count:Math.round(numberish(mapped(row,"creator_count",mapping))),
    video_count:Math.round(numberish(mapped(row,"video_count",mapping))),
    views_30d:Math.round(numberish(mapped(row,"views_30d",mapping))),
    affiliate_network:String(mapped(row,"affiliate_network",mapping)||"TikTok Shop").trim().slice(0,100),
    tracking_link:String(mapped(row,"tracking_link",mapping)||"").trim().slice(0,2000),
    notes:String(mapped(row,"notes",mapping)||"Imported from CSV").trim().slice(0,5000),
    status:["new","testing","winner","rejected"].includes(statusRaw)?statusRaw:"new",
  };
}
async function upsertScoredProduct(db,uid,p){
  const sc=scoreProduct(p),commissionAmount=p.price*p.commission_percent/100;
  const q=await db.query(`INSERT INTO products(user_id,name,product_url,category,description,price,commission_percent,commission_amount,sales_7d,sales_30d,revenue_30d,creator_count,video_count,views_30d,affiliate_network,tracking_link,notes,affiliate_score,status,updated_at)
  VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,NOW())
  ON CONFLICT (user_id,product_url) WHERE user_id IS NOT NULL AND product_url IS NOT NULL DO UPDATE SET name=EXCLUDED.name,category=EXCLUDED.category,description=EXCLUDED.description,price=EXCLUDED.price,commission_percent=EXCLUDED.commission_percent,commission_amount=EXCLUDED.commission_amount,sales_7d=EXCLUDED.sales_7d,sales_30d=EXCLUDED.sales_30d,revenue_30d=EXCLUDED.revenue_30d,creator_count=EXCLUDED.creator_count,video_count=EXCLUDED.video_count,views_30d=EXCLUDED.views_30d,affiliate_network=EXCLUDED.affiliate_network,tracking_link=EXCLUDED.tracking_link,notes=EXCLUDED.notes,affiliate_score=EXCLUDED.affiliate_score,status=EXCLUDED.status,updated_at=NOW() RETURNING id`,
  [uid,p.name,p.product_url,p.category,p.description,p.price,p.commission_percent,commissionAmount,p.sales_7d,p.sales_30d,p.revenue_30d,p.creator_count,p.video_count,p.views_30d,p.affiliate_network,p.tracking_link,p.notes,sc.total,p.status]);
  const id=q.rows[0].id;
  await db.query(`INSERT INTO product_scores(product_id,competition_score,visual_demo_score,impulse_score,problem_desire_score,sales_momentum_score,commission_score,total_score,recommendation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[id,sc.competition,sc.visual,sc.impulse,sc.problem,sc.salesMomentum,sc.commission,sc.total,sc.recommendation]);
  return {id,score:sc};
}

async function migrate(){
  await pool.query(`
  CREATE TABLE IF NOT EXISTS users(
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'creator_pro',
    role TEXT NOT NULL DEFAULT 'creator',
    status TEXT NOT NULL DEFAULT 'active',
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'creator';
  ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
  ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
  ALTER TABLE products ADD COLUMN IF NOT EXISTS user_id BIGINT REFERENCES users(id) ON DELETE CASCADE;
  ALTER TABLE products ADD COLUMN IF NOT EXISTS description TEXT;
  ALTER TABLE products ADD COLUMN IF NOT EXISTS affiliate_network TEXT DEFAULT 'TikTok Shop';
  ALTER TABLE products ADD COLUMN IF NOT EXISTS tracking_link TEXT;
  ALTER TABLE products ADD COLUMN IF NOT EXISTS revenue_30d NUMERIC(14,2) DEFAULT 0;
  ALTER TABLE products ADD COLUMN IF NOT EXISTS views_30d BIGINT DEFAULT 0;
  ALTER TABLE products ADD COLUMN IF NOT EXISTS notes TEXT;
  ALTER TABLE products ADD COLUMN IF NOT EXISTS source TEXT DEFAULT 'manual';
  ALTER TABLE products DROP CONSTRAINT IF EXISTS products_product_url_unique;
  CREATE UNIQUE INDEX IF NOT EXISTS products_user_url_unique ON products(user_id,product_url)
    WHERE user_id IS NOT NULL AND product_url IS NOT NULL;
  CREATE INDEX IF NOT EXISTS products_user_score_idx ON products(user_id,affiliate_score DESC NULLS LAST);
  CREATE TABLE IF NOT EXISTS import_runs(
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    source TEXT NOT NULL DEFAULT 'kalodata_csv',
    total_rows INT NOT NULL DEFAULT 0,
    imported_rows INT NOT NULL DEFAULT 0,
    skipped_rows INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS app_settings(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS admin_audit_log(
    id BIGSERIAL PRIMARY KEY,
    admin_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    details TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS avatar_profiles(
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    avatar_name TEXT NOT NULL DEFAULT '',
    presentation TEXT NOT NULL DEFAULT '',
    age_range TEXT NOT NULL DEFAULT '',
    visual_description TEXT NOT NULL DEFAULT '',
    hair_skin_clothing TEXT NOT NULL DEFAULT '',
    voice_tone TEXT NOT NULL DEFAULT '',
    accent TEXT NOT NULL DEFAULT '',
    target_audience TEXT NOT NULL DEFAULT '',
    niche TEXT NOT NULL DEFAULT '',
    video_style TEXT NOT NULL DEFAULT '',
    generator TEXT NOT NULL DEFAULT 'Higgsfield',
    character_id TEXT NOT NULL DEFAULT '',
    reference_urls TEXT NOT NULL DEFAULT '',
    phrases_use TEXT NOT NULL DEFAULT '',
    phrases_avoid TEXT NOT NULL DEFAULT '',
    brand_rules TEXT NOT NULL DEFAULT '',
    character_lock_prompt TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS creative_packs(
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    use_avatar BOOLEAN NOT NULL DEFAULT TRUE,
    angle TEXT NOT NULL DEFAULT 'problem_solution',
    style TEXT NOT NULL DEFAULT 'ugc_direct',
    hooks JSONB NOT NULL DEFAULT '[]'::jsonb,
    scripts JSONB NOT NULL DEFAULT '[]'::jsonb,
    scenes JSONB NOT NULL DEFAULT '[]'::jsonb,
    video_prompt TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE INDEX IF NOT EXISTS creative_packs_user_created_idx ON creative_packs(user_id,created_at DESC);
  CREATE TABLE IF NOT EXISTS video_jobs(
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    creative_pack_id BIGINT NOT NULL REFERENCES creative_packs(id) ON DELETE CASCADE,
    provider TEXT NOT NULL DEFAULT 'Higgsfield',
    status TEXT NOT NULL DEFAULT 'queued',
    external_job_id TEXT NOT NULL DEFAULT '',
    request_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    video_url TEXT NOT NULL DEFAULT '',
    thumbnail_url TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE INDEX IF NOT EXISTS video_jobs_user_created_idx ON video_jobs(user_id,created_at DESC);
  CREATE INDEX IF NOT EXISTS video_jobs_pack_idx ON video_jobs(creative_pack_id);
  `);
  const adminEmail=String(process.env.ADMIN_EMAIL||"").trim().toLowerCase();
  if(adminEmail) await pool.query("UPDATE users SET role='admin' WHERE lower(email)=$1",[adminEmail]);
  const admins=await pool.query("SELECT COUNT(*)::int count FROM users WHERE role='admin'");
  if(admins.rows[0].count===0){
    await pool.query("UPDATE users SET role='admin' WHERE id=(SELECT id FROM users ORDER BY created_at,id LIMIT 1)");
  }
  const scoreRows=await pool.query("SELECT key,value FROM app_settings WHERE key LIKE 'score.%'");
  for(const r of scoreRows.rows){const k=r.key.replace('score.','');if(Object.hasOwn(SCORE_CONFIG,k))SCORE_CONFIG[k]=Number(r.value);}
}
await migrate();

app.get("/health",async(req,res)=>{try{await pool.query("SELECT 1");res.json({ok:true,service:"affiliatelab"});}catch{res.status(503).json({ok:false});}});
app.get("/",(req,res)=>res.redirect(sessionFrom(req)?"/dashboard":"/login"));

app.get("/signup",(req,res)=>res.send(authPage("Create account",`
<form method="post" action="/signup"><div class="field"><label>Name</label><input name="name" required autocomplete="name"></div><div class="field"><label>Email</label><input name="email" type="email" required autocomplete="email"></div><div class="field"><label>Password</label><input name="password" type="password" minlength="10" required autocomplete="new-password"></div><button class="btn primary">Create Creator Pro Account</button></form><div class="authfoot">Already have an account? <a href="/login">Sign in</a></div>`)));
app.post("/signup",async(req,res)=>{
  const name=String(req.body.name||"").trim().slice(0,100),email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");
  if(!name||!email||password.length<10)return res.status(400).send(authPage("Create account",`<div class="flash err">Use a valid name/email and a password of at least 10 characters.</div><div class="authfoot"><a href="/signup">Try again</a></div>`));
  try{const hash=await bcrypt.hash(password,12);const q=await pool.query("INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email",[name,email,hash]);setSession(res,q.rows[0]);res.redirect("/dashboard");}
  catch(e){if(e.code==="23505")return res.status(409).send(authPage("Create account",`<div class="flash err">That email already has an account.</div><div class="authfoot"><a href="/login">Sign in instead</a></div>`));throw e;}
});
app.get("/login",(req,res)=>res.send(authPage("Sign in",`<form method="post" action="/login"><div class="field"><label>Email</label><input name="email" type="email" required autocomplete="email"></div><div class="field"><label>Password</label><input name="password" type="password" required autocomplete="current-password"></div><button class="btn primary">Sign in</button></form><div class="authfoot">New here? <a href="/signup">Create Creator Pro account</a></div>`)));
app.post("/login",async(req,res)=>{
  const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");
  const q=await pool.query("SELECT id,name,email,password_hash,role,status FROM users WHERE email=$1",[email]);const u=q.rows[0];
  if(!u||u.status==="disabled"||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).send(authPage("Sign in",`<div class="flash err">Email or password is incorrect.</div><div class="authfoot"><a href="/login">Try again</a></div>`));
  await pool.query("UPDATE users SET last_login_at=NOW() WHERE id=$1",[u.id]);
  setSession(res,u);res.redirect("/dashboard");
});
app.get("/logout",(req,res)=>{res.clearCookie("affiliatelab_session",{path:"/"});res.redirect("/login");});

app.get("/dashboard",requireAuth,async(req,res)=>{
  const uid=+req.user.sub;
  const [sq,tq]=await Promise.all([
    pool.query(`SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE status='testing')::int testing,COUNT(*) FILTER(WHERE status='winner')::int winners,COALESCE(SUM(commission_amount),0) commission FROM products WHERE user_id=$1`,[uid]),
    pool.query(`SELECT id,name,category,price,commission_percent,affiliate_score,status FROM products WHERE user_id=$1 ORDER BY affiliate_score DESC NULLS LAST,updated_at DESC LIMIT 8`,[uid])
  ]);
  const s=sq.rows[0],rows=tq.rows.map(p=>`<tr><td><a href="/products/${p.id}"><b>${esc(p.name)}</b></a></td><td>${esc(p.category||"—")}</td><td>${money(p.price)}</td><td>${+p.commission_percent||0}%</td><td><b>${p.affiliate_score??"—"}</b></td><td><span class="pill ${esc(p.status)}">${esc(p.status)}</span></td></tr>`).join("");
  res.send(shell({title:"Dashboard",user:req.user,active:"dashboard",body:`<div class="header"><div><div class="kicker">Creator Pro</div><h2>Dashboard</h2><p>Find products, score opportunities, create content, scale winners.</p></div><div class="actions"><a class="btn" href="/imports/kalodata">⇧ Import CSV</a><a class="btn primary" href="/products/new">＋ Add Product</a></div></div>
  <section class="stats"><div class="card stat"><div class="label">Products Tracked</div><div class="value">${s.total}</div></div><div class="card stat"><div class="label">Testing</div><div class="value">${s.testing}</div></div><div class="card stat"><div class="label">Winners</div><div class="value green">${s.winners}</div></div><div class="card stat"><div class="label">Est. Commission</div><div class="value">${money(s.commission)}</div></div></section>
  <section class="hero"><div class="card"><div class="cardpad"><div class="kicker">The AffiliateLab Loop</div><h3>Research → Score → Create → Test → Scale</h3><p>Kalodata supplies the research. AffiliateLab becomes the decision and execution layer.</p><div class="actions"><a class="btn primary" href="/imports/kalodata">Import Kalodata CSV</a><a class="btn" href="/opportunities">View Opportunities</a></div></div></div><div class="card"><div class="cardpad"><div class="muted">Best current opportunity</div><div class="scorebig">${tq.rows[0]?.affiliate_score??"—"}</div><b>${esc(tq.rows[0]?.name||"Add your first product")}</b></div></div></section>
  <section class="card"><div class="head">Top Products</div><div class="tablewrap">${rows?`<table class="table"><thead><tr><th>Product</th><th>Category</th><th>Price</th><th>Commission</th><th>Score</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`:`<div class="empty">No products yet. Add one to begin.</div>`}</div></section>`}));
});

app.get("/products",requireAuth,async(req,res)=>{
  const q=await pool.query(`SELECT id,name,category,price,commission_percent,sales_30d,creator_count,affiliate_score,status FROM products WHERE user_id=$1 ORDER BY updated_at DESC`,[+req.user.sub]);
  const rows=q.rows.map(p=>`<tr><td><a href="/products/${p.id}"><b>${esc(p.name)}</b></a></td><td>${esc(p.category||"—")}</td><td>${money(p.price)}</td><td>${+p.commission_percent||0}%</td><td>${num(p.sales_30d)}</td><td>${num(p.creator_count)}</td><td><b>${p.affiliate_score??"—"}</b></td><td><span class="pill ${esc(p.status)}">${esc(p.status)}</span></td></tr>`).join("");
  res.send(shell({title:"Products",user:req.user,active:"products",body:`<div class="header"><div><h2>My Products</h2><p>Your private opportunity database.</p></div><div class="actions"><a class="btn" href="/imports/kalodata">⇧ Import CSV</a><a class="btn primary" href="/products/new">＋ Add Product</a></div></div><section class="card"><div class="tablewrap">${rows?`<table class="table"><thead><tr><th>Product</th><th>Category</th><th>Price</th><th>Commission</th><th>30d Sales</th><th>Creators</th><th>Score</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`:`<div class="empty">No products yet.</div>`}</div></section>`}));
});

function productForm(csrf){
 return `<form method="post" action="/products"><input type="hidden" name="_csrf" value="${esc(csrf)}"><div class="layout">
 <section class="card"><div class="head">🏷 Product Information</div><div class="cardpad"><div class="grid2"><div>
 <div class="field"><label>Product Name *</label><input name="name" required></div><div class="field"><label>Product URL *</label><input name="product_url" required></div><div class="field"><label>Category / Niche</label><input name="category"></div><div class="field"><label>Description</label><textarea name="description"></textarea></div>
 <div class="moneyrow"><div class="field"><label>Price USD</label><input id="price" name="price" type="number" step=".01" value="29.99"></div><div class="field"><label>Commission %</label><input id="commission_percent" name="commission_percent" type="number" step=".1" value="20"></div><div class="field"><label>Commission $</label><input id="commission_amount" disabled></div></div>
 <div class="field"><label>Affiliate Network</label><select name="affiliate_network"><option>TikTok Shop</option><option>Amazon</option><option>ClickBank</option><option>Other</option></select></div><div class="field"><label>Your Affiliate Link</label><input name="tracking_link"></div>
 </div><div><div class="field"><label>Sales — 7 days</label><input id="sales_7d" name="sales_7d" type="number" value="0"></div><div class="field"><label>Sales — 30 days</label><input id="sales_30d" name="sales_30d" type="number" value="0"></div><div class="field"><label>Revenue — 30 days</label><input name="revenue_30d" type="number" step=".01" value="0"></div><div class="field"><label>Creator count</label><input id="creator_count" name="creator_count" type="number" value="0"></div><div class="field"><label>Video count</label><input id="video_count" name="video_count" type="number" value="0"></div><div class="field"><label>Views — 30 days</label><input name="views_30d" type="number" value="0"></div><div class="field"><label>Status</label><select name="status"><option>new</option><option>testing</option><option>winner</option><option>rejected</option></select></div><div class="field"><label>Private Notes</label><textarea name="notes"></textarea></div></div></div><div class="actions"><button class="btn primary">✦ Save & Analyze</button><a class="btn" href="/products">Cancel</a></div></div></section>
 <aside><section class="card score"><div style="font-weight:800;margin-bottom:16px">Opportunity Score Preview</div><div class="scoretop"><div class="ring" id="ring" style="--score:70"><div class="ringinner"><strong id="score">70</strong><div><span>/100</span></div></div></div><div><div class="badge" id="potential">TEST</div><div class="muted">Final score is calculated securely on the server.</div></div></div><div id="metrics"></div></section><section class="card" style="margin-top:16px"><div class="cardpad"><b>Kalodata workflow</b><p class="muted">You can now import a CSV from the Import CSV page instead of typing products one-by-one.</p><a class="btn" href="/imports/kalodata">Import CSV</a></div></section></aside></div></form>
 <script>const $=id=>document.getElementById(id),n=id=>Number($(id)?.value||0);function c(){const p=n("price"),co=n("commission_percent"),s7=n("sales_7d"),s30=n("sales_30d"),cr=n("creator_count"),v=n("video_count"),sm=Math.max(0,Math.min(100,Math.round((s7*4/Math.max(1,s30))*70+Math.min(30,s7/100)))),comp=Math.max(5,Math.min(100,Math.round(100-(Math.min(60,cr/50)+Math.min(35,v/150))))),cs=Math.min(100,Math.round(co*4)),ps=p<=15?95:p<=40?90:p<=70?78:p<=120?62:45,vis=82,prob=78,imp=Math.round((ps+cs)/2),t=Math.max(0,Math.min(100,Math.round(sm*.24+cs*.20+comp*.16+vis*.16+imp*.14+prob*.10)));$("score").textContent=t;$("ring").style.setProperty("--score",t);$("potential").textContent=t>=80?"PRIORITY TEST":t>=68?"TEST":t>=55?"WATCH":"PASS";$("commission_amount").value=(p*co/100).toFixed(2);const r=[["Sales Momentum",sm],["Competition",comp],["Commission",cs],["Visual Demo",vis],["Impulse",imp]];$("metrics").innerHTML=r.map(x=>'<div class="metric"><div class="metricrow"><span>'+x[0]+'</span><b>'+x[1]+'/100</b></div><div class="bar"><i style="width:'+x[1]+'%"></i></div></div>').join("")}document.querySelectorAll("input,select").forEach(x=>x.addEventListener("input",c));c()</script>`;
}
app.get("/products/new",requireAuth,(req,res)=>res.send(shell({title:"Add Product",user:req.user,active:"new",body:`<div class="header"><div><h2>Add New Product</h2><p>Enter Kalodata/TikTok Shop metrics and let AffiliateLab prioritize the test.</p></div></div>${productForm(req.user.csrf)}`})));

app.post("/products",requireAuth,requireCsrf,async(req,res)=>{
  const uid=+req.user.sub,b=req.body,p={name:String(b.name||"").trim().slice(0,250),product_url:String(b.product_url||"").trim().slice(0,2000),category:String(b.category||"").trim().slice(0,150),description:String(b.description||"").trim().slice(0,3000),price:+b.price||0,commission_percent:+b.commission_percent||0,sales_7d:+b.sales_7d||0,sales_30d:+b.sales_30d||0,revenue_30d:+b.revenue_30d||0,creator_count:+b.creator_count||0,video_count:+b.video_count||0,views_30d:+b.views_30d||0,affiliate_network:String(b.affiliate_network||"TikTok Shop"),tracking_link:String(b.tracking_link||"").trim().slice(0,2000),notes:String(b.notes||"").trim().slice(0,5000),status:["new","testing","winner","rejected"].includes(b.status)?b.status:"new"};
  if(!p.name||!p.product_url)return res.status(400).send("Name and product URL are required.");
  const saved=await upsertScoredProduct(pool,uid,p);
  await pool.query(`UPDATE products SET source='manual' WHERE id=$1`,[saved.id]);
  if(process.env.N8N_PRODUCT_WEBHOOK)fetch(process.env.N8N_PRODUCT_WEBHOOK,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({event:"product.saved",user_id:uid,product_id:saved.id,...p,score:saved.score})}).catch(e=>console.error("n8n webhook:",e.message));
  res.redirect(`/products/${saved.id}?saved=1`);
});

function kalodataImportPage(csrf){
  const fields=[
    ["name","Product name",true],["product_url","Product URL",true],["category","Category",false],["description","Description",false],
    ["price","Price",false],["commission_percent","Commission %",false],["sales_7d","7-day sales",false],["sales_30d","30-day sales",false],
    ["revenue_30d","30-day revenue",false],["creator_count","Creator count",false],["video_count","Video count",false],["views_30d","30-day views",false],
    ["affiliate_network","Affiliate network",false],["tracking_link","Affiliate link",false],["status","Status",false],["notes","Notes",false]
  ];
  return `<div class="header"><div><div class="kicker">Kalodata Import</div><h2>Import Products from CSV</h2><p>Upload a CSV, map its columns once, preview the rows, then score and save them in bulk.</p></div><a class="btn" href="/products">My Products</a></div>
  <section class="card"><div class="head">1. Choose CSV</div><div class="cardpad">
    <div class="field"><label>CSV file</label><input id="csvFile" type="file" accept=".csv,text/csv"></div>
    <p class="muted">AffiliateLab reads the file in your browser first. Nothing is imported until you click <b>Import & Score</b>.</p>
    <div id="fileMeta" class="flash ok" style="display:none"></div>
  </div></section>
  <section id="mappingCard" class="card" style="margin-top:18px;display:none"><div class="head">2. Map Columns</div><div class="cardpad"><p class="muted">AffiliateLab will try to match common Kalodata-style headers automatically. Change any dropdown that is wrong.</p>
    <div class="grid2" id="mappingGrid">${fields.map(([k,l,r])=>`<div class="field"><label>${esc(l)}${r?' *':''}</label><select data-map="${k}"><option value="">— Not mapped —</option></select></div>`).join("")}</div>
  </div></section>
  <section id="previewCard" class="card" style="margin-top:18px;display:none"><div class="head">3. Preview</div><div class="tablewrap"><table class="table" id="previewTable"></table></div><div class="cardpad"><div id="importStatus"></div><div class="actions"><button id="importBtn" class="btn primary" type="button">⇧ Import & Score</button><button id="resetBtn" class="btn" type="button">Choose another file</button></div></div></section>
  <script>
  const CSRF=${JSON.stringify(csrf)};
  const ALIASES={
    name:["product name","product","name","title","item name"],product_url:["product url","product link","url","link","item url","shop url","tiktok shop url"],category:["category","niche","product category"],description:["description","product description"],
    price:["price","product price","sale price","selling price"],commission_percent:["commission %","commission percent","commission rate","commission","affiliate commission"],sales_7d:["7-day sales","7 day sales","sales 7d","7d sales","sales_7d"],sales_30d:["30-day sales","30 day sales","sales 30d","30d sales","sales_30d","monthly sales"],
    revenue_30d:["30-day revenue","30 day revenue","revenue 30d","30d revenue","gmv","30d gmv","sales amount"],creator_count:["creator count","creators","creator number","affiliate creators"],video_count:["video count","videos","video number","related videos"],views_30d:["30-day views","30 day views","views 30d","30d views","video views"],
    affiliate_network:["affiliate network","network","platform"],tracking_link:["affiliate link","tracking link"],status:["status"],notes:["notes","note"]
  };
  let headers=[],rows=[];
  function parseCSV(text){
    text=text.replace(/^\\uFEFF/,""); const out=[]; let row=[],cell="",q=false;
    for(let i=0;i<text.length;i++){const ch=text[i],next=text[i+1]; if(q){if(ch==='"'&&next==='"'){cell+='"';i++;}else if(ch==='"'){q=false;}else cell+=ch;}else{if(ch==='"')q=true;else if(ch===','){row.push(cell);cell="";}else if(ch==='\\n'){row.push(cell);out.push(row);row=[];cell="";}else if(ch!=='\\r')cell+=ch;}}
    if(cell.length||row.length){row.push(cell);out.push(row);} return out.filter(r=>r.some(c=>String(c).trim()!==""));
  }
  function norm(s){return String(s||"").trim().toLowerCase().replace(/[_-]+/g," ").replace(/\\s+/g," ");}
  function autoHeader(key){const aliases=ALIASES[key]||[]; for(const a of aliases){const i=headers.findIndex(h=>norm(h)===a); if(i>=0)return headers[i];} for(const a of aliases){const i=headers.findIndex(h=>norm(h).includes(a)); if(i>=0)return headers[i];} return "";}
  function populateMaps(){document.querySelectorAll('[data-map]').forEach(sel=>{sel.innerHTML='<option value="">— Not mapped —</option>'+headers.map(h=>'<option value="'+h.replace(/&/g,'&amp;').replace(/"/g,'&quot;')+'">'+h.replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</option>').join(''); const a=autoHeader(sel.dataset.map); if(a)sel.value=a;});}
  function mapping(){const m={};document.querySelectorAll('[data-map]').forEach(s=>m[s.dataset.map]=s.value);return m;}
  function rowObjects(matrix){return matrix.slice(1).map(r=>Object.fromEntries(headers.map((h,i)=>[h,r[i]??""])));}
  function preview(){const m=mapping(); const keys=["name","product_url","price","commission_percent","sales_30d","creator_count"]; const labels={name:"Product",product_url:"URL",price:"Price",commission_percent:"Commission",sales_30d:"30d Sales",creator_count:"Creators"}; const head='<thead><tr>'+keys.map(k=>'<th>'+labels[k]+'</th>').join('')+'</tr></thead>'; const body='<tbody>'+rows.slice(0,5).map(r=>'<tr>'+keys.map(k=>'<td>'+String(m[k]?r[m[k]]||"":"—").replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</td>').join('')+'</tr>').join('')+'</tbody>'; document.getElementById('previewTable').innerHTML=head+body;}
  document.getElementById('csvFile').addEventListener('change',async e=>{const f=e.target.files[0];if(!f)return;if(f.size>4*1024*1024){alert('Please keep CSV files under 4 MB.');return;}const text=await f.text();const matrix=parseCSV(text);if(matrix.length<2){alert('No data rows found in this CSV.');return;}headers=matrix[0].map(h=>String(h).trim());rows=rowObjects(matrix);document.getElementById('fileMeta').style.display='block';document.getElementById('fileMeta').textContent=f.name+' · '+rows.length+' data rows · '+headers.length+' columns';populateMaps();document.getElementById('mappingCard').style.display='block';document.getElementById('previewCard').style.display='block';preview();document.querySelectorAll('[data-map]').forEach(s=>s.onchange=preview);});
  document.getElementById('resetBtn').onclick=()=>location.reload();
  document.getElementById('importBtn').onclick=async()=>{const btn=document.getElementById('importBtn'),st=document.getElementById('importStatus'),m=mapping();if(!m.name||!m.product_url){st.innerHTML='<div class="flash err">Map both Product name and Product URL before importing.</div>';return;}btn.disabled=true;btn.textContent='Importing…';st.innerHTML='';try{const r=await fetch('/imports/kalodata',{method:'POST',headers:{'content-type':'application/json','x-csrf-token':CSRF},body:JSON.stringify({rows,mapping:m})});const d=await r.json();if(!r.ok)throw new Error(d.error||'Import failed');st.innerHTML='<div class="flash ok"><b>'+d.imported+' products imported/scored.</b> '+d.skipped+' rows skipped. <a href="/opportunities">View ranked opportunities →</a></div>';btn.textContent='Imported';}catch(err){st.innerHTML='<div class="flash err">'+String(err.message).replace(/</g,'&lt;')+'</div>';btn.disabled=false;btn.textContent='⇧ Import & Score';}};
  </script>`;
}
app.get("/imports/kalodata",requireAuth,(req,res)=>res.send(shell({title:"Import CSV",user:req.user,active:"import",body:kalodataImportPage(req.user.csrf)})));
app.post("/imports/kalodata",requireAuth,requireCsrf,async(req,res)=>{
  const uid=+req.user.sub,rows=Array.isArray(req.body?.rows)?req.body.rows:[],mapping=req.body?.mapping||{};
  if(!mapping.name||!mapping.product_url)return res.status(400).json({error:"Product name and Product URL must be mapped."});
  if(!rows.length)return res.status(400).json({error:"No CSV rows were received."});
  if(rows.length>1500)return res.status(400).json({error:"Import up to 1,500 rows at a time."});
  const client=await pool.connect(); let imported=0,skipped=0;
  try{
    await client.query("BEGIN");
    for(const row of rows){
      const p=normalizedImportedProduct(row,mapping);
      if(!p.name||!p.product_url){skipped++;continue;}
      try{new URL(p.product_url);}catch{skipped++;continue;}
      const saved=await upsertScoredProduct(client,uid,p);
      await client.query(`UPDATE products SET source='kalodata_csv' WHERE id=$1`,[saved.id]);
      imported++;
    }
    await client.query("COMMIT");
    await pool.query("INSERT INTO import_runs(user_id,source,total_rows,imported_rows,skipped_rows) VALUES($1,'kalodata_csv',$2,$3,$4)",[uid,rows.length,imported,skipped]);
    res.json({ok:true,imported,skipped,total:rows.length});
  }catch(e){await client.query("ROLLBACK");throw e;}finally{client.release();}
});

app.get("/products/:id",requireAuth,async(req,res)=>{
  const q=await pool.query(`SELECT p.*,ps.competition_score,ps.visual_demo_score,ps.impulse_score,ps.problem_desire_score,ps.sales_momentum_score,ps.commission_score,ps.recommendation FROM products p LEFT JOIN LATERAL(SELECT * FROM product_scores WHERE product_id=p.id ORDER BY scored_at DESC LIMIT 1)ps ON true WHERE p.id=$1 AND p.user_id=$2`,[+req.params.id,+req.user.sub]);const p=q.rows[0];if(!p)return res.status(404).send("Product not found");
  const m=[["Sales Momentum",p.sales_momentum_score],["Competition",p.competition_score],["Commission",p.commission_score],["Visual Demo",p.visual_demo_score],["Impulse",p.impulse_score],["Problem / Desire",p.problem_desire_score]];
  res.send(shell({title:p.name,user:req.user,active:"products",body:`${req.query.saved?'<div class="flash ok">Product saved and analyzed.</div>':""}<div class="header"><div><div class="kicker">${esc(p.recommendation||"ANALYZED")}</div><h2>${esc(p.name)}</h2><p>${esc(p.category||"Uncategorized")} · ${money(p.price)} · ${+p.commission_percent||0}% commission</p></div><a class="btn" href="/products">Back</a></div><div class="layout"><section class="card"><div class="head">Product Intelligence</div><div class="cardpad"><div class="grid2"><div><b>Product URL</b><p><a target="_blank" rel="noreferrer" href="${esc(p.product_url)}">${esc(p.product_url)}</a></p><b>Description</b><p class="muted">${esc(p.description||"—")}</p><b>Network</b><p>${esc(p.affiliate_network||"TikTok Shop")}</p><b>Source</b><p>${esc(p.source||"manual")}</p></div><div><b>7-day sales</b><p>${num(p.sales_7d)}</p><b>30-day sales</b><p>${num(p.sales_30d)}</p><b>Creators</b><p>${num(p.creator_count)}</p><b>Videos</b><p>${num(p.video_count)}</p></div></div></div></section><aside><section class="card score"><div style="font-weight:800">Affiliate Opportunity Score</div><div class="scoretop" style="margin-top:16px"><div class="ring" style="--score:${+p.affiliate_score||0}"><div class="ringinner"><strong>${+p.affiliate_score||0}</strong><div><span>/100</span></div></div></div><div><div class="badge">${esc(p.recommendation||"WATCH")}</div><div class="muted">Prioritize testing; this is not a guarantee.</div></div></div>${m.map(x=>`<div class="metric"><div class="metricrow"><span>${x[0]}</span><b>${+x[1]||0}/100</b></div><div class="bar"><i style="width:${+x[1]||0}%"></i></div></div>`).join("")}</section></aside></div>`}));
});

app.get("/opportunities",requireAuth,async(req,res)=>{
  const q=await pool.query(`SELECT id,name,category,affiliate_score,status,commission_percent,sales_30d FROM products WHERE user_id=$1 ORDER BY affiliate_score DESC NULLS LAST LIMIT 50`,[+req.user.sub]);
  const rows=q.rows.map((p,i)=>`<tr><td>${i+1}</td><td><a href="/products/${p.id}"><b>${esc(p.name)}</b></a></td><td>${esc(p.category||"—")}</td><td><b>${p.affiliate_score??"—"}</b></td><td>${+p.commission_percent||0}%</td><td>${num(p.sales_30d)}</td><td><span class="pill ${esc(p.status)}">${esc(p.status)}</span></td></tr>`).join("");
  res.send(shell({title:"Top Opportunities",user:req.user,active:"opportunities",body:`<div class="header"><div><h2>Top Opportunities</h2><p>Rank products by AffiliateLab Opportunity Score.</p></div><a class="btn primary" href="/imports/kalodata">⇧ Import More</a></div><section class="card"><div class="tablewrap">${rows?`<table class="table"><thead><tr><th>#</th><th>Product</th><th>Category</th><th>Score</th><th>Commission</th><th>30d Sales</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`:`<div class="empty">Add products to create your ranking.</div>`}</div></section>`}));
});

function adminTabs(active){
  const items=[["/admin","Overview","overview"],["/admin/users","Users","users"],["/admin/products","Products","products"],["/admin/imports","Imports","imports"],["/admin/scoring","Scoring","scoring"],["/admin/seo","SEO / Content","seo"],["/admin/billing","Billing","billing"],["/admin/settings","App Settings","settings"]];
  return `<div class="actions" style="margin-bottom:18px;flex-wrap:wrap">${items.map(([u,l,k])=>`<a class="btn ${active===k?"primary":""}" href="${u}">${l}</a>`).join("")}</div>`;
}
async function audit(adminId,action,targetType="",targetId="",details=""){
  await pool.query("INSERT INTO admin_audit_log(admin_user_id,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5)",[adminId,action,targetType,targetId,String(details||"").slice(0,4000)]);
}
app.get("/admin",requireAuth,requireAdmin,async(req,res)=>{
  const [u,p,i,a]=await Promise.all([
    pool.query("SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE status='active')::int active,COUNT(*) FILTER(WHERE role='admin')::int admins FROM users"),
    pool.query("SELECT COUNT(*)::int total,COUNT(*) FILTER(WHERE status='winner')::int winners,COALESCE(AVG(affiliate_score),0)::numeric(10,1) avg_score FROM products WHERE user_id IS NOT NULL"),
    pool.query("SELECT COALESCE(SUM(imported_rows),0)::int imported,COUNT(*)::int runs FROM import_runs"),
    pool.query("SELECT l.*,u.email FROM admin_audit_log l LEFT JOIN users u ON u.id=l.admin_user_id ORDER BY l.created_at DESC LIMIT 8")
  ]);
  const us=u.rows[0],ps=p.rows[0],im=i.rows[0];
  const activity=a.rows.map(x=>`<tr><td>${esc(x.action)}</td><td>${esc(x.email||"system")}</td><td>${esc(x.target_type||"—")}</td><td>${new Date(x.created_at).toLocaleString()}</td></tr>`).join("");
  res.send(shell({title:"Admin",user:req.user,active:"admin",body:`<div class="header"><div><div class="kicker">Owner Console</div><h2>AffiliateLab Admin</h2><p>Manage users, products, imports, scoring, SEO and platform settings.</p></div><a class="btn" href="/dashboard">Creator dashboard</a></div>${adminTabs("overview")}<section class="stats"><div class="card stat"><div class="label">Users</div><div class="value">${us.total}</div></div><div class="card stat"><div class="label">Active</div><div class="value">${us.active}</div></div><div class="card stat"><div class="label">Products</div><div class="value">${ps.total}</div></div><div class="card stat"><div class="label">CSV Products Imported</div><div class="value">${im.imported}</div></div></section><section class="hero"><div class="card"><div class="cardpad"><div class="kicker">Platform health</div><h3>${ps.winners} winners · ${im.runs} import runs</h3><p>Average product score: <b>${ps.avg_score}</b>. Admin accounts: <b>${us.admins}</b>.</p></div></div><div class="card"><div class="cardpad"><div class="kicker">Admin-only</div><h3>Your creator login now unlocks this console</h3><p>Customers cannot access any <code>/admin</code> route unless their role is explicitly set to admin.</p></div></div></section><section class="card"><div class="head">Recent Admin Activity</div><div class="tablewrap">${activity?`<table class="table"><thead><tr><th>Action</th><th>Admin</th><th>Target</th><th>When</th></tr></thead><tbody>${activity}</tbody></table>`:`<div class="empty">No admin changes yet.</div>`}</div></section>`}));
});
app.get("/admin/users",requireAuth,requireAdmin,async(req,res)=>{
  const q=await pool.query(`SELECT u.id,u.name,u.email,u.plan,u.role,u.status,u.created_at,u.last_login_at,COUNT(p.id)::int product_count FROM users u LEFT JOIN products p ON p.user_id=u.id GROUP BY u.id ORDER BY u.created_at DESC`);
  const rows=q.rows.map(u=>`<tr><td><b>${esc(u.name)}</b><div class="muted">${esc(u.email)}</div></td><td>${esc(u.plan)}</td><td>${esc(u.role)}</td><td><span class="pill ${u.status==='active'?'winner':'rejected'}">${esc(u.status)}</span></td><td>${u.product_count}</td><td>${u.last_login_at?new Date(u.last_login_at).toLocaleString():"Never"}</td><td><form method="post" action="/admin/users/${u.id}" style="display:flex;gap:6px;align-items:center"><input type="hidden" name="_csrf" value="${esc(req.user.csrf)}"><select name="role"><option ${u.role==='creator'?'selected':''}>creator</option><option ${u.role==='admin'?'selected':''}>admin</option></select><select name="status"><option ${u.status==='active'?'selected':''}>active</option><option ${u.status==='disabled'?'selected':''}>disabled</option></select><select name="plan"><option ${u.plan==='creator_pro'?'selected':''}>creator_pro</option><option ${u.plan==='internal'?'selected':''}>internal</option><option ${u.plan==='free'?'selected':''}>free</option></select><button class="btn">Save</button></form></td></tr>`).join("");
  res.send(shell({title:"Admin Users",user:req.user,active:"admin",body:`<div class="header"><div><h2>Users</h2><p>Control access, roles and plans.</p></div></div>${adminTabs("users")}<section class="card"><div class="tablewrap"><table class="table"><thead><tr><th>User</th><th>Plan</th><th>Role</th><th>Status</th><th>Products</th><th>Last login</th><th>Controls</th></tr></thead><tbody>${rows}</tbody></table></div></section>`}));
});
app.post("/admin/users/:id",requireAuth,requireAdmin,requireCsrf,async(req,res)=>{
  const id=+req.params.id,role=["creator","admin"].includes(req.body.role)?req.body.role:"creator",status=["active","disabled"].includes(req.body.status)?req.body.status:"active",plan=["creator_pro","internal","free"].includes(req.body.plan)?req.body.plan:"creator_pro";
  if(id===+req.user.sub&&role!=="admin")return res.status(400).send("You cannot remove your own admin role.");
  if(id===+req.user.sub&&status!=="active")return res.status(400).send("You cannot disable your own account.");
  await pool.query("UPDATE users SET role=$1,status=$2,plan=$3 WHERE id=$4",[role,status,plan,id]);
  await audit(+req.user.sub,"user.updated","user",String(id),JSON.stringify({role,status,plan}));
  res.redirect("/admin/users");
});
app.get("/admin/products",requireAuth,requireAdmin,async(req,res)=>{
  const q=await pool.query(`SELECT p.id,p.name,p.category,p.price,p.affiliate_score,p.status,p.source,p.updated_at,u.email FROM products p LEFT JOIN users u ON u.id=p.user_id WHERE p.user_id IS NOT NULL ORDER BY p.updated_at DESC LIMIT 300`);
  const rows=q.rows.map(p=>`<tr><td><b>${esc(p.name)}</b><div class="muted">${esc(p.email||"—")}</div></td><td>${esc(p.category||"—")}</td><td>${money(p.price)}</td><td><b>${p.affiliate_score??"—"}</b></td><td>${esc(p.source||"manual")}</td><td>${esc(p.status)}</td><td>${new Date(p.updated_at).toLocaleString()}</td></tr>`).join("");
  res.send(shell({title:"Admin Products",user:req.user,active:"admin",body:`<div class="header"><div><h2>All Products</h2><p>Cross-account product visibility for support and operations.</p></div></div>${adminTabs("products")}<section class="card"><div class="tablewrap"><table class="table"><thead><tr><th>Product / Owner</th><th>Category</th><th>Price</th><th>Score</th><th>Source</th><th>Status</th><th>Updated</th></tr></thead><tbody>${rows}</tbody></table></div></section>`}));
});
app.get("/admin/imports",requireAuth,requireAdmin,async(req,res)=>{
  const q=await pool.query(`SELECT i.*,u.email FROM import_runs i LEFT JOIN users u ON u.id=i.user_id ORDER BY i.created_at DESC LIMIT 200`);
  const rows=q.rows.map(i=>`<tr><td>${esc(i.email||"—")}</td><td>${esc(i.source)}</td><td>${i.total_rows}</td><td>${i.imported_rows}</td><td>${i.skipped_rows}</td><td>${new Date(i.created_at).toLocaleString()}</td></tr>`).join("");
  res.send(shell({title:"Admin Imports",user:req.user,active:"admin",body:`<div class="header"><div><h2>CSV Imports</h2><p>Monitor bulk product ingestion and skipped rows.</p></div></div>${adminTabs("imports")}<section class="card"><div class="tablewrap">${rows?`<table class="table"><thead><tr><th>User</th><th>Source</th><th>Rows</th><th>Imported</th><th>Skipped</th><th>When</th></tr></thead><tbody>${rows}</tbody></table>`:`<div class="empty">No imports have been recorded yet.</div>`}</div></section>`}));
});
app.get("/admin/scoring",requireAuth,requireAdmin,async(req,res)=>{
  const defaults={sales_weight:"24",commission_weight:"20",competition_weight:"16",visual_weight:"16",impulse_weight:"14",problem_weight:"10",priority_threshold:"80",test_threshold:"68",watch_threshold:"55"};
  const q=await pool.query("SELECT key,value FROM app_settings WHERE key LIKE 'score.%'");const saved=Object.fromEntries(q.rows.map(r=>[r.key.replace('score.',''),r.value]));const v={...defaults,...saved};
  res.send(shell({title:"Scoring Settings",user:req.user,active:"admin",body:`<div class="header"><div><h2>Opportunity Scoring</h2><p>Owner controls for the AffiliateLab scoring model.</p></div></div>${adminTabs("scoring")}<section class="card"><div class="cardpad"><form method="post" action="/admin/scoring"><input type="hidden" name="_csrf" value="${esc(req.user.csrf)}"><div class="grid2"><div>${[["sales_weight","Sales momentum weight"],["commission_weight","Commission weight"],["competition_weight","Competition weight"],["visual_weight","Visual demo weight"],["impulse_weight","Impulse weight"],["problem_weight","Problem/desire weight"]].map(([k,l])=>`<div class="field"><label>${l}</label><input type="number" min="0" max="100" step="1" name="${k}" value="${esc(v[k])}"></div>`).join("")}</div><div>${[["priority_threshold","PRIORITY TEST threshold"],["test_threshold","TEST threshold"],["watch_threshold","WATCH threshold"]].map(([k,l])=>`<div class="field"><label>${l}</label><input type="number" min="0" max="100" step="1" name="${k}" value="${esc(v[k])}"></div>`).join("")}<div class="flash">Changes here apply to newly scored or re-imported products. Existing historical scores are preserved until those products are scored again.</div></div></div><button class="btn primary">Save scoring settings</button></form></div></section>`}));
});
app.post("/admin/scoring",requireAuth,requireAdmin,requireCsrf,async(req,res)=>{
  const keys=["sales_weight","commission_weight","competition_weight","visual_weight","impulse_weight","problem_weight","priority_threshold","test_threshold","watch_threshold"];
  for(const k of keys){const value=String(Math.max(0,Math.min(100,Number(req.body[k]||0))));await pool.query(`INSERT INTO app_settings(key,value,updated_by,updated_at) VALUES($1,$2,$3,NOW()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=NOW()`,[`score.${k}`,value,+req.user.sub]);SCORE_CONFIG[k]=Number(value);}
  await audit(+req.user.sub,"scoring.settings.updated","app_settings","score","Updated scoring control values");res.redirect("/admin/scoring");
});
app.get("/admin/seo",requireAuth,requireAdmin,async(req,res)=>{
  const defaults={site_title:"AffiliateLab — Creator Intelligence",meta_description:"AI-powered affiliate product research, scoring and creative operations.",marketing_domain:"",robots:"index,follow"};
  const q=await pool.query("SELECT key,value FROM app_settings WHERE key LIKE 'seo.%'");const saved=Object.fromEntries(q.rows.map(r=>[r.key.replace('seo.',''),r.value]));const v={...defaults,...saved};
  res.send(shell({title:"SEO / Content",user:req.user,active:"admin",body:`<div class="header"><div><h2>SEO / Content</h2><p>Private controls for the future public AffiliateLab marketing site.</p></div></div>${adminTabs("seo")}<section class="card"><div class="cardpad"><form method="post" action="/admin/seo"><input type="hidden" name="_csrf" value="${esc(req.user.csrf)}"><div class="field"><label>Site title</label><input name="site_title" value="${esc(v.site_title)}"></div><div class="field"><label>Meta description</label><textarea name="meta_description">${esc(v.meta_description)}</textarea></div><div class="field"><label>Marketing domain</label><input name="marketing_domain" placeholder="https://affiliatelab.com" value="${esc(v.marketing_domain)}"></div><div class="field"><label>Robots directive</label><select name="robots"><option ${v.robots==='index,follow'?'selected':''}>index,follow</option><option ${v.robots==='noindex,nofollow'?'selected':''}>noindex,nofollow</option></select></div><button class="btn primary">Save SEO settings</button></form><div class="flash" style="margin-top:16px">These settings are stored centrally. When we build the public marketing site/blog, it can read these values directly.</div></div></section>`}));
});
app.post("/admin/seo",requireAuth,requireAdmin,requireCsrf,async(req,res)=>{
  const vals={site_title:String(req.body.site_title||"").slice(0,160),meta_description:String(req.body.meta_description||"").slice(0,320),marketing_domain:String(req.body.marketing_domain||"").slice(0,300),robots:["index,follow","noindex,nofollow"].includes(req.body.robots)?req.body.robots:"index,follow"};
  for(const [k,value] of Object.entries(vals))await pool.query(`INSERT INTO app_settings(key,value,updated_by,updated_at) VALUES($1,$2,$3,NOW()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=NOW()`,[`seo.${k}`,value,+req.user.sub]);
  await audit(+req.user.sub,"seo.settings.updated","app_settings","seo",JSON.stringify(vals));res.redirect("/admin/seo");
});
app.get("/admin/billing",requireAuth,requireAdmin,async(req,res)=>{
  const q=await pool.query("SELECT plan,COUNT(*)::int count FROM users GROUP BY plan ORDER BY count DESC");
  res.send(shell({title:"Billing",user:req.user,active:"admin",body:`<div class="header"><div><h2>Billing</h2><p>Subscription operations for Creator Pro.</p></div></div>${adminTabs("billing")}<section class="stats">${q.rows.map(x=>`<div class="card stat"><div class="label">${esc(x.plan)}</div><div class="value">${x.count}</div></div>`).join("")}</section><section class="card"><div class="cardpad"><div class="kicker">Stripe next</div><h3>Creator Pro billing placeholder</h3><p>When Stripe is connected, this page should manage subscription status, trials, failed payments, credits and cancellations. No payment data is stored in AffiliateLab today.</p></div></section>`}));
});
app.get("/admin/settings",requireAuth,requireAdmin,async(req,res)=>{
  const q=await pool.query("SELECT key,value,updated_at FROM app_settings ORDER BY key");
  const rows=q.rows.map(x=>`<tr><td><code>${esc(x.key)}</code></td><td>${esc(x.value)}</td><td>${new Date(x.updated_at).toLocaleString()}</td></tr>`).join("");
  res.send(shell({title:"Admin Settings",user:req.user,active:"admin",body:`<div class="header"><div><h2>App Settings</h2><p>Central settings registry and integration status.</p></div></div>${adminTabs("settings")}<section class="hero"><div class="card"><div class="cardpad"><b>App URL</b><p>${esc(APP_URL)}</p><b>n8n webhook</b><p>${process.env.N8N_PRODUCT_WEBHOOK?"Configured":"Not configured"}</p></div></div><div class="card"><div class="cardpad"><b>Admin bootstrap</b><p>${process.env.ADMIN_EMAIL?`ADMIN_EMAIL configured: ${esc(process.env.ADMIN_EMAIL)}`:"Oldest account is admin unless ADMIN_EMAIL is configured."}</p></div></div></section><section class="card"><div class="head">Stored settings</div><div class="tablewrap">${rows?`<table class="table"><thead><tr><th>Key</th><th>Value</th><th>Updated</th></tr></thead><tbody>${rows}</tbody></table>`:`<div class="empty">No custom settings yet.</div>`}</div></section>`}));
});

function avatarLockPrompt(a){
  const parts=[
    a.avatar_name?`Character name: ${a.avatar_name}.`:"",
    a.presentation?`Presentation: ${a.presentation}.`:"",
    a.age_range?`Apparent age range: ${a.age_range}.`:"",
    a.visual_description?`Core appearance: ${a.visual_description}`:"",
    a.hair_skin_clothing?`Hair, skin and wardrobe continuity: ${a.hair_skin_clothing}`:"",
    a.voice_tone?`Voice and personality: ${a.voice_tone}`:"",
    a.accent?`Accent/speech style: ${a.accent}.`:"",
    a.niche?`Creator niche: ${a.niche}.`:"",
    a.target_audience?`Primary audience: ${a.target_audience}`:"",
    a.video_style?`Default video style: ${a.video_style}`:"",
    a.brand_rules?`Brand safety / continuity rules: ${a.brand_rules}`:"",
    a.phrases_use?`Preferred language: ${a.phrases_use}`:"",
    a.phrases_avoid?`Avoid: ${a.phrases_avoid}`:"",
    "Keep the same face, approximate age, hair, skin tone, body proportions, wardrobe logic, voice personality and overall identity across every scene. Do not randomly change identity-defining features."
  ].filter(Boolean);
  return parts.join(" ");
}

app.get("/avatar",requireAuth,async(req,res)=>{
  const q=await pool.query("SELECT * FROM avatar_profiles WHERE user_id=$1",[+req.user.sub]);
  const a=q.rows[0]||{};
  const filled=["avatar_name","visual_description","voice_tone","target_audience","niche","video_style"].filter(k=>String(a[k]||"").trim()).length;
  const completeness=Math.round(filled/6*100);
  const refs=String(a.reference_urls||"").split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
  const refCards=refs.slice(0,3).map((u,i)=>`<div class="card"><div class="cardpad"><div class="kicker">Reference ${i+1}</div><img src="${esc(u)}" alt="Avatar reference ${i+1}" style="width:100%;max-height:260px;object-fit:cover;border-radius:12px;margin-top:10px"><p class="muted" style="word-break:break-all">${esc(u)}</p></div></div>`).join("");
  res.send(shell({title:"My Avatar",user:req.user,active:"avatar",body:`
  <div class="header"><div><div class="kicker">Creator Identity</div><h2>My Avatar</h2><p>Build one persistent AI identity and reuse it across every product, script and video brief.</p></div><div class="actions"><span class="pill ${completeness>=80?"winner":completeness>=50?"testing":"new"}">${completeness}% complete</span></div></div>
  <section class="hero"><div class="card"><div class="cardpad"><div class="kicker">Identity lock</div><h3>${esc(a.avatar_name||"Create your avatar")}</h3><p>${a.visual_description?esc(a.visual_description):"Define the face, style, voice and audience once. AffiliateLab will carry those rules into future creative generation."}</p><div class="actions"><span class="pill new">${esc(a.generator||"Higgsfield")}</span>${a.character_id?`<span class="pill testing">Character ID saved</span>`:""}</div></div></div><div class="card"><div class="cardpad"><div class="kicker">How this will be used</div><h3>Product → Script → Avatar → Video</h3><p class="muted">Creative Studio will combine a winning product with this identity profile so hooks and scene prompts stay on-brand and visually consistent.</p></div></div></section>
  <section class="card"><div class="head">Avatar Identity Profile</div><div class="cardpad"><form method="post" action="/avatar"><input type="hidden" name="_csrf" value="${esc(req.user.csrf)}">
  <div class="grid2">
    <div>
      <div class="field"><label>Avatar name</label><input name="avatar_name" maxlength="100" placeholder="e.g. Maya" value="${esc(a.avatar_name||"")}"></div>
      <div class="field"><label>Presentation</label><select name="presentation"><option value="">Choose...</option>${["Female","Male","Androgynous / neutral","Custom"].map(x=>`<option ${a.presentation===x?"selected":""}>${x}</option>`).join("")}</select></div>
      <div class="field"><label>Age range</label><input name="age_range" maxlength="80" placeholder="e.g. 28–35" value="${esc(a.age_range||"")}"></div>
      <div class="field"><label>Core visual description</label><textarea name="visual_description" maxlength="2000" placeholder="Face, build, distinguishing features, overall look...">${esc(a.visual_description||"")}</textarea></div>
      <div class="field"><label>Hair / skin / clothing continuity</label><textarea name="hair_skin_clothing" maxlength="2000" placeholder="Hair style/color, skin tone, wardrobe rules, accessories...">${esc(a.hair_skin_clothing||"")}</textarea></div>
      <div class="field"><label>Reference image URLs</label><textarea name="reference_urls" maxlength="6000" placeholder="One HTTPS image URL per line, up to 3 references">${esc(a.reference_urls||"")}</textarea><div class="muted">For V1, paste image URLs. Direct file upload/storage can be added when we connect the video providers.</div></div>
    </div>
    <div>
      <div class="field"><label>Voice / personality</label><textarea name="voice_tone" maxlength="2000" placeholder="Warm, confident, conversational, energetic, expert...">${esc(a.voice_tone||"")}</textarea></div>
      <div class="field"><label>Accent / speech style</label><input name="accent" maxlength="200" placeholder="e.g. neutral North American, relaxed pace" value="${esc(a.accent||"")}"></div>
      <div class="field"><label>Target audience</label><textarea name="target_audience" maxlength="1500" placeholder="Who this avatar speaks to...">${esc(a.target_audience||"")}</textarea></div>
      <div class="field"><label>Content niche</label><input name="niche" maxlength="200" placeholder="e.g. beauty, hair care, wellness" value="${esc(a.niche||"")}"></div>
      <div class="field"><label>Preferred video style</label><input name="video_style" maxlength="500" placeholder="e.g. direct-to-camera UGC, bathroom demo, testimonial" value="${esc(a.video_style||"")}"></div>
      <div class="field"><label>Preferred generator</label><select name="generator">${["Higgsfield","Seedance","HeyGen","Other / manual"].map(x=>`<option ${String(a.generator||"Higgsfield")===x?"selected":""}>${x}</option>`).join("")}</select></div>
      <div class="field"><label>Provider character / avatar ID</label><input name="character_id" maxlength="500" placeholder="Optional ID from Higgsfield / HeyGen / another provider" value="${esc(a.character_id||"")}"></div>
    </div>
  </div>
  <div class="grid2">
    <div><div class="field"><label>Phrases / language to use</label><textarea name="phrases_use" maxlength="2000" placeholder="Preferred phrases, vocabulary, CTA style...">${esc(a.phrases_use||"")}</textarea></div></div>
    <div><div class="field"><label>Phrases / claims to avoid</label><textarea name="phrases_avoid" maxlength="2000" placeholder="Claims, words or tones this creator should never use...">${esc(a.phrases_avoid||"")}</textarea></div></div>
  </div>
  <div class="field"><label>Brand-safe / continuity rules</label><textarea name="brand_rules" maxlength="3000" placeholder="Always/never rules for the character, product presentation and brand safety...">${esc(a.brand_rules||"")}</textarea></div>
  <div class="field"><label>Character Lock Prompt</label><textarea name="character_lock_prompt" maxlength="7000" placeholder="AffiliateLab can generate this automatically from the fields above. You can also customize it.">${esc(a.character_lock_prompt||avatarLockPrompt(a))}</textarea><div class="muted">This becomes the reusable identity block Creative Studio can attach to future image/video prompts.</div></div>
  <div class="actions"><button class="btn primary">Save Avatar</button><a class="btn" href="/creatives">Open Creative Studio</a></div>
  </form></div></section>
  ${refCards?`<div class="header" style="margin-top:22px"><div><h3>Master References</h3><p>Visual references currently attached to this identity.</p></div></div><section class="hero">${refCards}</section>`:""}
  `}));
});

app.post("/avatar",requireAuth,requireCsrf,async(req,res)=>{
  const uid=+req.user.sub;
  const allowedGenerators=["Higgsfield","Seedance","HeyGen","Other / manual"];
  const a={
    avatar_name:String(req.body.avatar_name||"").trim().slice(0,100),
    presentation:String(req.body.presentation||"").trim().slice(0,100),
    age_range:String(req.body.age_range||"").trim().slice(0,80),
    visual_description:String(req.body.visual_description||"").trim().slice(0,2000),
    hair_skin_clothing:String(req.body.hair_skin_clothing||"").trim().slice(0,2000),
    voice_tone:String(req.body.voice_tone||"").trim().slice(0,2000),
    accent:String(req.body.accent||"").trim().slice(0,200),
    target_audience:String(req.body.target_audience||"").trim().slice(0,1500),
    niche:String(req.body.niche||"").trim().slice(0,200),
    video_style:String(req.body.video_style||"").trim().slice(0,500),
    generator:allowedGenerators.includes(req.body.generator)?req.body.generator:"Higgsfield",
    character_id:String(req.body.character_id||"").trim().slice(0,500),
    reference_urls:String(req.body.reference_urls||"").split(/\r?\n/).map(x=>x.trim()).filter(x=>/^https:\/\//i.test(x)).slice(0,3).join("\n").slice(0,6000),
    phrases_use:String(req.body.phrases_use||"").trim().slice(0,2000),
    phrases_avoid:String(req.body.phrases_avoid||"").trim().slice(0,2000),
    brand_rules:String(req.body.brand_rules||"").trim().slice(0,3000),
    character_lock_prompt:String(req.body.character_lock_prompt||"").trim().slice(0,7000),
  };
  if(!a.character_lock_prompt)a.character_lock_prompt=avatarLockPrompt(a);
  await pool.query(`INSERT INTO avatar_profiles(user_id,avatar_name,presentation,age_range,visual_description,hair_skin_clothing,voice_tone,accent,target_audience,niche,video_style,generator,character_id,reference_urls,phrases_use,phrases_avoid,brand_rules,character_lock_prompt,updated_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,NOW())
    ON CONFLICT(user_id) DO UPDATE SET avatar_name=EXCLUDED.avatar_name,presentation=EXCLUDED.presentation,age_range=EXCLUDED.age_range,visual_description=EXCLUDED.visual_description,hair_skin_clothing=EXCLUDED.hair_skin_clothing,voice_tone=EXCLUDED.voice_tone,accent=EXCLUDED.accent,target_audience=EXCLUDED.target_audience,niche=EXCLUDED.niche,video_style=EXCLUDED.video_style,generator=EXCLUDED.generator,character_id=EXCLUDED.character_id,reference_urls=EXCLUDED.reference_urls,phrases_use=EXCLUDED.phrases_use,phrases_avoid=EXCLUDED.phrases_avoid,brand_rules=EXCLUDED.brand_rules,character_lock_prompt=EXCLUDED.character_lock_prompt,updated_at=NOW()`,
    [uid,a.avatar_name,a.presentation,a.age_range,a.visual_description,a.hair_skin_clothing,a.voice_tone,a.accent,a.target_audience,a.niche,a.video_style,a.generator,a.character_id,a.reference_urls,a.phrases_use,a.phrases_avoid,a.brand_rules,a.character_lock_prompt]);
  res.redirect("/avatar");
});
function creativeAngleLabel(v){
  return ({problem_solution:"Problem → Solution",before_after:"Before → After",demo_proof:"Demo / Proof",curiosity:"Curiosity / Pattern Interrupt",testimonial:"Testimonial / Personal Story",comparison:"Comparison / Why This One"})[v]||"Problem → Solution";
}
function creativeStyleLabel(v){
  return ({ugc_direct:"Direct-to-camera UGC",demo:"Product demo",testimonial:"Testimonial",voiceover:"Voiceover + B-roll",faceless:"Faceless / product-only"})[v]||"Direct-to-camera UGC";
}
function buildCreativePack(product,avatar,opts){
  const name=product.name||"this product";
  const category=product.category||"product";
  const price=Number(product.price||0);
  const commission=Number(product.commission_percent||0);
  const s7=Number(product.sales_7d||0), s30=Number(product.sales_30d||0);
  const score=Number(product.affiliate_score||0);
  const angle=opts.angle||"problem_solution";
  const style=opts.style||"ugc_direct";
  const avatarName=opts.useAvatar && avatar?.avatar_name ? avatar.avatar_name : "";
  const audience=opts.useAvatar && avatar?.target_audience ? avatar.target_audience : "TikTok shoppers";
  const niche=opts.useAvatar && avatar?.niche ? avatar.niche : category;
  const voice=opts.useAvatar && avatar?.voice_tone ? avatar.voice_tone : "conversational, confident and natural";
  const intro=avatarName?`${avatarName} speaking in a ${voice} style`:`Creator speaking in a ${voice} style`;
  const proof=s7>0?`${s7.toLocaleString()} sales in the last 7 days`:s30>0?`${s30.toLocaleString()} sales in 30 days`:`an AffiliateLab opportunity score of ${score.toFixed(0)}`;
  const priceLine=price>0?`around $${price.toFixed(2)}`:"at the current offer price";
  const hooks=[
    `I didn't expect ${name} to be this interesting until I saw ${proof}.`,
    `If you're into ${niche}, this is the ${category} product I'd look at before it gets crowded.`,
    `Wait—before you buy another ${category} product, look at what ${name} is doing differently.`,
    `This is one of those TikTok Shop products that makes sense the second you see the demo.`,
    `${audience}: here's why ${name} just scored ${score.toFixed(0)}/100 in my product test.`
  ];
  const scripts=[
    {label:"15-second test",text:`${hooks[0]} Here's the quick version: ${name} is priced ${priceLine}, the commission is ${commission||0}%, and the product is showing real momentum. I'd open with the result, show the product immediately, and end with one clear CTA: check the offer while it's still easy to test.`},
    {label:"30-second UGC",text:`${hooks[2]} I found ${name} while looking at ${category} products with strong momentum. What caught my attention was ${proof}. The offer is ${priceLine}${commission?`, with a ${commission}% affiliate commission`:""}. I'd show the product in use, call out one visible benefit without overclaiming, then finish with: if this solves the problem you're dealing with, tap through and see if it fits you.`},
    {label:"45-second story/demo",text:`${hooks[4]} I keep seeing creators chase products after they're already saturated, so I wanted to test something earlier. ${name} stood out because it has ${proof}. For the video, I'd start with the problem, show the product within the first three seconds, demonstrate one clear use case, then explain why the offer feels easy to understand. Keep it specific, keep it believable, and let the product do the selling. CTA: check the product page and decide if it's worth trying.`}
  ];
  const scenes=[
    {scene:1,time:"0–3s",shot:"Pattern interrupt / close-up",direction:`Show ${name} immediately. On-screen text uses the strongest hook.`},
    {scene:2,time:"3–8s",shot:style==="faceless"?"Hands + product":"Creator + product",direction:`Introduce the core problem/desire for ${audience}.`},
    {scene:3,time:"8–16s",shot:"Demo / proof",direction:`Demonstrate one visible use case. Reference ${proof} as market proof, not a product-performance guarantee.`},
    {scene:4,time:"16–24s",shot:"Benefit + objection",direction:`Explain why ${name} is interesting at ${priceLine}. Keep claims brand-safe.`},
    {scene:5,time:"24–30s",shot:"CTA",direction:"One clear CTA. Avoid hype, fake urgency, or unsupported claims."}
  ];
  const lock=opts.useAvatar && avatar?.character_lock_prompt ? avatar.character_lock_prompt : "";
  const visual=opts.useAvatar && avatar ? [avatar.visual_description,avatar.hair_skin_clothing,avatar.video_style].filter(Boolean).join(" ") : "";
  const provider=opts.useAvatar && avatar?.generator ? avatar.generator : (style==="faceless"?"Manual / Seedance":"Higgsfield");
  const videoPrompt=[
    `Create a vertical 9:16 TikTok-style ${creativeStyleLabel(style)} video for ${name}.`,
    `Creative angle: ${creativeAngleLabel(angle)}.`,
    `Audience: ${audience}. Tone: ${voice}.`,
    visual?`Visual direction: ${visual}`:"",
    lock?`CHARACTER LOCK: ${lock}`:"",
    `Scene flow: ${scenes.map(s=>`${s.time} ${s.direction}`).join(" | ")}`,
    `Use natural handheld pacing, believable lighting, product-first framing, readable captions, and a native social-media feel.`,
    `Do not invent medical, financial, or performance claims. Keep the same product appearance and, when avatar mode is on, the same character identity across every scene.`
  ].filter(Boolean).join("\n");
  return {hooks,scripts,scenes,video_prompt:videoPrompt,provider};
}

app.get("/creatives",requireAuth,async(req,res)=>{
  const uid=+req.user.sub;
  const [productsQ,avatarQ,historyQ]=await Promise.all([
    pool.query(`SELECT p.id,p.name,p.category,p.price,p.commission_percent,p.sales_7d,p.sales_30d,p.affiliate_score,p.status
      FROM products p WHERE p.user_id=$1 ORDER BY p.affiliate_score DESC NULLS LAST,p.updated_at DESC LIMIT 100`,[uid]),
    pool.query("SELECT * FROM avatar_profiles WHERE user_id=$1",[uid]),
    pool.query(`SELECT cp.*,p.name AS product_name FROM creative_packs cp JOIN products p ON p.id=cp.product_id
      WHERE cp.user_id=$1 ORDER BY cp.created_at DESC LIMIT 10`,[uid])
  ]);
  const avatar=avatarQ.rows[0]||null;
  const productOptions=productsQ.rows.map(p=>`<option value="${p.id}">${esc(p.name)} — ${Number(p.affiliate_score||0).toFixed(0)}/100</option>`).join("");
  const history=historyQ.rows.length?historyQ.rows.map(x=>`<tr><td><a href="/creatives/${x.id}"><b>${esc(x.product_name)}</b></a></td><td>${esc(creativeAngleLabel(x.angle))}</td><td>${esc(creativeStyleLabel(x.style))}</td><td>${x.use_avatar?"Avatar":"No avatar"}</td><td>${esc(x.provider||"")}</td><td>${new Date(x.created_at).toLocaleString()}</td></tr>`).join(""):`<tr><td colspan="6" class="muted">No creative packs yet.</td></tr>`;
  res.send(shell({title:"Creative Studio",user:req.user,active:"creatives",body:`
  <div class="header"><div><div class="kicker">Execution Layer</div><h2>Creative Studio</h2><p>Turn a scored product into hooks, scripts, scenes and a provider-ready video brief.</p></div></div>
  <section class="hero">
    <div class="card"><div class="cardpad"><div class="kicker">1. Product</div><h3>Choose what to promote</h3><p class="muted">Your highest-scoring products are listed first.</p></div></div>
    <div class="card"><div class="cardpad"><div class="kicker">2. Identity</div><h3>${avatar?esc(avatar.avatar_name||"Saved avatar"):"No avatar saved"}</h3><p class="muted">${avatar?`Default generator: ${esc(avatar.generator||"Higgsfield")}`:`Create an avatar profile first, or generate faceless creative.`}</p></div></div>
  </section>
  <section class="card"><div class="head">Generate Creative Pack</div><div class="cardpad">
    ${productsQ.rows.length?`<form method="post" action="/creatives/generate"><input type="hidden" name="_csrf" value="${esc(req.user.csrf)}">
      <div class="grid2">
        <div>
          <div class="field"><label>Product</label><select name="product_id" required>${productOptions}</select></div>
          <div class="field"><label>Creative angle</label><select name="angle">
            <option value="problem_solution">Problem → Solution</option><option value="before_after">Before → After</option><option value="demo_proof">Demo / Proof</option>
            <option value="curiosity">Curiosity / Pattern Interrupt</option><option value="testimonial">Testimonial / Personal Story</option><option value="comparison">Comparison / Why This One</option>
          </select></div>
        </div>
        <div>
          <div class="field"><label>Video style</label><select name="style">
            <option value="ugc_direct">Direct-to-camera UGC</option><option value="demo">Product demo</option><option value="testimonial">Testimonial</option><option value="voiceover">Voiceover + B-roll</option><option value="faceless">Faceless / product-only</option>
          </select></div>
          <div class="field"><label>Avatar mode</label><select name="use_avatar">
            <option value="1" ${avatar?"":"disabled"}>Use My Avatar${avatar?` — ${esc(avatar.avatar_name||"saved profile")}`:" (create one first)"}</option>
            <option value="0">Off — faceless / generic creator</option>
          </select></div>
        </div>
      </div>
      <div class="actions"><button class="btn primary">Generate Creative Pack</button><a class="btn" href="/avatar">Edit My Avatar</a></div>
    </form>`:`<div class="empty">Add or import a product first, then return here to generate creative.</div>`}
  </div></section>
  <section class="card" style="margin-top:20px"><div class="head">Recent Creative Packs</div><div class="tablewrap"><table><thead><tr><th>Product</th><th>Angle</th><th>Style</th><th>Identity</th><th>Provider</th><th>Created</th></tr></thead><tbody>${history}</tbody></table></div></section>
  `}));
});

app.post("/creatives/generate",requireAuth,requireCsrf,async(req,res)=>{
  const uid=+req.user.sub;
  const productId=Number(req.body.product_id);
  if(!Number.isInteger(productId)||productId<=0)return res.status(400).send("Invalid product.");
  const angle=["problem_solution","before_after","demo_proof","curiosity","testimonial","comparison"].includes(req.body.angle)?req.body.angle:"problem_solution";
  const style=["ugc_direct","demo","testimonial","voiceover","faceless"].includes(req.body.style)?req.body.style:"ugc_direct";
  const useAvatar=String(req.body.use_avatar)==="1";
  const [pq,aq]=await Promise.all([
    pool.query("SELECT * FROM products WHERE id=$1 AND user_id=$2",[productId,uid]),
    pool.query("SELECT * FROM avatar_profiles WHERE user_id=$1",[uid])
  ]);
  const product=pq.rows[0];
  if(!product)return res.status(404).send("Product not found.");
  const avatar=aq.rows[0]||null;
  const pack=buildCreativePack(product,avatar,{angle,style,useAvatar:useAvatar&&!!avatar});
  const ins=await pool.query(`INSERT INTO creative_packs(user_id,product_id,use_avatar,angle,style,hooks,scripts,scenes,video_prompt,provider)
    VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10) RETURNING id`,
    [uid,productId,useAvatar&&!!avatar,angle,style,JSON.stringify(pack.hooks),JSON.stringify(pack.scripts),JSON.stringify(pack.scenes),pack.video_prompt,pack.provider]);
  res.redirect(`/creatives/${ins.rows[0].id}`);
});

app.get("/creatives/:id",requireAuth,async(req,res)=>{
  const uid=+req.user.sub,id=Number(req.params.id);
  if(!Number.isInteger(id))return res.status(404).send("Not found.");
  const [q,jq]=await Promise.all([
    pool.query(`SELECT cp.*,p.name AS product_name,p.affiliate_score,p.category,p.price,p.commission_percent
      FROM creative_packs cp JOIN products p ON p.id=cp.product_id WHERE cp.id=$1 AND cp.user_id=$2`,[id,uid]),
    pool.query(`SELECT * FROM video_jobs WHERE creative_pack_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 10`,[id,uid])
  ]);
  const c=q.rows[0]; if(!c)return res.status(404).send("Creative pack not found.");
  const hooks=Array.isArray(c.hooks)?c.hooks:JSON.parse(c.hooks||"[]");
  const scripts=Array.isArray(c.scripts)?c.scripts:JSON.parse(c.scripts||"[]");
  const scenes=Array.isArray(c.scenes)?c.scenes:JSON.parse(c.scenes||"[]");
  const copyBtn=(label,target)=>`<button class="btn" type="button" onclick="copyText('${target}',this)">${label}</button>`;
  const jobs=jq.rows.length?jq.rows.map(j=>`<tr><td>#${j.id}</td><td>${esc(j.provider)}</td><td><span class="pill ${j.status==="completed"?"winner":j.status==="failed"?"testing":"new"}">${esc(j.status)}</span></td><td>${j.video_url?`<a href="${esc(j.video_url)}" target="_blank" rel="noopener">Open video</a>`:"—"}</td><td>${j.error_message?esc(j.error_message):"—"}</td><td><a href="/video-jobs/${j.id}" class="btn">View</a></td></tr>`).join(""):`<tr><td colspan="6" class="muted">No video jobs yet.</td></tr>`;
  res.send(shell({title:"Creative Pack",user:req.user,active:"creatives",body:`
    <script>
      async function copyText(id,btn){
        const el=document.getElementById(id); if(!el)return;
        const text=("value" in el)?el.value:el.innerText;
        try{await navigator.clipboard.writeText(text);const old=btn.textContent;btn.textContent="Copied ✓";setTimeout(()=>btn.textContent=old,1200);}
        catch(e){window.prompt("Copy this text:",text);}
      }
    </script>
    <div class="header"><div><div class="kicker">${esc(creativeAngleLabel(c.angle))}</div><h2>${esc(c.product_name)} Creative Pack</h2><p>${esc(creativeStyleLabel(c.style))} · ${c.use_avatar?"My Avatar":"No avatar"} · ${esc(c.provider||"")}</p></div><div class="actions"><a class="btn" href="/creatives">New Pack</a><form method="post" action="/creatives/${c.id}/regenerate" style="display:inline"><input type="hidden" name="_csrf" value="${esc(req.user.csrf)}"><button class="btn">Regenerate</button></form></div></div>
    <section class="card"><div class="head">5 Hooks <span style="float:right">${copyBtn("Copy all hooks","hooks-all")}</span></div><div class="cardpad"><div id="hooks-all" style="display:none">${hooks.map((h,i)=>`${i+1}. ${esc(h)}`).join("\n")}</div>${hooks.map((h,i)=>`<div class="card" style="margin-bottom:10px"><div class="cardpad"><div class="actions" style="justify-content:space-between"><div class="kicker">Hook ${i+1}</div>${copyBtn("Copy",`hook-${i}`)}</div><b id="hook-${i}">${esc(h)}</b></div></div>`).join("")}</div></section>
    <div class="header" style="margin-top:20px"><div><h3>Scripts</h3><p>Three lengths for rapid testing.</p></div></div>
    <section class="hero">${scripts.map((s,i)=>`<div class="card"><div class="cardpad"><div class="actions" style="justify-content:space-between"><div class="kicker">${esc(s.label)}</div>${copyBtn("Copy",`script-${i}`)}</div><p id="script-${i}">${esc(s.text)}</p></div></div>`).join("")}</section>
    <section class="card" style="margin-top:20px"><div class="head">Scene Breakdown</div><div class="tablewrap"><table><thead><tr><th>Scene</th><th>Time</th><th>Shot</th><th>Direction</th></tr></thead><tbody>${scenes.map(s=>`<tr><td>${s.scene}</td><td>${esc(s.time)}</td><td>${esc(s.shot)}</td><td>${esc(s.direction)}</td></tr>`).join("")}</tbody></table></div></section>
    <section class="card" style="margin-top:20px"><div class="head">${esc(c.provider||"Video")} Prompt <span style="float:right">${copyBtn("Copy prompt","video-prompt")}</span></div><div class="cardpad"><textarea id="video-prompt" style="min-height:320px" readonly>${esc(c.video_prompt)}</textarea><p class="muted">This prompt can now be submitted to the video connector below.</p></div></section>
    <section class="card" style="margin-top:20px"><div class="head">Generate Video</div><div class="cardpad">
      <form method="post" action="/creatives/${c.id}/video"><input type="hidden" name="_csrf" value="${esc(req.user.csrf)}">
        <div class="grid2">
          <div class="field"><label>Provider</label><select name="provider"><option>Higgsfield</option><option>Seedance</option><option>HeyGen</option></select></div>
          <div class="field"><label>Delivery</label><input value="${process.env.N8N_VIDEO_WEBHOOK?"n8n connector configured":"n8n connector not configured"}" disabled></div>
        </div>
        <div class="actions"><button class="btn primary" ${process.env.N8N_VIDEO_WEBHOOK?"":"disabled"}>Generate Video</button><a class="btn" href="/settings">Connector Settings</a></div>
        ${process.env.N8N_VIDEO_WEBHOOK?"":`<p class="muted">Add <code>N8N_VIDEO_WEBHOOK</code> to the AffiliateLab app environment variables before video submission is enabled.</p>`}
      </form>
    </div></section>
    <section class="card" style="margin-top:20px"><div class="head">Video Jobs</div><div class="tablewrap"><table><thead><tr><th>Job</th><th>Provider</th><th>Status</th><th>Output</th><th>Error</th><th></th></tr></thead><tbody>${jobs}</tbody></table></div></section>
  `}));
});

app.post("/creatives/:id/regenerate",requireAuth,requireCsrf,async(req,res)=>{
  const uid=+req.user.sub,id=Number(req.params.id);
  const q=await pool.query(`SELECT cp.*,p.* FROM creative_packs cp JOIN products p ON p.id=cp.product_id WHERE cp.id=$1 AND cp.user_id=$2`,[id,uid]);
  const row=q.rows[0]; if(!row)return res.status(404).send("Creative pack not found.");
  const aq=await pool.query("SELECT * FROM avatar_profiles WHERE user_id=$1",[uid]);
  const pack=buildCreativePack(row,aq.rows[0]||null,{angle:row.angle,style:row.style,useAvatar:row.use_avatar});
  await pool.query(`UPDATE creative_packs SET hooks=$1::jsonb,scripts=$2::jsonb,scenes=$3::jsonb,video_prompt=$4,provider=$5 WHERE id=$6 AND user_id=$7`,
    [JSON.stringify(pack.hooks),JSON.stringify(pack.scripts),JSON.stringify(pack.scenes),pack.video_prompt,pack.provider,id,uid]);
  res.redirect(`/creatives/${id}`);
});

app.post("/creatives/:id/video",requireAuth,requireCsrf,async(req,res)=>{
  const uid=+req.user.sub,id=Number(req.params.id);
  const provider=["Higgsfield","Seedance","HeyGen"].includes(req.body.provider)?req.body.provider:"Higgsfield";
  const webhook=String(process.env.N8N_VIDEO_WEBHOOK||"").trim();
  if(!webhook)return res.status(503).send("Video connector is not configured. Add N8N_VIDEO_WEBHOOK.");
  const [cq,aq]=await Promise.all([
    pool.query(`SELECT cp.*,p.name AS product_name,p.product_url,p.category,p.price,p.commission_percent
      FROM creative_packs cp JOIN products p ON p.id=cp.product_id WHERE cp.id=$1 AND cp.user_id=$2`,[id,uid]),
    pool.query("SELECT * FROM avatar_profiles WHERE user_id=$1",[uid])
  ]);
  const c=cq.rows[0]; if(!c)return res.status(404).send("Creative pack not found.");
  const avatar=aq.rows[0]||null;
  const payload={
    event:"video.generate",
    creative_pack_id:c.id,
    user_id:uid,
    provider,
    product:{name:c.product_name,url:c.product_url,category:c.category,price:c.price,commission_percent:c.commission_percent},
    creative:{angle:c.angle,style:c.style,use_avatar:c.use_avatar,hooks:c.hooks,scripts:c.scripts,scenes:c.scenes,video_prompt:c.video_prompt},
    avatar:c.use_avatar&&avatar?{
      name:avatar.avatar_name,presentation:avatar.presentation,age_range:avatar.age_range,visual_description:avatar.visual_description,
      hair_skin_clothing:avatar.hair_skin_clothing,voice_tone:avatar.voice_tone,accent:avatar.accent,target_audience:avatar.target_audience,
      niche:avatar.niche,video_style:avatar.video_style,generator:avatar.generator,character_id:avatar.character_id,
      reference_urls:String(avatar.reference_urls||"").split(/\r?\n/).filter(Boolean),character_lock_prompt:avatar.character_lock_prompt
    }:null,
    callback_url:`${APP_URL}/api/video-jobs/CALLBACK_ID/callback`
  };
  const iq=await pool.query(`INSERT INTO video_jobs(user_id,creative_pack_id,provider,status,request_payload) VALUES($1,$2,$3,'queued',$4::jsonb) RETURNING id`,
    [uid,id,provider,JSON.stringify(payload)]);
  const jobId=iq.rows[0].id;
  payload.video_job_id=jobId;
  payload.callback_url=`${APP_URL}/api/video-jobs/${jobId}/callback`;
  const secret=String(process.env.VIDEO_CALLBACK_SECRET||"").trim();
  const headers={"content-type":"application/json"};
  if(secret)headers["x-affiliatelab-secret"]=secret;
  try{
    const r=await fetch(webhook,{method:"POST",headers,body:JSON.stringify(payload),signal:AbortSignal.timeout(15000)});
    const text=await r.text();
    let body={}; try{body=text?JSON.parse(text):{}}catch{body={raw:text.slice(0,5000)}}
    if(!r.ok){
      await pool.query("UPDATE video_jobs SET status='failed',response_payload=$1::jsonb,error_message=$2,updated_at=NOW() WHERE id=$3",[JSON.stringify(body),`Connector HTTP ${r.status}`,jobId]);
    }else{
      const ext=String(body.job_id||body.id||body.external_job_id||"").slice(0,500);
      const status=String(body.status||"submitted").toLowerCase();
      const videoUrl=String(body.video_url||body.url||"").slice(0,5000);
      await pool.query("UPDATE video_jobs SET status=$1,external_job_id=$2,response_payload=$3::jsonb,video_url=$4,updated_at=NOW() WHERE id=$5",
        [videoUrl?"completed":status,ext,JSON.stringify(body),videoUrl,jobId]);
    }
  }catch(e){
    await pool.query("UPDATE video_jobs SET status='failed',error_message=$1,updated_at=NOW() WHERE id=$2",[String(e.message||e).slice(0,3000),jobId]);
  }
  res.redirect(`/video-jobs/${jobId}`);
});

app.get("/video-jobs/:id",requireAuth,async(req,res)=>{
  const uid=+req.user.sub,id=Number(req.params.id);
  const q=await pool.query(`SELECT vj.*,cp.video_prompt,p.name AS product_name
    FROM video_jobs vj JOIN creative_packs cp ON cp.id=vj.creative_pack_id JOIN products p ON p.id=cp.product_id
    WHERE vj.id=$1 AND vj.user_id=$2`,[id,uid]);
  const j=q.rows[0]; if(!j)return res.status(404).send("Video job not found.");
  res.send(shell({title:"Video Job",user:req.user,active:"creatives",body:`
    <div class="header"><div><div class="kicker">Video Job #${j.id}</div><h2>${esc(j.product_name)}</h2><p>${esc(j.provider)} · ${esc(j.status)}</p></div><div class="actions"><a class="btn" href="/creatives/${j.creative_pack_id}">Back to Creative Pack</a></div></div>
    <section class="hero"><div class="card"><div class="cardpad"><div class="kicker">Status</div><h3>${esc(j.status)}</h3><p class="muted">${j.external_job_id?`External job: ${esc(j.external_job_id)}`:"Waiting for provider job ID."}</p></div></div>
    <div class="card"><div class="cardpad"><div class="kicker">Provider</div><h3>${esc(j.provider)}</h3><p class="muted">Created ${new Date(j.created_at).toLocaleString()}</p></div></div></section>
    ${j.video_url?`<section class="card" style="margin-top:20px"><div class="head">Finished Video</div><div class="cardpad"><video controls style="width:100%;max-width:520px;border-radius:12px" src="${esc(j.video_url)}"></video><div class="actions" style="margin-top:12px"><a class="btn primary" target="_blank" rel="noopener" href="${esc(j.video_url)}">Open Video</a></div></div></section>`:""}
    ${j.error_message?`<section class="card" style="margin-top:20px"><div class="head">Error</div><div class="cardpad"><p>${esc(j.error_message)}</p></div></section>`:""}
    <script>setTimeout(()=>{if(${JSON.stringify(!["completed","failed"].includes(j.status))})location.reload()},10000)</script>
  `}));
});

app.post("/api/video-jobs/:id/callback",express.json({limit:"2mb"}),async(req,res)=>{
  const id=Number(req.params.id); if(!Number.isInteger(id))return res.status(400).json({ok:false});
  const expected=String(process.env.VIDEO_CALLBACK_SECRET||"").trim();
  if(expected && req.get("x-affiliatelab-secret")!==expected)return res.status(401).json({ok:false,error:"unauthorized"});
  const q=await pool.query("SELECT id FROM video_jobs WHERE id=$1",[id]); if(!q.rows[0])return res.status(404).json({ok:false});
  const status=String(req.body.status||"").toLowerCase();
  const normalized=["queued","submitted","processing","completed","failed"].includes(status)?status:"processing";
  const videoUrl=String(req.body.video_url||req.body.url||"").trim().slice(0,5000);
  const thumb=String(req.body.thumbnail_url||"").trim().slice(0,5000);
  const ext=String(req.body.job_id||req.body.external_job_id||"").trim().slice(0,500);
  const err=String(req.body.error||req.body.error_message||"").trim().slice(0,3000);
  await pool.query(`UPDATE video_jobs SET status=$1,video_url=$2,thumbnail_url=$3,external_job_id=CASE WHEN $4<>'' THEN $4 ELSE external_job_id END,
    error_message=$5,response_payload=$6::jsonb,updated_at=NOW() WHERE id=$7`,
    [videoUrl?"completed":normalized,videoUrl,thumb,ext,err,JSON.stringify(req.body||{}),id]);
  res.json({ok:true,video_job_id:id});
});
app.get("/settings",requireAuth,(req,res)=>res.send(shell({title:"Settings",user:req.user,active:"settings",body:`<div class="header"><div><h2>Settings</h2><p>Creator Pro account and integrations.</p></div></div><section class="card"><div class="cardpad"><b>Plan</b><p>Creator Pro — planned launch price: $49/month</p><b>n8n webhook</b><p class="muted">${process.env.N8N_PRODUCT_WEBHOOK?"Configured":"Not configured yet"}</p><b>Public app URL</b><p>${esc(APP_URL)}</p></div></section>`})));

app.use((err,req,res,next)=>{console.error(err);res.status(500).send(isProd?"Something went wrong.":`<pre>${esc(err.stack)}</pre>`);});
app.listen(PORT,"0.0.0.0",()=>console.log(`AffiliateLab listening on ${PORT}`));
