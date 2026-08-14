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

app.get("/avatar",requireAuth,(req,res)=>res.send(shell({title:"My Avatar",user:req.user,active:"avatar",body:`<div class="header"><div><h2>My Avatar</h2><p>Each creator builds and connects their own consistent AI identity.</p></div></div><section class="card"><div class="cardpad"><div class="kicker">Next module</div><h3>Avatar Identity Profile</h3><p class="muted">Store avatar name, master references, voice, platform, character ID and visual rules. AffiliateLab will use the profile whenever it generates a creative brief.</p></div></section>`})));
app.get("/creatives",requireAuth,(req,res)=>res.send(shell({title:"Creative Studio",user:req.user,active:"creatives",body:`<div class="header"><div><h2>Creative Studio</h2><p>Turn scored products into hooks, scripts and avatar-ready briefs.</p></div></div><section class="card"><div class="empty">Creative generation is the next module.</div></section>`})));
app.get("/settings",requireAuth,(req,res)=>res.send(shell({title:"Settings",user:req.user,active:"settings",body:`<div class="header"><div><h2>Settings</h2><p>Creator Pro account and integrations.</p></div></div><section class="card"><div class="cardpad"><b>Plan</b><p>Creator Pro — planned launch price: $49/month</p><b>n8n webhook</b><p class="muted">${process.env.N8N_PRODUCT_WEBHOOK?"Configured":"Not configured yet"}</p><b>Public app URL</b><p>${esc(APP_URL)}</p></div></section>`})));

app.use((err,req,res,next)=>{console.error(err);res.status(500).send(isProd?"Something went wrong.":`<pre>${esc(err.stack)}</pre>`);});
app.listen(PORT,"0.0.0.0",()=>console.log(`AffiliateLab listening on ${PORT}`));
