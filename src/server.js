
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
app.use(express.json({limit:"100kb"}));
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
function requireAuth(req,res,next){const s=sessionFrom(req);if(!s)return res.redirect("/login");req.user=s;next();}
function requireCsrf(req,res,next){const s=sessionFrom(req),t=req.body?._csrf||req.get("x-csrf-token");if(!s||!t||t!==s.csrf)return res.status(403).send("Invalid CSRF token");req.user=s;next();}

function shell({title,user,active="",body}){
  const nav=(u,l,k,i)=>`<a class="${active===k?"active":""}" href="${u}">${i} ${l}</a>`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · AffiliateLab</title><link rel="stylesheet" href="/static/app.css"></head><body>
  <div class="app"><aside class="sidebar"><div class="brand"><div class="logo">⚗</div><div><h1>AffiliateLab</h1><small>Creator Intelligence</small></div></div>
  <nav class="nav">${nav("/dashboard","Dashboard","dashboard","▣")}${nav("/products","My Products","products","▤")}${nav("/products/new","Add Product","new","＋")}${nav("/opportunities","Top Opportunities","opportunities","▥")}${nav("/avatar","My Avatar","avatar","◉")}${nav("/creatives","Creative Studio","creatives","▻")}${nav("/settings","Settings","settings","⚙")}</nav>
  <div class="sidebar-bottom"><div class="userbox"><b>${esc(user.name||"Creator Pro")}</b><div class="email">${esc(user.email)}</div><a class="logout" href="/logout">Sign out</a></div></div></aside><main class="main">${body}</main></div></body></html>`;
}
function authPage(title,content){
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · AffiliateLab</title><link rel="stylesheet" href="/static/app.css"></head><body class="authbody"><div class="authcard"><div class="authbrand"><div class="logo">⚗</div><h1>AffiliateLab</h1><div class="muted">AI-powered affiliate operating system</div></div>${content}</div></body></html>`;
}
function scoreProduct(p){
  const price=+p.price||0,comm=+p.commission_percent||0,s7=+p.sales_7d||0,s30=+p.sales_30d||0,creators=+p.creator_count||0,videos=+p.video_count||0;
  const salesMomentum=Math.max(0,Math.min(100,Math.round((s7*4/Math.max(1,s30))*70+Math.min(30,s7/100))));
  const competition=Math.max(5,Math.min(100,Math.round(100-(Math.min(60,creators/50)+Math.min(35,videos/150)))));
  const commission=Math.min(100,Math.round(comm*4));
  const priceScore=price<=15?95:price<=40?90:price<=70?78:price<=120?62:45;
  const visual=82,problem=78,impulse=Math.round((priceScore+commission)/2);
  const total=Math.max(0,Math.min(100,Math.round(salesMomentum*.24+commission*.20+competition*.16+visual*.16+impulse*.14+problem*.10)));
  const recommendation=total>=80?"PRIORITY TEST":total>=68?"TEST":total>=55?"WATCH":"PASS";
  return {salesMomentum,competition,commission,visual,problem,impulse,total,recommendation};
}

async function migrate(){
  await pool.query(`
  CREATE TABLE IF NOT EXISTS users(
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'creator_pro',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  ALTER TABLE products ADD COLUMN IF NOT EXISTS user_id BIGINT REFERENCES users(id) ON DELETE CASCADE;
  ALTER TABLE products ADD COLUMN IF NOT EXISTS description TEXT;
  ALTER TABLE products ADD COLUMN IF NOT EXISTS affiliate_network TEXT DEFAULT 'TikTok Shop';
  ALTER TABLE products ADD COLUMN IF NOT EXISTS tracking_link TEXT;
  ALTER TABLE products ADD COLUMN IF NOT EXISTS revenue_30d NUMERIC(14,2) DEFAULT 0;
  ALTER TABLE products ADD COLUMN IF NOT EXISTS views_30d BIGINT DEFAULT 0;
  ALTER TABLE products ADD COLUMN IF NOT EXISTS notes TEXT;
  ALTER TABLE products DROP CONSTRAINT IF EXISTS products_product_url_unique;
  CREATE UNIQUE INDEX IF NOT EXISTS products_user_url_unique ON products(user_id,product_url)
    WHERE user_id IS NOT NULL AND product_url IS NOT NULL;
  CREATE INDEX IF NOT EXISTS products_user_score_idx ON products(user_id,affiliate_score DESC NULLS LAST);
  `);
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
  const q=await pool.query("SELECT id,name,email,password_hash FROM users WHERE email=$1",[email]);const u=q.rows[0];
  if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).send(authPage("Sign in",`<div class="flash err">Email or password is incorrect.</div><div class="authfoot"><a href="/login">Try again</a></div>`));
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
  res.send(shell({title:"Dashboard",user:req.user,active:"dashboard",body:`<div class="header"><div><div class="kicker">Creator Pro</div><h2>Dashboard</h2><p>Find products, score opportunities, create content, scale winners.</p></div><a class="btn primary" href="/products/new">＋ Add Product</a></div>
  <section class="stats"><div class="card stat"><div class="label">Products Tracked</div><div class="value">${s.total}</div></div><div class="card stat"><div class="label">Testing</div><div class="value">${s.testing}</div></div><div class="card stat"><div class="label">Winners</div><div class="value green">${s.winners}</div></div><div class="card stat"><div class="label">Est. Commission</div><div class="value">${money(s.commission)}</div></div></section>
  <section class="hero"><div class="card"><div class="cardpad"><div class="kicker">The AffiliateLab Loop</div><h3>Research → Score → Create → Test → Scale</h3><p>Kalodata supplies the research. AffiliateLab becomes the decision and execution layer.</p><div class="actions"><a class="btn primary" href="/products/new">Score a Product</a><a class="btn" href="/opportunities">View Opportunities</a></div></div></div><div class="card"><div class="cardpad"><div class="muted">Best current opportunity</div><div class="scorebig">${tq.rows[0]?.affiliate_score??"—"}</div><b>${esc(tq.rows[0]?.name||"Add your first product")}</b></div></div></section>
  <section class="card"><div class="head">Top Products</div><div class="tablewrap">${rows?`<table class="table"><thead><tr><th>Product</th><th>Category</th><th>Price</th><th>Commission</th><th>Score</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`:`<div class="empty">No products yet. Add one to begin.</div>`}</div></section>`}));
});

app.get("/products",requireAuth,async(req,res)=>{
  const q=await pool.query(`SELECT id,name,category,price,commission_percent,sales_30d,creator_count,affiliate_score,status FROM products WHERE user_id=$1 ORDER BY updated_at DESC`,[+req.user.sub]);
  const rows=q.rows.map(p=>`<tr><td><a href="/products/${p.id}"><b>${esc(p.name)}</b></a></td><td>${esc(p.category||"—")}</td><td>${money(p.price)}</td><td>${+p.commission_percent||0}%</td><td>${num(p.sales_30d)}</td><td>${num(p.creator_count)}</td><td><b>${p.affiliate_score??"—"}</b></td><td><span class="pill ${esc(p.status)}">${esc(p.status)}</span></td></tr>`).join("");
  res.send(shell({title:"Products",user:req.user,active:"products",body:`<div class="header"><div><h2>My Products</h2><p>Your private opportunity database.</p></div><a class="btn primary" href="/products/new">＋ Add Product</a></div><section class="card"><div class="tablewrap">${rows?`<table class="table"><thead><tr><th>Product</th><th>Category</th><th>Price</th><th>Commission</th><th>30d Sales</th><th>Creators</th><th>Score</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`:`<div class="empty">No products yet.</div>`}</div></section>`}));
});

function productForm(csrf){
 return `<form method="post" action="/products"><input type="hidden" name="_csrf" value="${esc(csrf)}"><div class="layout">
 <section class="card"><div class="head">🏷 Product Information</div><div class="cardpad"><div class="grid2"><div>
 <div class="field"><label>Product Name *</label><input name="name" required></div><div class="field"><label>Product URL *</label><input name="product_url" required></div><div class="field"><label>Category / Niche</label><input name="category"></div><div class="field"><label>Description</label><textarea name="description"></textarea></div>
 <div class="moneyrow"><div class="field"><label>Price USD</label><input id="price" name="price" type="number" step=".01" value="29.99"></div><div class="field"><label>Commission %</label><input id="commission_percent" name="commission_percent" type="number" step=".1" value="20"></div><div class="field"><label>Commission $</label><input id="commission_amount" disabled></div></div>
 <div class="field"><label>Affiliate Network</label><select name="affiliate_network"><option>TikTok Shop</option><option>Amazon</option><option>ClickBank</option><option>Other</option></select></div><div class="field"><label>Your Affiliate Link</label><input name="tracking_link"></div>
 </div><div><div class="field"><label>Sales — 7 days</label><input id="sales_7d" name="sales_7d" type="number" value="0"></div><div class="field"><label>Sales — 30 days</label><input id="sales_30d" name="sales_30d" type="number" value="0"></div><div class="field"><label>Revenue — 30 days</label><input name="revenue_30d" type="number" step=".01" value="0"></div><div class="field"><label>Creator count</label><input id="creator_count" name="creator_count" type="number" value="0"></div><div class="field"><label>Video count</label><input id="video_count" name="video_count" type="number" value="0"></div><div class="field"><label>Views — 30 days</label><input name="views_30d" type="number" value="0"></div><div class="field"><label>Status</label><select name="status"><option>new</option><option>testing</option><option>winner</option><option>rejected</option></select></div><div class="field"><label>Private Notes</label><textarea name="notes"></textarea></div></div></div><div class="actions"><button class="btn primary">✦ Save & Analyze</button><a class="btn" href="/products">Cancel</a></div></div></section>
 <aside><section class="card score"><div style="font-weight:800;margin-bottom:16px">Opportunity Score Preview</div><div class="scoretop"><div class="ring" id="ring" style="--score:70"><div class="ringinner"><strong id="score">70</strong><div><span>/100</span></div></div></div><div><div class="badge" id="potential">TEST</div><div class="muted">Final score is calculated securely on the server.</div></div></div><div id="metrics"></div></section><section class="card" style="margin-top:16px"><div class="cardpad"><b>Kalodata workflow</b><p class="muted">For V1, paste metrics from Kalodata. CSV/API import comes next.</p></div></section></aside></div></form>
 <script>const $=id=>document.getElementById(id),n=id=>Number($(id)?.value||0);function c(){const p=n("price"),co=n("commission_percent"),s7=n("sales_7d"),s30=n("sales_30d"),cr=n("creator_count"),v=n("video_count"),sm=Math.max(0,Math.min(100,Math.round((s7*4/Math.max(1,s30))*70+Math.min(30,s7/100)))),comp=Math.max(5,Math.min(100,Math.round(100-(Math.min(60,cr/50)+Math.min(35,v/150))))),cs=Math.min(100,Math.round(co*4)),ps=p<=15?95:p<=40?90:p<=70?78:p<=120?62:45,vis=82,prob=78,imp=Math.round((ps+cs)/2),t=Math.max(0,Math.min(100,Math.round(sm*.24+cs*.20+comp*.16+vis*.16+imp*.14+prob*.10)));$("score").textContent=t;$("ring").style.setProperty("--score",t);$("potential").textContent=t>=80?"PRIORITY TEST":t>=68?"TEST":t>=55?"WATCH":"PASS";$("commission_amount").value=(p*co/100).toFixed(2);const r=[["Sales Momentum",sm],["Competition",comp],["Commission",cs],["Visual Demo",vis],["Impulse",imp]];$("metrics").innerHTML=r.map(x=>'<div class="metric"><div class="metricrow"><span>'+x[0]+'</span><b>'+x[1]+'/100</b></div><div class="bar"><i style="width:'+x[1]+'%"></i></div></div>').join("")}document.querySelectorAll("input,select").forEach(x=>x.addEventListener("input",c));c()</script>`;
}
app.get("/products/new",requireAuth,(req,res)=>res.send(shell({title:"Add Product",user:req.user,active:"new",body:`<div class="header"><div><h2>Add New Product</h2><p>Enter Kalodata/TikTok Shop metrics and let AffiliateLab prioritize the test.</p></div></div>${productForm(req.user.csrf)}`})));

app.post("/products",requireAuth,requireCsrf,async(req,res)=>{
  const uid=+req.user.sub,b=req.body,p={name:String(b.name||"").trim().slice(0,250),product_url:String(b.product_url||"").trim().slice(0,2000),category:String(b.category||"").trim().slice(0,150),description:String(b.description||"").trim().slice(0,3000),price:+b.price||0,commission_percent:+b.commission_percent||0,sales_7d:+b.sales_7d||0,sales_30d:+b.sales_30d||0,revenue_30d:+b.revenue_30d||0,creator_count:+b.creator_count||0,video_count:+b.video_count||0,views_30d:+b.views_30d||0,affiliate_network:String(b.affiliate_network||"TikTok Shop"),tracking_link:String(b.tracking_link||"").trim().slice(0,2000),notes:String(b.notes||"").trim().slice(0,5000),status:["new","testing","winner","rejected"].includes(b.status)?b.status:"new"};
  if(!p.name||!p.product_url)return res.status(400).send("Name and product URL are required.");
  const sc=scoreProduct(p),commissionAmount=p.price*p.commission_percent/100;
  const q=await pool.query(`INSERT INTO products(user_id,name,product_url,category,description,price,commission_percent,commission_amount,sales_7d,sales_30d,revenue_30d,creator_count,video_count,views_30d,affiliate_network,tracking_link,notes,affiliate_score,status,updated_at)
  VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,NOW())
  ON CONFLICT (user_id,product_url) WHERE user_id IS NOT NULL AND product_url IS NOT NULL DO UPDATE SET name=EXCLUDED.name,category=EXCLUDED.category,description=EXCLUDED.description,price=EXCLUDED.price,commission_percent=EXCLUDED.commission_percent,commission_amount=EXCLUDED.commission_amount,sales_7d=EXCLUDED.sales_7d,sales_30d=EXCLUDED.sales_30d,revenue_30d=EXCLUDED.revenue_30d,creator_count=EXCLUDED.creator_count,video_count=EXCLUDED.video_count,views_30d=EXCLUDED.views_30d,affiliate_network=EXCLUDED.affiliate_network,tracking_link=EXCLUDED.tracking_link,notes=EXCLUDED.notes,affiliate_score=EXCLUDED.affiliate_score,status=EXCLUDED.status,updated_at=NOW() RETURNING id`,
  [uid,p.name,p.product_url,p.category,p.description,p.price,p.commission_percent,commissionAmount,p.sales_7d,p.sales_30d,p.revenue_30d,p.creator_count,p.video_count,p.views_30d,p.affiliate_network,p.tracking_link,p.notes,sc.total,p.status]);
  const id=q.rows[0].id;
  await pool.query(`INSERT INTO product_scores(product_id,competition_score,visual_demo_score,impulse_score,problem_desire_score,sales_momentum_score,commission_score,total_score,recommendation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[id,sc.competition,sc.visual,sc.impulse,sc.problem,sc.salesMomentum,sc.commission,sc.total,sc.recommendation]);
  if(process.env.N8N_PRODUCT_WEBHOOK)fetch(process.env.N8N_PRODUCT_WEBHOOK,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({event:"product.saved",user_id:uid,product_id:id,...p,score:sc})}).catch(e=>console.error("n8n webhook:",e.message));
  res.redirect(`/products/${id}?saved=1`);
});

app.get("/products/:id",requireAuth,async(req,res)=>{
  const q=await pool.query(`SELECT p.*,ps.competition_score,ps.visual_demo_score,ps.impulse_score,ps.problem_desire_score,ps.sales_momentum_score,ps.commission_score,ps.recommendation FROM products p LEFT JOIN LATERAL(SELECT * FROM product_scores WHERE product_id=p.id ORDER BY scored_at DESC LIMIT 1)ps ON true WHERE p.id=$1 AND p.user_id=$2`,[+req.params.id,+req.user.sub]);const p=q.rows[0];if(!p)return res.status(404).send("Product not found");
  const m=[["Sales Momentum",p.sales_momentum_score],["Competition",p.competition_score],["Commission",p.commission_score],["Visual Demo",p.visual_demo_score],["Impulse",p.impulse_score],["Problem / Desire",p.problem_desire_score]];
  res.send(shell({title:p.name,user:req.user,active:"products",body:`${req.query.saved?'<div class="flash ok">Product saved and analyzed.</div>':""}<div class="header"><div><div class="kicker">${esc(p.recommendation||"ANALYZED")}</div><h2>${esc(p.name)}</h2><p>${esc(p.category||"Uncategorized")} · ${money(p.price)} · ${+p.commission_percent||0}% commission</p></div><a class="btn" href="/products">Back</a></div><div class="layout"><section class="card"><div class="head">Product Intelligence</div><div class="cardpad"><div class="grid2"><div><b>Product URL</b><p><a target="_blank" rel="noreferrer" href="${esc(p.product_url)}">${esc(p.product_url)}</a></p><b>Description</b><p class="muted">${esc(p.description||"—")}</p><b>Network</b><p>${esc(p.affiliate_network||"TikTok Shop")}</p></div><div><b>7-day sales</b><p>${num(p.sales_7d)}</p><b>30-day sales</b><p>${num(p.sales_30d)}</p><b>Creators</b><p>${num(p.creator_count)}</p><b>Videos</b><p>${num(p.video_count)}</p></div></div></div></section><aside><section class="card score"><div style="font-weight:800">Affiliate Opportunity Score</div><div class="scoretop" style="margin-top:16px"><div class="ring" style="--score:${+p.affiliate_score||0}"><div class="ringinner"><strong>${+p.affiliate_score||0}</strong><div><span>/100</span></div></div></div><div><div class="badge">${esc(p.recommendation||"WATCH")}</div><div class="muted">Prioritize testing; this is not a guarantee.</div></div></div>${m.map(x=>`<div class="metric"><div class="metricrow"><span>${x[0]}</span><b>${+x[1]||0}/100</b></div><div class="bar"><i style="width:${+x[1]||0}%"></i></div></div>`).join("")}</section></aside></div>`}));
});

app.get("/opportunities",requireAuth,async(req,res)=>{
  const q=await pool.query(`SELECT id,name,category,affiliate_score,status,commission_percent,sales_30d FROM products WHERE user_id=$1 ORDER BY affiliate_score DESC NULLS LAST LIMIT 50`,[+req.user.sub]);
  const rows=q.rows.map((p,i)=>`<tr><td>${i+1}</td><td><a href="/products/${p.id}"><b>${esc(p.name)}</b></a></td><td>${esc(p.category||"—")}</td><td><b>${p.affiliate_score??"—"}</b></td><td>${+p.commission_percent||0}%</td><td>${num(p.sales_30d)}</td><td><span class="pill ${esc(p.status)}">${esc(p.status)}</span></td></tr>`).join("");
  res.send(shell({title:"Top Opportunities",user:req.user,active:"opportunities",body:`<div class="header"><div><h2>Top Opportunities</h2><p>Rank products by AffiliateLab Opportunity Score.</p></div></div><section class="card"><div class="tablewrap">${rows?`<table class="table"><thead><tr><th>#</th><th>Product</th><th>Category</th><th>Score</th><th>Commission</th><th>30d Sales</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`:`<div class="empty">Add products to create your ranking.</div>`}</div></section>`}));
});
app.get("/avatar",requireAuth,(req,res)=>res.send(shell({title:"My Avatar",user:req.user,active:"avatar",body:`<div class="header"><div><h2>My Avatar</h2><p>Each creator builds and connects their own consistent AI identity.</p></div></div><section class="card"><div class="cardpad"><div class="kicker">Next module</div><h3>Avatar Identity Profile</h3><p class="muted">Store avatar name, master references, voice, platform, character ID and visual rules. AffiliateLab will use the profile whenever it generates a creative brief.</p></div></section>`})));
app.get("/creatives",requireAuth,(req,res)=>res.send(shell({title:"Creative Studio",user:req.user,active:"creatives",body:`<div class="header"><div><h2>Creative Studio</h2><p>Turn scored products into hooks, scripts and avatar-ready briefs.</p></div></div><section class="card"><div class="empty">Creative generation is the next module.</div></section>`})));
app.get("/settings",requireAuth,(req,res)=>res.send(shell({title:"Settings",user:req.user,active:"settings",body:`<div class="header"><div><h2>Settings</h2><p>Creator Pro account and integrations.</p></div></div><section class="card"><div class="cardpad"><b>Plan</b><p>Creator Pro — planned launch price: $49/month</p><b>n8n webhook</b><p class="muted">${process.env.N8N_PRODUCT_WEBHOOK?"Configured":"Not configured yet"}</p><b>Public app URL</b><p>${esc(APP_URL)}</p></div></section>`})));

app.use((err,req,res,next)=>{console.error(err);res.status(500).send(isProd?"Something went wrong.":`<pre>${esc(err.stack)}</pre>`);});
app.listen(PORT,"0.0.0.0",()=>console.log(`AffiliateLab listening on ${PORT}`));
