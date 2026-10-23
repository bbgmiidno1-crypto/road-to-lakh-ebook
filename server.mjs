import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import pg from 'pg';
import {Resend} from 'resend';
import {S3Client,GetObjectCommand} from '@aws-sdk/client-s3';
import {getSignedUrl} from '@aws-sdk/s3-request-presigner';
import {z} from 'zod';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {PRICE_PAISE,safeEqual,hmac,verifyWebhook,hash,downloadSignature,validDownload,paymentMatches,offer,escapeHtml} from './lib/core.mjs';
const root=path.dirname(fileURLToPath(import.meta.url));
export const schema=`
CREATE TABLE IF NOT EXISTS orders (
 id TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', token_hash TEXT NOT NULL,
 provider_order_id TEXT UNIQUE, payment_id TEXT UNIQUE, amount INTEGER NOT NULL, currency TEXT NOT NULL DEFAULT 'INR',
 mode TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'created', created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 paid_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ, delivery_state TEXT NOT NULL DEFAULT 'not_started',
 delivery_version INTEGER NOT NULL DEFAULT 1, email_id TEXT UNIQUE, recovery_at TIMESTAMPTZ,
 recovery_count INTEGER NOT NULL DEFAULT 0, email_event_at TIMESTAMPTZ, email_event_rank INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS webhook_events (id TEXT PRIMARY KEY, provider TEXT NOT NULL, received_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS outbox (
 id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id), version INTEGER NOT NULL,
 payload JSONB, state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
 first_attempt_at TIMESTAMPTZ, next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(), email_id TEXT, last_error TEXT,
 UNIQUE(order_id,version)
);
CREATE TABLE IF NOT EXISTS admin_audit (id TEXT PRIMARY KEY, order_id TEXT NOT NULL, action TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
`;
export function makeApp({env=process.env,db=null,fetcher=fetch,mailer=null,signDownload=null,now=()=>Date.now(),siteConfig=null}={}){
 const app=express();
 const site=siteConfig||JSON.parse(fs.readFileSync(path.join(root,'site.config.json'),'utf8'));
 const contact=site.contactEmail;
 const mode=env.PAYMENT_MODE==='live'?'live':'test';
 const required=['DATABASE_URL','APP_URL','RAZORPAY_KEY_ID','RAZORPAY_KEY_SECRET','RAZORPAY_WEBHOOK_SECRET','RESEND_API_KEY','RESEND_WEBHOOK_SECRET','EMAIL_FROM','DOWNLOAD_SIGNING_SECRET','S3_ENDPOINT','S3_ACCESS_KEY_ID','S3_SECRET_ACCESS_KEY','S3_BUCKET','S3_OBJECT_KEY','ADMIN_TOKEN'];
 const missing=required.filter(x=>!env[x]);
 const policyReady=site.policiesApproved===true&&['sellerLegalName','sellerAddress','contactEmail','grievanceContact','retentionPolicy','refundPolicy','licenseTerms','taxStatement','policyEffectiveDate','deliverySupportTimeframe'].every(k=>site[k]&&!site[k].includes('[CONFIGURE'))&&z.string().email().safeParse(contact).success;
 const secretReady=[env.DOWNLOAD_SIGNING_SECRET,env.ADMIN_TOKEN,env.RAZORPAY_WEBHOOK_SECRET].every(v=>v&&v.length>=32);
 const keyMode=env.RAZORPAY_KEY_ID?.startsWith(mode==='live'?'rzp_live_':'rzp_test_');
 const flagsOn=env.PAYMENT_ENABLED==='true'&&env.DELIVERY_ENABLED==='true';
 const configured=!!db&&missing.length===0&&policyReady&&secretReady&&keyMode&&env.APP_URL?.startsWith('https://');
 const enabled=configured&&flagsOn&&(mode==='test'||env.LIVE_E2E_CONFIRMED==='true');
 const resend=mailer||(env.RESEND_API_KEY?new Resend(env.RESEND_API_KEY):null);
 const base=(env.APP_URL||'http://localhost:3000').replace(/\/$/,'');
 app.disable('x-powered-by');
 app.set('trust proxy',env.TRUST_PROXY_HOPS?Number(env.TRUST_PROXY_HOPS):false);
 app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'",'https://checkout.razorpay.com'],styleSrc:["'self'"],imgSrc:["'self'",'data:'],connectSrc:["'self'",'https://api.razorpay.com'],frameSrc:['https://api.razorpay.com','https://checkout.razorpay.com'],objectSrc:["'none'"],baseUri:["'self'"],formAction:["'self'"],upgradeInsecureRequests:env.NODE_ENV==='production'?[]:null}},referrerPolicy:{policy:'no-referrer'}}));
 app.use('/api',(_,res,next)=>{res.set('Cache-Control','no-store');next();});
 const limiter=rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:'draft-7',legacyHeaders:false});
 app.use('/api/orders',limiter); app.use('/api/admin',limiter);
 const asyncRoute=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);
 async function tx(fn){const c=await db.connect();try{await c.query('BEGIN');const result=await fn(c);await c.query('COMMIT');return result;}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
 async function provider(endpoint,options={}){const r=await fetcher('https://api.razorpay.com/v1/'+endpoint,{...options,signal:AbortSignal.timeout(15000),headers:{'Content-Type':'application/json',Authorization:'Basic '+Buffer.from(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`).toString('base64'),...options.headers}});if(!r.ok)throw new Error('Payment provider request failed');return r.json();}
 async function recordCaptured(c,p,eventID){
  const result=await c.query('SELECT * FROM orders WHERE provider_order_id=$1 FOR UPDATE',[p.order_id]); const o=result.rows[0];
  if(!o)throw new Error('Unknown provider order; retry webhook or reconcile');
  if(o.mode!==mode||!paymentMatches(p,o))throw new Error('Payment/order/amount/currency/capture validation failed');
  if(o.revoked_at)return;
  if(o.payment_id&&o.payment_id!==p.id)throw new Error('Conflicting payment on order');
  await c.query("UPDATE orders SET state='paid',payment_id=$2,paid_at=COALESCE(paid_at,now()),delivery_state=CASE WHEN delivery_state='not_started' THEN 'queued' ELSE delivery_state END WHERE id=$1",[o.id,p.id]);
  await c.query('INSERT INTO outbox(id,order_id,version) VALUES($1,$2,$3) ON CONFLICT(order_id,version) DO NOTHING',[`${o.id}:1`,o.id,1]);
 }
 // RAW BODY routes must precede express.json(). Never trust a browser success event.
 app.post('/api/webhooks/razorpay',express.raw({type:'application/json',limit:'256kb'}),asyncRoute(async(req,res)=>{
  if(!configured)return res.status(503).json({error:'Integration not configured'});
  if(!Buffer.isBuffer(req.body)||!verifyWebhook(req.body,req.get('x-razorpay-signature'),env.RAZORPAY_WEBHOOK_SECRET))return res.status(400).json({error:'Invalid webhook signature'});
  const event=JSON.parse(req.body.toString());const eventID='rzp:'+(req.get('x-razorpay-event-id')||hash(req.body));
  if(!['payment.captured','payment.refunded','refund.processed'].includes(event.event))return res.sendStatus(200);
  if(!flagsOn)return res.status(503).json({error:'Processing paused; provider should retry'});
  let p;if(event.event==='refund.processed')p=await provider('payments/'+encodeURIComponent(event.payload.refund.entity.payment_id));else p=await provider('payments/'+encodeURIComponent(event.payload.payment.entity.id));
  await tx(async c=>{const inserted=await c.query('INSERT INTO webhook_events(id,provider) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING id',[eventID,'razorpay']);if(!inserted.rowCount)return;
   if(event.event==='payment.captured'){await recordCaptured(c,p,eventID);}else if(Number(p.amount_refunded)>0){await c.query("UPDATE orders SET state='refunded',revoked_at=now() WHERE payment_id=$1",[p.id]);}
  });res.json({received:true});
 }));
 app.post('/api/webhooks/resend',express.raw({type:'application/json',limit:'256kb'}),asyncRoute(async(req,res)=>{
  if(!configured)return res.sendStatus(503);
  let event;try{event=resend.webhooks.verify({payload:req.body.toString(),headers:{id:req.get('svix-id'),timestamp:req.get('svix-timestamp'),signature:req.get('svix-signature')},webhookSecret:env.RESEND_WEBHOOK_SECRET});}catch{return res.status(400).json({error:'Invalid email webhook signature'});}
  const states={'email.sent':['sent',1],'email.delivery_delayed':['delayed',2],'email.delivered':['delivered',3],'email.failed':['failed',4],'email.bounced':['bounced',4],'email.complained':['complained',5]};const status=states[event.type];if(!status)return res.sendStatus(200);
  const stamp=Date.parse(event.created_at);if(!Number.isFinite(stamp))return res.sendStatus(400);
  await tx(async c=>{const ins=await c.query('INSERT INTO webhook_events(id,provider) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING id',['resend:'+req.get('svix-id'),'resend']);if(!ins.rowCount)return;
   // Match current email only; ignore old recovery-version events. Monotonic rank avoids delivered→sent regression.
   const updated=await c.query('UPDATE orders SET delivery_state=$2,email_event_at=$3,email_event_rank=$4 WHERE email_id=$1 AND email_event_rank<=$4 RETURNING id',[event.data.email_id,status[0],new Date(stamp),status[1]]);
   if(!updated.rowCount){const check=await c.query('SELECT id FROM outbox WHERE email_id=$1',[event.data.email_id]);if(!check.rowCount)throw new Error('Email not persisted yet; retry webhook');}
  });res.json({received:true});
 }));
 app.use(express.json({limit:'16kb'}));
 // Same-origin requests for checkout/admin. No permissive CORS.
 app.use('/api',(req,res,next)=>{if(['GET','HEAD','OPTIONS'].includes(req.method))return next();const origin=req.get('origin');if(origin&&origin!==base)return res.status(403).json({error:'Origin rejected'});if(!req.is('application/json'))return res.status(415).json({error:'JSON required'});next();});
 app.get('/api/config',(_,res)=>res.json({price:PRICE_PAISE/100,paymentEnabled:enabled,deliveryEnabled:enabled,mode,serverNow:now(),offer:offer(env,now()),contactEmail:contact,policies:site,upiId:env.UPI_ID||'[ENTER_MY_UPI_ID]',upiQrImage:env.UPI_QR_IMAGE||'',setupMessage:enabled?(mode==='test'?'TEST MODE — real purchase nahi hai.':''):'Checkout abhi disabled hai. Payment aur email setup/test ke baad hi purchase available hoga.'}));
 app.get('/healthz',(_,res)=>res.json({ok:true,checkoutEnabled:enabled}));
 app.post('/api/orders',asyncRoute(async(req,res)=>{
  if(!enabled)return res.status(503).json({error:'Checkout disabled. Koi payment accept nahi ho raha aur email save nahi ki gayi.'});
  if(offer(env,now()).expired)return res.status(410).json({error:'Configured offer expired. Naya order accept nahi ho raha.'});
  const parsed=z.object({email:z.string().trim().email().max(254),name:z.string().trim().max(100).optional(),acceptedPolicies:z.literal(true)}).safeParse(req.body);
  if(!parsed.success)return res.status(400).json({error:'Valid email aur policy acknowledgement zaroori hai.'});
  const id='RTL-'+crypto.randomUUID(),token=crypto.randomBytes(32).toString('hex');
  await db.query('INSERT INTO orders(id,email,name,token_hash,amount,mode) VALUES($1,$2,$3,$4,$5,$6)',[id,parsed.data.email,parsed.data.name||'',hash(token),PRICE_PAISE,mode]);
  let po;try{po=await provider('orders',{method:'POST',body:JSON.stringify({amount:PRICE_PAISE,currency:'INR',receipt:id,notes:{local_order_id:id}})});await db.query('UPDATE orders SET provider_order_id=$2 WHERE id=$1',[id,po.id]);}catch(e){await db.query("UPDATE orders SET state='creation_failed' WHERE id=$1",[id]);throw e;}
  res.status(201).json({orderId:id,token,keyId:env.RAZORPAY_KEY_ID,providerOrderId:po.id,amount:PRICE_PAISE,currency:'INR',mode});
 }));
 async function authenticated(req,res,next){if(!db)return res.status(503).json({error:'Order service not configured'});const token=req.get('authorization')?.replace(/^Bearer /,'');if(!token)return res.status(401).json({error:'Order access token required'});const r=await db.query('SELECT * FROM orders WHERE id=$1',[req.params.id]);const o=r.rows[0];if(!o||!safeEqual(hash(token),o.token_hash))return res.status(404).json({error:'Order not found'});req.order=o;next();}
 app.get('/api/orders/:id',asyncRoute(authenticated),asyncRoute(async(req,res)=>{const o=req.order;res.json({orderId:o.id,paymentStatus:o.state,deliveryStatus:o.delivery_state,mode:o.mode,createdAt:o.created_at});}));
 // No callback route exists that can mark an order paid.
 app.post('/api/orders/:id/reconcile',asyncRoute(authenticated),asyncRoute(async(req,res)=>{
  if(!enabled)return res.sendStatus(503);const o=req.order;if(!o.provider_order_id)return res.sendStatus(409);
  const payments=await provider(`orders/${encodeURIComponent(o.provider_order_id)}/payments`);const p=payments.items.find(p=>paymentMatches(p,o));
  if(p)await tx(c=>recordCaptured(c,p,'api-reconcile'));res.json({checked:true,verifiedCaptured:!!p});
 }));
 app.get('/download/:id',asyncRoute(async(req,res)=>{
  res.set({'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Robots-Tag':'noindex, nofollow'});
  if(!enabled)return res.status(503).type('text').send('Download service paused. Please contact seller support.');
  const {e,v,s}=req.query;if(!validDownload(env.DOWNLOAD_SIGNING_SECRET,req.params.id,e,v,s,now()))return res.status(403).type('text').send('Link invalid ya expired hai. Order ID ke saath seller support se naya link maangein.');
  const r=await db.query('SELECT * FROM orders WHERE id=$1',[req.params.id]);const o=r.rows[0];if(!o||o.state!=='paid'||o.revoked_at||String(o.delivery_version)!==v||o.mode!==mode)return res.status(403).type('text').send('Verified paid order required.');
  let url;if(signDownload)url=await signDownload();else{const s3=new S3Client({region:env.S3_REGION||'auto',endpoint:env.S3_ENDPOINT,credentials:{accessKeyId:env.S3_ACCESS_KEY_ID,secretAccessKey:env.S3_SECRET_ACCESS_KEY}});url=await getSignedUrl(s3,new GetObjectCommand({Bucket:env.S3_BUCKET,Key:env.S3_OBJECT_KEY,ResponseContentType:'application/pdf',ResponseContentDisposition:'attachment; filename="Road-to-1-Lakh-in-a-Month.pdf"'}),{expiresIn:60});}res.redirect(303,url);
 }));
 function admin(req,res,next){if(!env.ADMIN_TOKEN||!safeEqual(req.get('authorization')||'','Bearer '+env.ADMIN_TOKEN))return res.status(401).json({error:'Admin authorization required'});next();}
 app.get('/api/admin/orders',admin,asyncRoute(async(req,res)=>{if(!db)return res.sendStatus(503);const r=req.query.orderId?await db.query('SELECT id,email,state,delivery_state,email_id,mode,created_at FROM orders WHERE id=$1',[String(req.query.orderId).slice(0,100)]):await db.query('SELECT id,email,state,delivery_state,email_id,mode,created_at FROM orders ORDER BY created_at DESC LIMIT 100');res.json(r.rows);}));
 app.post('/api/admin/recover',admin,asyncRoute(async(req,res)=>{
  if(!enabled)return res.sendStatus(503);const parsed=z.object({orderId:z.string().max(100),email:z.string().email().max(254).optional(),confirmIdentityChecked:z.literal(true)}).safeParse(req.body);if(!parsed.success)return res.status(400).json({error:'Order ID and independent identity verification required'});
  await tx(async c=>{const r=await c.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE',[parsed.data.orderId]);const o=r.rows[0];if(!o||o.state!=='paid'||o.revoked_at||o.mode!==mode)throw new Error('Paid active order required');
   if(o.recovery_at&&now()-new Date(o.recovery_at).getTime()<86400000)throw new Error('Recovery cooldown: 24 hours');
   const p=await provider('payments/'+encodeURIComponent(o.payment_id));if(!paymentMatches(p,o))throw new Error('Provider no longer confirms captured unrefunded payment');
   const version=o.delivery_version+1;await c.query("UPDATE orders SET email=$2,delivery_version=$3,delivery_state='queued',email_id=NULL,email_event_rank=0,email_event_at=NULL,recovery_at=now(),recovery_count=recovery_count+1 WHERE id=$1",[o.id,parsed.data.email||o.email,version]);
   await c.query('INSERT INTO outbox(id,order_id,version) VALUES($1,$2,$3)',[`${o.id}:${version}`,o.id,version]);await c.query('INSERT INTO admin_audit(id,order_id,action) VALUES($1,$2,$3)',[crypto.randomUUID(),o.id,'Verified recovery; new delivery version '+version]);
  });res.json({queued:true});
 }));
 app.use(express.static(path.join(root,'public'),{dotfiles:'deny',index:'index.html',maxAge:0}));
 app.use((err,req,res,next)=>{console.error('Request failed:',err.message);res.status(500).json({error:'Request complete nahi hui. Dobara payment mat karein; order status check karein ya support se contact karein.'});});
 let working=false;
 async function workOnce(){
  if(!enabled||working)return;working=true;try{const claimed=await tx(async c=>{
   const r=await c.query("SELECT * FROM outbox WHERE state IN ('pending','processing') AND next_attempt_at<=now() ORDER BY next_attempt_at LIMIT 1 FOR UPDATE SKIP LOCKED");const job=r.rows[0];if(!job)return null;
   const or=await c.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE',[job.order_id]);const o=or.rows[0];if(!o||o.state!=='paid'||o.revoked_at||o.delivery_version!==job.version){await c.query("UPDATE outbox SET state='cancelled' WHERE id=$1",[job.id]);return;}
   // Before each attempt, recheck provider; this also catches refunds missed by a webhook.
   try{const p=await provider('payments/'+encodeURIComponent(o.payment_id));if(!paymentMatches(p,o))throw new Error('Captured unrefunded payment no longer verified');}catch(e){await c.query("UPDATE outbox SET next_attempt_at=now()+interval '5 minutes',last_error=$2 WHERE id=$1",[job.id,e.message]);return;}
   if(job.first_attempt_at&&now()-new Date(job.first_attempt_at).getTime()>23*3600000){await c.query("UPDATE outbox SET state='manual_review',last_error='Provider idempotency window nearing expiry; inspect provider before retry' WHERE id=$1",[job.id]);await c.query("UPDATE orders SET delivery_state='manual_review' WHERE id=$1",[o.id]);return;}
   let payload=job.payload;if(!payload){const expires=Math.floor(now()/1000)+604800;const sig=downloadSignature(env.DOWNLOAD_SIGNING_SECRET,o.id,expires,job.version);const link=`${base}/download/${o.id}?e=${expires}&v=${job.version}&s=${sig}`;
    payload={from:env.EMAIL_FROM,to:[o.email],subject:`Aapki ebook ready hai | ${o.id}`,text:`Namaste ${o.name||'reader'},\nAapka ₹349 payment independently verify ho gaya hai.\nOrder: ${o.id}\n${mode==='test'?'TEST ORDER — real purchase nahi.\n':''}Road to ₹1 Lakh in a Month — Sujit Singh\nSecure download (7 din): ${link}\nLink private rakhein. PDF: 124 pages; prompts aur templates PDF ke andar hain.\nSupport: ${contact}\nIncome guarantee nahi hai.`,html:`<p>Namaste ${escapeHtml(o.name||'reader')},</p><p>Aapka <strong>₹349 payment independently verify</strong> ho gaya hai.</p><p>Order: ${escapeHtml(o.id)}${mode==='test'?'<br><strong>TEST ORDER — real purchase nahi.</strong>':''}</p><h2>Road to ₹1 Lakh in a Month</h2><p>Sujit Singh · 124-page PDF</p><p><a href="${escapeHtml(link)}">Apni ebook download karein</a></p><p>Link 7 din valid hai. Link private rakhein. Templates aur prompts PDF ke andar hain; separate spreadsheets nahi hain.</p><p>Support: ${escapeHtml(contact)}. Income guarantee nahi hai.</p>`};}
   // COMMIT payload and first-attempt time BEFORE the external call. A process crash can then retry the exact same payload/key within the 24h provider window.
   const started=job.first_attempt_at||new Date(now());
   await c.query("UPDATE outbox SET state='processing',payload=$2,first_attempt_at=$3,attempts=attempts+1,next_attempt_at=$4 WHERE id=$1",[job.id,JSON.stringify(payload),started,new Date(now()+5*60000)]);
   return {job,o,payload};
  });
  if(!claimed)return;
  const {job,o,payload}=claimed;
  try{const result=await resend.emails.send(payload,{idempotencyKey:'ebook/'+job.id});if(result.error)throw new Error(result.error.message);const emailID=result.data?.id;if(!emailID)throw new Error('Missing provider email ID');
   await tx(async c=>{await c.query("UPDATE outbox SET state='sent',email_id=$2,last_error=NULL WHERE id=$1",[job.id,emailID]);await c.query("UPDATE orders SET email_id=$2,delivery_state='submitted' WHERE id=$1 AND delivery_version=$3",[o.id,emailID,job.version]);});
  }catch(e){const manual=job.attempts>=7;await tx(async c=>{await c.query("UPDATE outbox SET state=$2,next_attempt_at=$3,last_error=$4 WHERE id=$1",[job.id,manual?'manual_review':'pending',new Date(now()+5*60000)]);
   return {job,o,payload};
  });
  if(!claimed)return;
  const {job,o,payload}=claimed;
  try{const result=await resend.emails.send(payload,{idempotencyKey:'ebook/'+job.id});if(result.error)throw new Error(result.error.message);const emailID=result.data?.id;if(!emailID)throw new Error('Missing provider email ID');
   await tx(async c=>{await c.query("UPDATE outbox SET state='sent',email_id=$2,last_error=NULL WHERE id=$1",[job.id,emailID]);await c.query("UPDATE orders SET email_id=$2,delivery_state='submitted' WHERE id=$1 AND delivery_version=$3",[o.id,emailID,job.version]);});
  }catch(e){const manual=job.attempts>=7;await tx(async c=>{await c.query("UPDATE outbox SET state=$2,next_attempt_at=$3,last_error=$4 WHERE id=$1",[job.id,manual?'manual_review':'pending',new Date(now()+Math.min(3600000,30000*2**job.attempts)),String(e.message).slice(0,300)]);await c.query('UPDATE orders SET delivery_state=$2 WHERE id=$1 AND delivery_version=$3',[o.id,manual?'manual_review':'retrying',job.version]);});}
  }catch(e){console.error('Delivery worker:',e.message);}finally{working=false;}
 }
 return {app,workOnce,enabled,configured,missing,policyReady};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const db=process.env.DATABASE_URL?new pg.Pool({connectionString:process.env.DATABASE_URL,max:5}):null;
 if(db)await db.query(schema);
 const built=makeApp({db});built.app.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log(`Website started; checkout ${built.enabled?'ENABLED '+(process.env.PAYMENT_MODE||'test'):'DISABLED'}; no integration testing implied`));
 setInterval(()=>built.workOnce(),5000).unref();
}
