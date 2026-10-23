import crypto from 'node:crypto';
export const PRICE_PAISE=34900;
export function safeEqual(a,b){if(typeof a!=='string'||typeof b!=='string')return false;const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&crypto.timingSafeEqual(x,y);}
export function hmac(secret,body){return crypto.createHmac('sha256',secret).update(body).digest('hex');}
export function verifyWebhook(raw,signature,secret){return !!secret&&safeEqual(hmac(secret,raw),signature);}
export function hash(value){return crypto.createHash('sha256').update(value).digest('hex');}
export function downloadSignature(secret,id,expires,version){return hmac(secret,`${id}.${expires}.${version}`);}
export function validDownload(secret,id,expires,version,sig,now=Date.now()){return Number.isInteger(Number(expires))&&Number(expires)>Math.floor(now/1000)&&Number(expires)<=Math.floor(now/1000)+604801&&safeEqual(downloadSignature(secret,id,expires,version),sig);}
export function paymentMatches(payment,order){return payment.status==='captured'&&payment.captured===true&&payment.id&&payment.order_id===order.provider_order_id&&payment.amount===order.amount&&payment.currency===order.currency&&Number(payment.amount_refunded||0)===0;}
export function offer(env,now=Date.now()){
 const start=Date.parse(env.OFFER_STARTS_AT||''),end=Date.parse(env.OFFER_ENDS_AT||'');
 const configured=env.GENUINE_OFFER_CONFIRMED==='true'&&Number.isFinite(start)&&Number.isFinite(end)&&end-start===300000;
 return {configured,active:configured&&now>=start&&now<end,expired:configured&&now>=end,startsAt:configured?new Date(start).toISOString():null,endsAt:configured?new Date(end).toISOString():null};
}
export function escapeHtml(x){return String(x??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));}
