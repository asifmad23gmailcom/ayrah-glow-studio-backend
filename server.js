'use strict';
const http=require('node:http');const fs=require('node:fs');const path=require('node:path');const crypto=require('node:crypto');
const PORT=Number(process.env.PORT||3000),KEY=process.env.RAZORPAY_KEY_ID,SECRET=process.env.RAZORPAY_KEY_SECRET,WEBHOOK=process.env.RAZORPAY_WEBHOOK_SECRET;
const catalog=new Map(JSON.parse(fs.readFileSync(path.join(__dirname,'catalog.json'),'utf8')).map(p=>[p.id,p]));
const store=path.join(__dirname,'data','orders.json');fs.mkdirSync(path.dirname(store),{recursive:true});
function load(){try{return JSON.parse(fs.readFileSync(store,'utf8'))}catch(e){if(e.code==='ENOENT')return {};throw e}}
function save(db){const tmp=store+'.tmp';fs.writeFileSync(tmp,JSON.stringify(db,null,2),{mode:0o600});fs.renameSync(tmp,store)}
function send(res,status,obj){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(obj))}
function safeEqual(a,b){if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;return crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b))}
async function body(req){const chunks=[];let size=0;for await(const c of req){size+=c.length;if(size>32000)throw Error('Request too large');chunks.push(c)}return Buffer.concat(chunks)}
async function razor(endpoint,method='GET',payload){const auth=Buffer.from(KEY+':'+SECRET).toString('base64');const r=await fetch('https://api.razorpay.com/v1/'+endpoint,{method,headers:{Authorization:'Basic '+auth,'Content-Type':'application/json'},body:payload?JSON.stringify(payload):undefined,signal:AbortSignal.timeout(12000)});const data=await r.json();if(!r.ok)throw Error(data.error?.description||'Razorpay API request failed');return data}
function validCustomer(c){return c&&typeof c==='object'&&typeof c.name==='string'&&c.name.trim().length>=2&&c.name.length<=100&&/^[0-9]{10}$/.test(c.phone||'')&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(c.email||'')&&['address','city','state'].every(k=>typeof c[k]==='string'&&c[k].trim().length>1&&c[k].length<=200)&&/^[0-9]{6}$/.test(c.pin||'')&&(!c.note||String(c.note).length<=500)}
const attempts=new Map();function rateLimit(req){const ip=req.socket.remoteAddress||'unknown',now=Date.now(),list=(attempts.get(ip)||[]).filter(t=>now-t<60000);list.push(now);attempts.set(ip,list);return list.length>15}
async function handler(req,res){
 if(req.method==='GET'&&(req.url==='/'||req.url==='/index.html')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','X-Content-Type-Options':'nosniff','Cache-Control':'no-cache'});return fs.createReadStream(path.join(__dirname,'public','index.html')).pipe(res)}
 if(req.method==='GET'&&req.url==='/api/health')return send(res,200,{ready:!!(KEY&&SECRET),mode:KEY?.startsWith('rzp_live_')?'live':'test'});
 if(req.method==='POST'&&req.url==='/api/razorpay/webhook'){
  if(!WEBHOOK)return send(res,503,{error:'Webhook secret not configured'});
  const raw=await body(req),expected=crypto.createHmac('sha256',WEBHOOK).update(raw).digest('hex');if(!safeEqual(expected,req.headers['x-razorpay-signature']))return send(res,401,{error:'Invalid signature'});
  const event=JSON.parse(raw.toString('utf8')),payment=event.payload?.payment?.entity;
  if(event.event==='payment.captured'&&payment?.order_id){const db=load();const entry=Object.values(db).find(o=>o.razorpayOrderId===payment.order_id);if(entry&&payment.amount===entry.amount&&payment.currency==='INR'){entry.status='paid';entry.paymentId=payment.id;entry.updatedAt=new Date().toISOString();save(db)}}
  return send(res,200,{ok:true});
 }
 if(!['/api/orders','/api/payments/verify'].includes(req.url)||req.method!=='POST')return send(res,404,{error:'Not found'});
 if(!KEY||!SECRET)return send(res,503,{error:'Razorpay API credentials are not configured on the server'});
 if(rateLimit(req))return send(res,429,{error:'Too many attempts; try again shortly'});
 const data=JSON.parse((await body(req)).toString('utf8'));
 if(req.url==='/api/orders'){
  if(!validCustomer(data.customer)||!Array.isArray(data.items)||data.items.length<1||data.items.length>30)return send(res,400,{error:'Please check your delivery details and cart'});
  const seen=new Set();let amount=0;const items=[];
  for(const item of data.items){if(!item||typeof item.id!=='string'||!catalog.has(item.id)||!Number.isInteger(item.quantity)||item.quantity<1||item.quantity>20||seen.has(item.id))return send(res,400,{error:'Invalid cart items'});seen.add(item.id);const p=catalog.get(item.id);amount+=p.price*100*item.quantity;items.push({id:p.id,name:p.name,unitPrice:p.price,quantity:item.quantity})}
  if(!Number.isSafeInteger(amount)||amount<100||amount>50000000)return send(res,400,{error:'Invalid order total'});
  const localOrderId='AGS-'+crypto.randomUUID();const rp=await razor('orders','POST',{amount,currency:'INR',receipt:localOrderId.slice(0,40),partial_payment:false});
  const db=load();db[localOrderId]={localOrderId,razorpayOrderId:rp.id,amount,currency:'INR',items,customer:data.customer,status:'pending',createdAt:new Date().toISOString()};save(db);
  return send(res,201,{localOrderId,orderId:rp.id,keyId:KEY,amount,currency:'INR'});
 }
 const {localOrderId,razorpay_order_id,razorpay_payment_id,razorpay_signature}=data;
 if(![localOrderId,razorpay_order_id,razorpay_payment_id,razorpay_signature].every(v=>typeof v==='string'&&v.length<150))return send(res,400,{error:'Invalid payment verification data'});
 const db=load(),order=db[localOrderId];if(!order||order.razorpayOrderId!==razorpay_order_id)return send(res,404,{error:'Order not found'});
 const expected=crypto.createHmac('sha256',SECRET).update(order.razorpayOrderId+'|'+razorpay_payment_id).digest('hex');if(!safeEqual(expected,razorpay_signature))return send(res,400,{error:'Invalid payment signature'});
 const [payment,rpOrder]=await Promise.all([razor('payments/'+encodeURIComponent(razorpay_payment_id)),razor('orders/'+encodeURIComponent(order.razorpayOrderId))]);
 if(payment.order_id!==order.razorpayOrderId||payment.amount!==order.amount||payment.currency!=='INR'||rpOrder.amount!==order.amount)return send(res,409,{error:'Payment details do not match order'});
 order.status=payment.status==='captured'&&rpOrder.status==='paid'?'paid':'awaiting_capture';order.paymentId=payment.id;order.updatedAt=new Date().toISOString();save(db);
 return send(res,200,{localOrderId,status:order.status});
}
http.createServer((req,res)=>Promise.resolve(handler(req,res)).catch(err=>{console.error(err.message);send(res,err.message==='Request too large'?413:500,{error:'Unable to process request. Please try again.'})})).listen(PORT,()=>console.log('Ayrah Glow Studio running on http://localhost:'+PORT));
