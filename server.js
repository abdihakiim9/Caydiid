'use strict';
/* Caydiid backend: sign-up with e-mail verification code, login, sessions.
   Zero dependencies (Node 18+). Also serves the app's static files. */
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=+process.env.PORT||8080,PROD=process.env.NODE_ENV==='production';
const DATA=process.env.DATA_DIR||path.join(__dirname,'data');
const ORIGIN=process.env.ALLOWED_ORIGIN||'';            // only needed if the app files are hosted elsewhere
const TRUST_PROXY=process.env.TRUST_PROXY==='1';
const MAIL=(process.env.MAIL_PROVIDER||'').toLowerCase(); // 'brevo' | 'resend' | '' (dev: print code in console)
const FROM_EMAIL=process.env.MAIL_FROM||'',FROM_NAME=process.env.MAIL_FROM_NAME||'Caydiid';
const DEV_ECHO=!PROD&&process.env.DEV_ECHO==='1';        // test only: returns the code in the API reply
fs.mkdirSync(DATA,{recursive:true});
const DB_FILE=path.join(DATA,'db.json');
let db={users:{},pending:{}};try{db=Object.assign(db,JSON.parse(fs.readFileSync(DB_FILE,'utf8')))}catch(e){}
const persist=()=>{const t=DB_FILE+'.tmp';fs.writeFileSync(t,JSON.stringify(db));fs.renameSync(t,DB_FILE)};
let SECRET=process.env.SECRET;
if(!SECRET){const f=path.join(DATA,'secret.key');try{SECRET=fs.readFileSync(f,'utf8')}catch(e){SECRET=crypto.randomBytes(32).toString('hex');fs.writeFileSync(f,SECRET,{mode:0o600})}}
const hmac=s=>crypto.createHmac('sha256',SECRET).update(s).digest('hex');
const safeEq=(a,b)=>{a=Buffer.from(String(a));b=Buffer.from(String(b));return a.length===b.length&&crypto.timingSafeEqual(a,b)};
/* passwords */
const hashPw=pw=>{const s=crypto.randomBytes(16);return 's1:'+s.toString('hex')+':'+crypto.scryptSync(pw,s,64).toString('hex')};
const DUMMY=hashPw('dummy-password');
const checkPw=(pw,h)=>{const p=String(h).split(':');if(p[0]!=='s1')return false;return safeEq(crypto.scryptSync(pw,Buffer.from(p[1],'hex'),64).toString('hex'),p[2])};
/* session tokens */
const b64=b=>Buffer.from(b).toString('base64url');
const mkToken=uid=>{const p=b64(JSON.stringify({u:uid,e:Date.now()+365*864e5}));return p+'.'+hmac('t:'+p)};
const readToken=t=>{const [p,s]=String(t||'').split('.');if(!p||!s||!safeEq(hmac('t:'+p),s))return null;try{const o=JSON.parse(Buffer.from(p,'base64url'));return o.e>Date.now()?o.u:null}catch(e){return null}};
/* validation */
const norm=e=>String(e||'').trim().toLowerCase();
const okEmail=e=>e.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const okName=n=>/^[\p{L}\p{M}'. -]{1,40}$/u.test(n);
const okPhone=p=>/^\+?[0-9 ()\-]{7,25}$/.test(p)&&p.replace(/\D/g,'').length>=7&&p.replace(/\D/g,'').length<=15;
function okDob(s){if(!/^\d{4}-\d{2}-\d{2}$/.test(s))return 'Enter a valid date of birth';const d=new Date(s+'T00:00:00Z');if(isNaN(d)||d.toISOString().slice(0,10)!==s)return 'Enter a valid date of birth';const n=new Date();let a=n.getUTCFullYear()-d.getUTCFullYear();if(n.getUTCMonth()<d.getUTCMonth()||(n.getUTCMonth()===d.getUTCMonth()&&n.getUTCDate()<d.getUTCDate()))a--;if(d>n||a>120)return 'Enter a valid date of birth';if(a<13)return 'You must be at least 13 years old to use Caydiid';return ''}
const pub=u=>({email:u.email,first:u.first,last:u.last,dob:u.dob,phone:u.phone});

/* Gmail SMTP (zero dependencies): uses a Google "App Password" */
const tls=require('tls');
function smtpSend(to,subject,text,html){
 const host=process.env.SMTP_HOST||'smtp.gmail.com',port=+process.env.SMTP_PORT||465;
 const user=process.env.GMAIL_USER||'',pass=String(process.env.GMAIL_APP_PASSWORD||'').replace(/\s+/g,'');
 if(!user||!pass)return Promise.reject(new Error('GMAIL_USER / GMAIL_APP_PASSWORD not set'));
 const b=s=>Buffer.from(s,'utf8').toString('base64'),wrap=s=>b(s).replace(/(.{76})/g,'$1\r\n');
 const bd='cdd'+crypto.randomBytes(8).toString('hex');
 const msg=['From: '+FROM_NAME.replace(/[\r\n"<>]/g,'')+' <'+user+'>','To: <'+to+'>','Subject: =?UTF-8?B?'+b(subject)+'?=','Date: '+new Date().toUTCString(),'MIME-Version: 1.0','Content-Type: multipart/alternative; boundary="'+bd+'"','',
  '--'+bd,'Content-Type: text/plain; charset=UTF-8','Content-Transfer-Encoding: base64','',wrap(text),
  '--'+bd,'Content-Type: text/html; charset=UTF-8','Content-Transfer-Encoding: base64','',wrap(html),'--'+bd+'--',''].join('\r\n');
 const steps=[['',220],['EHLO caydiid',250],['AUTH LOGIN',334],[b(user),334],[b(pass),235],['MAIL FROM:<'+user+'>',250],['RCPT TO:<'+to+'>',250],['DATA',354],[msg+'\r\n.',250],['QUIT',221]];
 return new Promise((ok,no)=>{
  let i=0,buf='',done=false;
  const sock=tls.connect({host,port,servername:host,rejectUnauthorized:process.env.SMTP_INSECURE!=='1'});
  const end=e=>{if(done)return;done=true;try{sock.destroy()}catch(x){}e?no(e):ok()};
  sock.setTimeout(20000,()=>end(new Error('smtp timeout')));
  sock.on('error',end);
  sock.on('close',()=>end(i>=steps.length-1?null:new Error('smtp closed early')));
  sock.on('data',d=>{buf+=d.toString('utf8');
   let m;while((m=buf.match(/^(?:\d{3}-[^\n]*\n)*(\d{3}) [^\n]*\n/))){buf=buf.slice(m[0].length);
    const code=+m[1],want=steps[i][1];
    if(code!==want)return end(new Error('smtp step '+i+' expected '+want+' got '+code+(code===535?' (wrong Gmail App Password)':'')));
    i++;if(i>=steps.length)return end();
    sock.write(steps[i][0]+'\r\n')}})})
}
/* e-mail sending */
async function sendCode(email,code,first){
 const subject='Your Caydiid verification code: '+code;
 const text=`Hi ${first},\n\nYour Caydiid verification code is ${code}\nIt expires in 10 minutes.\n\nIf you did not try to create an account, ignore this e-mail.`;
 const html=`<div style="font-family:system-ui,sans-serif;max-width:420px;margin:auto"><h2>Caydiid</h2><p>Hi ${first.replace(/[<>&]/g,'')},</p><p>Your verification code is</p><p style="font-size:34px;font-weight:800;letter-spacing:8px;margin:12px 0">${code}</p><p style="color:#666">It expires in 10 minutes. If you did not try to create an account, ignore this e-mail.</p></div>`;
 if(MAIL==='gmail'){await smtpSend(email,subject,text,html);return}
 if(MAIL==='brevo'){const r=await fetch('https://api.brevo.com/v3/smtp/email',{method:'POST',headers:{'api-key':process.env.BREVO_API_KEY||'','content-type':'application/json'},body:JSON.stringify({sender:{name:FROM_NAME,email:FROM_EMAIL},to:[{email}],subject,textContent:text,htmlContent:html})});if(!r.ok)throw new Error('brevo '+r.status+' '+(await r.text()).slice(0,200));return}
 if(MAIL==='resend'){const r=await fetch('https://api.resend.com/emails',{method:'POST',headers:{authorization:'Bearer '+(process.env.RESEND_API_KEY||''),'content-type':'application/json'},body:JSON.stringify({from:`${FROM_NAME} <${FROM_EMAIL}>`,to:[email],subject,text,html})});if(!r.ok)throw new Error('resend '+r.status+' '+(await r.text()).slice(0,200));return}
 if(PROD)throw new Error('MAIL_PROVIDER is not configured');
 console.log(`[DEV] verification code for ${email}: ${code}`);
}
/* helpers */
const ipOf=req=>TRUST_PROXY?String(req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress:req.socket.remoteAddress;
const hits=new Map();setInterval(()=>{const n=Date.now();for(const[k,v]of hits)if(v.t<n)hits.delete(k)},60000).unref();
function limited(req,key,max,win){const k=ipOf(req)+'|'+key,n=Date.now();let h=hits.get(k);if(!h||h.t<n){h={c:0,t:n+win};hits.set(k,h)}return ++h.c>max}
const send=(res,code,obj)=>{res.writeHead(code,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(obj))};
const body=req=>new Promise((ok,no)=>{let b='';req.on('data',c=>{b+=c;if(b.length>20000){no(new Error('big'));req.destroy()}});req.on('end',()=>{try{ok(JSON.parse(b||'{}'))}catch(e){no(e)}});req.on('error',no)});
const fail=(res,code,msg)=>send(res,code,{error:msg});
async function issueCode(p,email){
 const now=Date.now();p.sent=(p.sent||[]).filter(t=>t>now-36e5);
 if(p.ls&&now-p.ls<30000)return {wait:Math.ceil((30000-(now-p.ls))/1000)};
 if(p.sent.length>=5)return {many:1};
 const code=String(crypto.randomInt(0,1000000)).padStart(6,'0');
 await sendCode(email,code,p.first);
 p.ch=hmac('c:'+email+':'+code);p.exp=now+600000;p.tries=0;p.ls=now;p.sent.push(now);persist();
 return {code};
}
/* routes */
const routes={
 async 'POST /api/signup/start'(req,res,b){
  if(limited(req,'start',10,9e5))return fail(res,429,'Too many attempts. Try again later.');
  const email=norm(b.email),first=String(b.first||'').trim(),last=String(b.last||'').trim(),dob=String(b.dob||''),phone=String(b.phone||'').trim(),pw=String(b.password||'');
  if(!okName(first))return fail(res,400,'Enter your first name');
  if(!okName(last))return fail(res,400,'Enter your last name');
  const de=okDob(dob);if(de)return fail(res,400,de);
  if(!okPhone(phone))return fail(res,400,'Enter a valid phone number, e.g. +252 61 234 5678');
  if(!okEmail(email))return fail(res,400,'Enter a valid e-mail address');
  if(pw.length<8||pw.length>128)return fail(res,400,'Password must be 8–128 characters');
  if(db.users[email])return fail(res,409,'This e-mail already has an account. Log in instead.');
  const p=db.pending[email]=Object.assign(db.pending[email]||{},{first,last,dob,phone,pw:hashPw(pw),created:Date.now()});
  let r;try{r=await issueCode(p,email)}catch(e){console.error('mail error:',e.message);return fail(res,502,'Could not send the e-mail. Check the address and try again.')}
  if(r.wait||r.many){persist();return fail(res,429,r.many?'Too many codes requested. Try again in an hour.':`Please wait ${r.wait}s before asking for another code.`)}
  send(res,200,Object.assign({ok:true},DEV_ECHO?{devCode:r.code}:{}))},
 async 'POST /api/signup/resend'(req,res,b){
  if(limited(req,'resend',15,9e5))return fail(res,429,'Too many attempts. Try again later.');
  const email=norm(b.email),p=db.pending[email];
  if(!p)return fail(res,404,'Your sign-up expired. Please fill the form again.');
  let r;try{r=await issueCode(p,email)}catch(e){console.error('mail error:',e.message);return fail(res,502,'Could not send the e-mail. Try again.')}
  if(r.wait||r.many)return fail(res,429,r.many?'Too many codes requested. Try again in an hour.':`Please wait ${r.wait}s before asking for another code.`);
  send(res,200,Object.assign({ok:true},DEV_ECHO?{devCode:r.code}:{}))},
 async 'POST /api/signup/verify'(req,res,b){
  if(limited(req,'verify',30,9e5))return fail(res,429,'Too many attempts. Try again later.');
  const email=norm(b.email),code=String(b.code||'').replace(/\D/g,''),p=db.pending[email];
  if(!p||!p.ch)return fail(res,404,'Your sign-up expired. Please fill the form again.');
  if(Date.now()>p.exp)return fail(res,410,'This code expired. Tap “Resend code”.');
  if(p.tries>=5){return fail(res,429,'Too many wrong codes. Tap “Resend code” to get a new one.')}
  if(!safeEq(hmac('c:'+email+':'+code),p.ch)){p.tries++;persist();return fail(res,400,'Wrong code. '+(5-p.tries)+' tries left.')}
  if(db.users[email]){delete db.pending[email];persist();return fail(res,409,'This e-mail already has an account. Log in instead.')}
  const u=db.users[email]={id:crypto.randomUUID(),email,first:p.first,last:p.last,dob:p.dob,phone:p.phone,pw:p.pw,verified:true,created:Date.now()};
  delete db.pending[email];persist();
  send(res,200,{ok:true,token:mkToken(u.id),user:pub(u)})},
 async 'POST /api/login'(req,res,b){
  if(limited(req,'login',20,9e5))return fail(res,429,'Too many attempts. Try again later.');
  const email=norm(b.email),pw=String(b.password||'').slice(0,128),u=db.users[email];
  const ok=checkPw(pw,u?u.pw:DUMMY);
  if(!u||!ok)return fail(res,401,'Wrong e-mail or password');
  send(res,200,{ok:true,token:mkToken(u.id),user:pub(u)})},
 async 'GET /api/me'(req,res){
  const uid=readToken((req.headers.authorization||'').replace(/^Bearer /,'')),u=uid&&Object.values(db.users).find(x=>x.id===uid);
  if(!u)return fail(res,401,'Session expired');send(res,200,{ok:true,user:pub(u)})},
 async 'GET /api/health'(req,res){send(res,200,{ok:true,mail:MAIL||'dev'})}
};
/* static files (whitelist only; never expose server/ or data/) */
const STATIC=/^\/(index\.html|styles\.css|app\.js|features[0-9]?\.js|sw\.js|manifest\.json|logo\.png)?$/;
const TYPES={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json','.png':'image/png'};
http.createServer(async(req,res)=>{
 try{
  const url=new URL(req.url,'http://x'),p=url.pathname;
  if(ORIGIN&&p.startsWith('/api/')){res.setHeader('access-control-allow-origin',ORIGIN);res.setHeader('access-control-allow-headers','content-type,authorization');res.setHeader('access-control-allow-methods','GET,POST,OPTIONS');res.setHeader('vary','origin');if(req.method==='OPTIONS'){res.writeHead(204);return res.end()}}
  const h=routes[req.method+' '+p];
  if(h){const b=req.method==='POST'?await body(req):{};return await h(req,res,b)}
  if(req.method==='GET'&&STATIC.test(p)){const f=p==='/'?'index.html':p.slice(1),fp=path.join(__dirname,f);
   return fs.readFile(fp,(e,d)=>{if(e){res.writeHead(404);return res.end('Not found')}res.writeHead(200,{'content-type':TYPES[path.extname(f)]||'application/octet-stream','cache-control':'no-cache','x-content-type-options':'nosniff'});res.end(d)})}
  res.writeHead(404);res.end('Not found')
 }catch(e){console.error(e.message);if(!res.headersSent)fail(res,400,'Bad request')}
}).listen(PORT,()=>console.log(`Caydiid server on :${PORT}  mail=${MAIL||'DEV (codes print in console)'}${PROD&&!MAIL?'  ⚠ set MAIL_PROVIDER!':''}`));
