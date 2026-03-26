// ============================================================
//  One MFB — server.js
//  Install:  npm install express cors node-fetch
//  Run:      node server.js
// ============================================================
const express=require('express'),cors=require('cors'),fs=require('fs'),path=require('path');
const app=express(),PORT=process.env.PORT||3000;
app.use(cors());app.use(express.json());app.use(express.static(__dirname));
const DB=path.join(__dirname,'data','onemfb_guests.json');
function loadDB(){if(!fs.existsSync(DB))return{guests:{}};try{return JSON.parse(fs.readFileSync(DB,'utf8'));}catch{return{guests:{}};}}
function saveDB(db){fs.writeFileSync(DB,JSON.stringify(db,null,2));}
const TRIAL=5;
function getIP(req){return req.headers['x-forwarded-for']?.split(',')[0].trim()||req.headers['x-real-ip']||req.socket.remoteAddress||'unknown';}
async function enrichIP(ip, fallbackIP){
  if(ip==='127.0.0.1'||ip==='::1'||ip.startsWith('::ffff:127')){
    // Running locally — try to enrich the client-reported IP instead
    if(fallbackIP && fallbackIP!==ip){
      try{const{default:fetch}=await import('node-fetch');const r=await fetch(`https://ipapi.co/${fallbackIP}/json/`);return await r.json();}catch{}
    }
    return{ip,note:'localhost'};
  }
  try{const{default:fetch}=await import('node-fetch');const r=await fetch(`https://ipapi.co/${ip}/json/`);return await r.json();}catch{return{ip};}
}
function detectEvasion(db,inc){
  const flags=[];
  for(const[guestId,data]of Object.entries(db.guests)){
    if(guestId===inc.guestId)continue;
    if(data.visitCount<TRIAL)continue;
    const chk=(arr,val,sig,conf)=>{if(val&&arr?.includes(val))flags.push({sig,matchedGuest:guestId,conf});};
    chk(data.signals.fingerprints,inc.fpHash,'Fingerprint','HIGH');
    chk(data.signals.serverIPs,inc.serverIP,'Server IP','MEDIUM');
    chk(data.signals.webrtcLocal,inc.webrtcLocal,'WebRTC Local IP','HIGH');
    chk(data.signals.webrtcPublic,inc.webrtcPublic,'WebRTC Public IP','HIGH');
    chk(data.signals.cookies,inc.cookieToken,'Cookie Token','HIGH');
    chk(data.signals.lsTokens,inc.lsToken,'localStorage Token','HIGH');
  }
  if(!flags.length)return{evading:false};
  const highs=flags.filter(f=>f.conf==='HIGH').length;
  const conf=highs>=2?'VERY HIGH':highs===1?'HIGH':'MEDIUM';
  const sigs=[...new Set(flags.map(f=>f.sig))].join(', ');
  const who=[...new Set(flags.map(f=>f.matchedGuest))].join(', ');
  return{evading:true,conf,message:`Evasion detected (${conf}) — signals: ${sigs}. Linked to: ${who}.`,flags};
}
app.post('/api/guest-visit',async(req,res)=>{
  const{guestId,cookieToken,lsToken,fingerprint,ipData,webrtc,gyro,session,behavioral,page}=req.body;
  if(!guestId)return res.status(400).json({status:'error',message:'Missing guestId.'});
  const serverIP=getIP(req),ts=new Date().toISOString(),db=loadDB();
  const geo=await enrichIP(serverIP, ipData?.ip);
  const ev=detectEvasion(db,{guestId,fpHash:fingerprint?.hash,serverIP,webrtcLocal:webrtc?.localIP,webrtcPublic:webrtc?.publicIP,cookieToken,lsToken});
  if(ev.evading){console.log(`\n[${ts}] 🚨 BLOCKED  guest=${guestId}  reason=${ev.message}`);return res.json({status:'blocked',message:ev.message,serverIP});}
  if(!db.guests[guestId])db.guests[guestId]={guestId,firstSeen:ts,lastSeen:ts,visitCount:0,signals:{fingerprints:[],serverIPs:[],webrtcLocal:[],webrtcPublic:[],cookies:[],lsTokens:[]},geoHistory:[],visits:[]};
  const g=db.guests[guestId];
  g.lastSeen=ts;g.visitCount+=1;
  const add=(arr,v)=>{if(v&&!arr.includes(v))arr.push(v);};
  add(g.signals.fingerprints,fingerprint?.hash);add(g.signals.serverIPs,serverIP);
  add(g.signals.webrtcLocal,webrtc?.localIP);add(g.signals.webrtcPublic,webrtc?.publicIP);
  add(g.signals.cookies,cookieToken);add(g.signals.lsTokens,lsToken);
  if(!g.geoHistory.find(e=>e.ip===serverIP))g.geoHistory.push({ip:serverIP,country:geo.country_name,city:geo.city,isp:geo.org,asn:geo.asn,ts});
  g.visits.push({ts,serverIP,fingerprint:{hash:fingerprint?.hash,canvas:fingerprint?.canvas,webgl:fingerprint?.webgl,audio:fingerprint?.audio,fonts:fingerprint?.fonts,plugins:fingerprint?.plugins},browser:{ua:fingerprint?.userAgent,lang:fingerprint?.language,tz:fingerprint?.timezone,screen:fingerprint?.screen,cpu:fingerprint?.cpuCores,mem:fingerprint?.memory,platform:fingerprint?.platform},clientIP:ipData,webrtc,gyro,session,behavioral,page});
  saveDB(db);
  const left=TRIAL-g.visitCount;
  console.log(`\n[${ts}] VISIT  guest=${guestId}`);
  console.log(`  IP      : ${serverIP} (${geo.country_name||'?'}, ${geo.city||'?'})`);
  console.log(`  FP      : ${fingerprint?.hash||'?'}`);
  console.log(`  WebRTC  : local=${webrtc?.localIP} public=${webrtc?.publicIP}`);
  console.log(`  Gyro    : α=${gyro?.alpha} β=${gyro?.beta} γ=${gyro?.gamma}`);
  console.log(`  Behave  : moves=${behavioral?.mouseMoves} keys=${behavioral?.keyPresses} time=${behavioral?.timeOnPage}s`);
  console.log(`  Visits  : ${g.visitCount}/${TRIAL}`);
  if(g.visitCount>=TRIAL)return res.json({status:'blocked',message:'Free trial ended. Please upgrade.',visitCount:g.visitCount,serverIP});
  if(left<=2)return res.json({status:'warning',message:`Only ${left} free visit${left===1?'':'s'} left.`,visitCount:g.visitCount,serverIP});
  return res.json({status:'clean',message:`${left} free visit${left===1?'':'s'} remaining.`,visitCount:g.visitCount,serverIP});
});
app.post('/api/behavior-update',(req,res)=>{
  const{guestId,behavioral,gyro}=req.body;if(!guestId)return res.status(400).json({ok:false});
  const db=loadDB(),g=db.guests[guestId];if(!g)return res.status(404).json({ok:false});
  const last=g.visits[g.visits.length-1];if(last){last.behavioral=behavioral;last.gyro=gyro;}
  saveDB(db);res.json({ok:true});
});

// ── API ────────────────────────────────────────
app.get('/api/logs',(req,res)=>res.json(loadDB().guests));
app.get('/api/logs/:id',(req,res)=>{const g=loadDB().guests[req.params.id];return g?res.json(g):res.status(404).json({error:'Not found.'});});

// ── Admin dashboard ────────────────────────────
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'admin.html')));

app.delete('/api/logs/clear', (req,res)=>{
  const {password} = req.body;
  if(password !== 'onemfbadmin123') return res.status(403).json({error:'Wrong password.'});
  saveDB({guests:{}});
  console.log(`\n[${new Date().toISOString()}] 🗑️  All guest data cleared by admin.\n`);
  res.json({ok:true, message:'All guest data cleared.'});
});

app.listen(PORT,()=>{
  console.log(`\n🏦  One MFB Tracker running`);
  console.log(`   Site  : http://localhost:${PORT}`);
  console.log(`   Admin : http://localhost:${PORT}/admin`);
  console.log(`   Logs  : GET http://localhost:${PORT}/api/logs\n`);
});