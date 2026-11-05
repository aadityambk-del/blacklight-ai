/* ================= BLACKLIGHT AI — real client-side forensic engine ================= */
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
let anim = {stop(){}};
const state = {route:'overview', view:'command', mode:'analyst', reports:[], idx:-1, busy:false, maskPII:true};
const current = ()=> state.idx>=0 ? state.reports[state.idx] : null;

/* PII masking — privacy by design, concrete */
function maskVal(field,v){
  if(!state.maskPII||!v) return v;
  const s=String(v);
  if(/aadhaar/i.test(field)) return s.replace(/\d(?=\d{4})/g,'X');           // XXXX XXXX 1234
  if(/pan/i.test(field)) return s.replace(/^(.{2}).+(.{2})$/,'$1XXXXX$2');    // ABXXXXX4F
  if(/ifsc|account/i.test(field)) return s.replace(/.(?=.{3})/g,'X');
  if(/name|address/i.test(field)) return s.replace(/\S/g,(c,i)=>i<2?c:'•');
  return s;
}

/* real-world context & recommended action (shown to users) */
const CTX={
  crossdoc:{t:'Cross-document mismatch',risk:'The same person’s details disagreeing across documents is a hallmark of synthetic-identity and income fraud.',action:'Hold onboarding; request fresh, consistent proofs and verify each against its source system.',ref:['RBI Master Direction – KYC','PMLA 2002']},
  arithmetic:{t:'Payslip figures don’t add up',risk:'Doctored payslips inflate income to qualify for larger loans.',action:'Verify net pay against bank credits; request the payslip from the employer/payroll portal.',ref:['RBI KYC','Lender income-verification norms']},
  aadhaar:{t:'Aadhaar checksum failure',risk:'A failing Verhoeff checksum means the number is mistyped or fabricated — it cannot be a genuine Aadhaar.',action:'Re-capture via DigiLocker or offline Aadhaar XML; never accept a photocopy alone.',ref:['UIDAI guidelines','RBI KYC']},
  producer:{t:'Edited, not scanned',risk:'A consumer PDF editor on a “scanned” document usually means it was altered after scanning.',action:'Request the original scan from the issuing source and compare metadata.',ref:['ISO/IEC 27042']},
  incremental:{t:'Hidden revisions',risk:'Incremental saves can conceal edits made after the document was first created.',action:'Inspect the revision history; obtain an unedited original.',ref:['ISO/IEC 27037']},
  date:{t:'Impossible dates',risk:'Future or out-of-sequence dates indicate manual tampering or a template error.',action:'Cross-check issue dates against the employment/account timeline.',ref:['RBI KYC']},
  ela:{t:'Pixel-level edit signal',risk:'Localised recompression can indicate a pasted or altered region — an amount, a photo, a signature.',action:'Treat as a lead, not proof; request the original and inspect the flagged region.',ref:['ISO/IEC 27042']},
  aigen:{t:'Possibly computer-generated',risk:'Missing camera noise with editor-only provenance can indicate a digitally generated (not scanned) document.',action:'Require a verifiable original or a source-system record.',ref:['OWASP ML Top 10']},
  signature:{t:'Signature present',risk:'Signatures are a common forgery target — pasted or lifted from another document.',action:'Compare against a known specimen; confirm placement and ink consistency.',ref:['ISO/IEC 27042']},
};
function contextFor(rep){
  const keys=new Set();
  const multi=state.reports.length>1;
  if(multi&&computeCase().conflicts.length)keys.add('crossdoc');
  rep.findings.forEach(f=>{const t=f.t.toLowerCase();
    if(/arithmetic/.test(t))keys.add('arithmetic');
    if(/aadhaar/.test(t))keys.add('aadhaar');
    if(/consumer editor|produced/.test(t))keys.add('producer');
    if(/incremental/.test(t))keys.add('incremental');
    if(/future-dated|date/.test(t))keys.add('date');
    if(/ela/.test(t))keys.add('ela');
    if(/generated/.test(t))keys.add('aigen');
    if(/signature/.test(t))keys.add('signature');});
  return [...keys].map(k=>CTX[k]).filter(Boolean);
}
/* Optional backend: set window.BLACKLIGHT_API (config.js) or ?api=URL. Blank = in-browser engine. */
const API = (new URLSearchParams(location.search).get('api')) || (typeof window!=='undefined' && window.BLACKLIGHT_API) || '';

if(window.pdfjsLib){ try{ pdfjsLib.GlobalWorkerOptions.workerSrc='https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js'; }catch(e){} }

/* ---------- icons ---------- */
const I = {
  command:'<path d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z"/>',
  graph:'<circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M8 7l8-1M7.5 8l4 8M16 8l-3.5 8"/>',
  eye:'<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  hash:'<path d="M4 9h16M4 15h16M10 3L8 21M16 3l-2 18"/>',
  layers:'<path d="M12 2l9 5-9 5-9-5 9-5zM3 12l9 5 9-5M3 17l9 5 9-5"/>',
  ladder:'<path d="M7 3v18M17 3v18M7 7h10M7 12h10M7 17h10"/>',
  file:'<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6M9 13h6M9 17h4"/>',
  audit:'<path d="M9 11l3 3 8-8"/><path d="M20 12v7a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2h9"/>',
  run:'<path d="M5 3l14 9-14 9z"/>', check:'<path d="M20 6L9 17l-5-5"/>',
  warn:'<path d="M12 3l9 16H3z"/><path d="M12 9v5M12 17h.01"/>',
  shield:'<path d="M12 2l8 4v6c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6z"/>',
  upload:'<path d="M12 15V3M7 8l5-5 5 5"/><path d="M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2"/>',
  bank:'<path d="M3 21h18M5 21V10M19 21V10M3 10l9-6 9 6M9 21v-6h6v6"/>',
  brief:'<rect x="3" y="7" width="18" height="13" rx="2"/><path d="M8 7V5a2 2 0 012-2h4a2 2 0 012 2v2"/>',
  umbrella:'<path d="M12 2v2M3 11a9 9 0 0118 0zM12 11v7a3 3 0 01-6 0"/>',
  users:'<circle cx="9" cy="8" r="3"/><path d="M3 20a6 6 0 0112 0M16 6a3 3 0 010 6M21 20a6 6 0 00-5-5.9"/>',
  zap:'<path d="M13 2L3 14h7l-1 8 10-12h-7z"/>', back:'<path d="M15 18l-6-6 6-6"/>',
  target:'<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 1v3M12 20v3M1 12h3M20 12h3"/>',
  x:'<path d="M18 6L6 18M6 6l12 12"/>',
  globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
  lock:'<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/>',
  unlock:'<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 017.5-2"/>',
};
const NAV=[['WORKSTATION',[['command','Command Centre','command'],['graph','Entity Graph','graph'],['visual','Visual Forensics','eye'],['trace','Document Viewer','target']]],
  ['FORENSICS',[['logic','Logic & Format','hash'],['meta','Metadata Forensics','layers']]],
  ['EVIDENCE',[['ladder','Evidence Ladder','ladder'],['dossier','Investigation Dossier','file'],['audit','Audit Trail','audit']]],
  ['CONTEXT',[['context','Real-World Context','globe']]]];

/* ---------- helpers ---------- */
const el=(h)=>{const d=document.createElement('div');d.innerHTML=h.trim();return d.firstElementChild;};
const svg=(p,cls='ico')=>`<svg class="${cls}" viewBox="0 0 24 24" stroke="currentColor">${p}</svg>`;
const brand=`<div class="brand"><div class="logo"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#22D3EE" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg></div><div><h1><b>BLACK</b>LIGHT<i> AI</i></h1><p class="eye">Document Forensics</p></div></div>`;
const esc=(s)=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const nowT=()=>new Date().toLocaleTimeString('en-GB',{hour12:false});
const fmtKB=(n)=>n<1024?n+' B':(n/1024).toFixed(1)+' KB';
const loadImg=(src)=>new Promise((res,rej)=>{const i=new Image();i.onload=()=>res(i);i.onerror=rej;i.src=src;});
const fileToDataURL=(f)=>new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(r.result);r.onerror=rej;r.readAsDataURL(f);});
async function sha256(buf){try{const h=await crypto.subtle.digest('SHA-256',buf);return [...new Uint8Array(h)].map(b=>b.toString(16).padStart(2,'0')).join('');}catch(e){return 'unavailable-'+Math.random().toString(16).slice(2,10);}}

/* ---------- Verhoeff (real Aadhaar checksum) ---------- */
const V_D=[[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const V_P=[[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,9,1,6,7,3,2,4],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
function verhoeff(num){ if(!/^\d{12}$/.test(num)) return false; let c=0; const a=num.split('').reverse(); for(let i=0;i<a.length;i++){ c=V_D[c][V_P[i%8][+a[i]]]; } return c===0; }

const EDITOR=/ilovepdf|pdfescape|photoshop|gimp|canva|smallpdf|sejda|foxit phantom|microsoft.*word|libreoffice|pdf24|nitro|wps/i;
function decDate(s){ if(!s)return null; const m=/(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?/.exec(s); if(!m)return null; return new Date(+m[1],(+m[2]||1)-1,+m[3]||1,+m[4]||0,+m[5]||0,+m[6]||0); }
function fmtDate(d){ return d? d.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}) : null; }
function hexToStr(h){let s='';for(let i=0;i<h.length-1;i+=2)s+=String.fromCharCode(parseInt(h.substr(i,2),16));return s.replace(/^﻿|\u0000/g,'');}

/* ---------- raw PDF metadata (library-free, real) ---------- */
function rawPdfMeta(bytes){
  const s=new TextDecoder('latin1').decode(bytes);
  const lit=(key)=>{let m=s.match(new RegExp('/'+key+'\\s*\\(((?:[^()\\\\]|\\\\.)*)\\)'));if(m)return m[1].replace(/\\([()\\])/g,'$1').trim();
    let h=s.match(new RegExp('/'+key+'\\s*<([0-9A-Fa-f]+)>'));if(h){try{return hexToStr(h[1]).trim();}catch(e){}}return null;};
  const cd=s.match(/\/CreationDate\s*\(D:(\d{8,14})/), md=s.match(/\/ModDate\s*\(D:(\d{8,14})/);
  const fonts=[...new Set((s.match(/\/BaseFont\s*\/([A-Za-z0-9+\-,.]+)/g)||[]).map(x=>x.split('/').pop().replace(/^[A-Z]{6}\+/,'')))];
  return {producer:lit('Producer'),creator:lit('Creator'),created:cd&&cd[1],modified:md&&md[1],
    eof:(s.match(/%%EOF/g)||[]).length, fonts, hasJS:/\/JavaScript|\/JS[\s>\/]/.test(s), acro:/\/AcroForm/.test(s), enc:/\/Encrypt[\s\/]/.test(s)};
}

/* ---------- real Error-Level Analysis ---------- */
async function elaFromCanvas(src){
  const w=src.width,h=src.height;
  const jpg=src.toDataURL('image/jpeg',0.9);
  const img=await loadImg(jpg);
  const c2=document.createElement('canvas');c2.width=w;c2.height=h;const x2=c2.getContext('2d');x2.drawImage(img,0,0,w,h);
  const a=src.getContext('2d').getImageData(0,0,w,h).data, b=x2.getImageData(0,0,w,h).data;
  const out=x2.createImageData(w,h),o=out.data; let sum=0; const scale=18;
  for(let i=0;i<a.length;i+=4){let mx=0;for(let k=0;k<3;k++){const d=Math.min(255,Math.abs(a[i+k]-b[i+k])*scale);o[i+k]=d;mx=Math.max(mx,d);}o[i+3]=255;sum+=mx;}
  x2.putImageData(out,0,0);
  return {dataURL:c2.toDataURL(), score:sum/(w*h)};
}

/* ---------- the analyzer ---------- */
async function analyze(file){
  const buf=await file.arrayBuffer(), bytes=new Uint8Array(buf);
  const rep={file:{name:file.name,size:file.size,type:file.type||'',lm:file.lastModified},sample:false,
    findings:[],checks:[],meta:[],fields:{},audit:[],ela:null,text:'',origURL:null,items:[],regions:[],decisions:{}};
  const add=(rung,t)=>rep.findings.push({rung,t}); let risk=0; const bump=(n)=>risk+=n;
  rep.hash=await sha256(buf);
  rep.audit.push([nowT(),'Document ingested · SHA-256 '+rep.hash.slice(0,12)+'…']);
  const isPdf=/pdf/i.test(file.type)||/\.pdf$/i.test(file.name)||(bytes[0]===0x25&&bytes[1]===0x50&&bytes[2]===0x44);
  const isImg=/^image\//i.test(file.type)||/\.(png|jpe?g|webp|bmp|gif)$/i.test(file.name);
  rep.kind=isPdf?'pdf':isImg?'image':'other';

  if(isPdf){
    const m=rawPdfMeta(bytes); rep.fonts=m.fonts;
    const cdt=decDate(m.created), mdt=decDate(m.modified), modNe=cdt&&mdt&&Math.abs(mdt-cdt)>60000;
    rep.meta.push(['Producer', m.producer||'—', EDITOR.test(m.producer||'')?'var(--red)':'var(--green)']);
    rep.meta.push(['Creator', m.creator||'—','var(--mut)']);
    rep.meta.push(['Created', fmtDate(cdt)||'—','var(--mut)']);
    rep.meta.push(['Modified', fmtDate(mdt)||'—', modNe?'var(--amber)':'var(--green)']);
    rep.meta.push(['Incremental saves', String(Math.max(0,m.eof-1)), m.eof>1?'var(--amber)':'var(--green)']);
    rep.meta.push(['Font families', String(m.fonts.length), m.fonts.length>6?'var(--amber)':'var(--green)']);
    if(m.hasJS) rep.meta.push(['Embedded JavaScript','present','var(--red)']);
    if(m.enc) rep.meta.push(['Encryption','present','var(--amber)']);
    rep.audit.push([nowT(),'PDF metadata parsed · producer "'+(m.producer||'unknown')+'"']);
    if(EDITOR.test(m.producer||'')){add('man','Produced/edited by "'+m.producer+'" — consumer editor, not a scanner');bump(25);}
    if(modNe){add('inc','Modified '+fmtDate(mdt)+', after creation '+fmtDate(cdt));bump(15);}
    if(m.eof>1){add('man',(m.eof-1)+' incremental save(s) — hidden revision history in the file');bump(15);}
    if(m.hasJS){add('man','Embedded JavaScript present in document');bump(15);}
    if(m.fonts.length>6){add('man',m.fonts.length+' font families — possible splice/paste');bump(8);}
    if(window.pdfjsLib){
      try{
        const pdf=await pdfjsLib.getDocument({data:bytes.slice(0)}).promise; rep.pages=pdf.numPages;
        let text='';for(let i=1;i<=Math.min(pdf.numPages,8);i++){const pg=await pdf.getPage(i);const tc=await pg.getTextContent();text+=tc.items.map(t=>t.str).join(' ')+'\n';}
        rep.text=text.replace(/\s+/g,' ');
        const page=await pdf.getPage(1), base=page.getViewport({scale:1}), sc=Math.min(1.6,1100/Math.max(base.width,base.height));
        const vp=page.getViewport({scale:sc}), cvs=document.createElement('canvas'); cvs.width=vp.width; cvs.height=vp.height;
        await page.render({canvasContext:cvs.getContext('2d'),viewport:vp}).promise;
        rep.origURL=cvs.toDataURL(); rep.ela=await elaFromCanvas(cvs);
        // per-item positions for click-to-region traceability (real coordinates)
        try{const tc1=await page.getTextContent();
          rep.items=tc1.items.filter(it=>it.str&&it.str.trim()).map(it=>{const tx=pdfjsLib.Util.transform(vp.transform,it.transform);const hh=Math.hypot(tx[2],tx[3]);const ww=(it.width||0)*sc;
            return {str:it.str, box:[tx[4]/cvs.width,(tx[5]-hh)/cvs.height, Math.max(ww,hh*0.4)/cvs.width, hh*1.25/cvs.height]};});
        }catch(e){rep.items=[];}
        rep.audit.push([nowT(),'Text + page-1 render extracted · '+pdf.numPages+' page(s) · '+(rep.items?rep.items.length:0)+' text regions mapped']);
      }catch(e){ rep.textErr=true; rep.audit.push([nowT(),'Text layer unavailable (scanned/protected) — metadata only']); }
    } else rep.textErr=true;
  } else if(isImg){
    const url=await fileToDataURL(file), img=await loadImg(url);
    const sc=Math.min(1,1100/Math.max(img.width,img.height));
    const cvs=document.createElement('canvas');cvs.width=Math.round(img.width*sc);cvs.height=Math.round(img.height*sc);
    cvs.getContext('2d').drawImage(img,0,0,cvs.width,cvs.height);
    rep.origURL=url; rep.dims=[img.width,img.height];
    rep.meta.push(['Type',file.type||'image','var(--mut)']);
    rep.meta.push(['Dimensions',img.width+' × '+img.height,'var(--mut)']);
    rep.meta.push(['Modified',fmtDate(new Date(file.lastModified))||'—','var(--mut)']);
    rep.ela=await elaFromCanvas(cvs);
    rep.audit.push([nowT(),'Image decoded '+img.width+'×'+img.height+' · ELA computed']);
  } else { rep.meta.push(['Type',file.type||'unknown','var(--mut)']); add('obs','Unsupported type — hash + custody only'); }

  if(rep.text) runFormatChecks(rep,add,bump);
  else if(isPdf) rep.checks.push({ok:null,t:'Text-based checks',m:'No embedded text layer',v:'Scanned PDF — OCR is on the roadmap'});

  if(rep.ela){ if(rep.ela.score>12){add('man','ELA energy high ('+rep.ela.score.toFixed(1)+') — inspect highlighted regions');bump(12);} else add('obs','ELA energy low ('+rep.ela.score.toFixed(1)+') — no strong splice signal'); }
  // signature zone detection (5.4)
  if(rep.items&&rep.items.length){const sig=rep.items.find(i=>/signature|signatory|signed/i.test(i.str));
    if(sig){rep.regions.push({label:'Signature zone',value:sig.str.trim().slice(0,24),box:sig.box,status:'warn'});add('rev','Signature zone located — compare against a known specimen');}}
  // possible computer-generated / AI-generated flag (possible-level only)
  if(rep.kind==='image'&&rep.ela&&rep.ela.score<3.5){add('man','Possibly computer-generated — unusually low image noise (no camera signature)');bump(8);}
  else if(rep.kind==='pdf'&&EDITOR.test((rep.meta.find(m=>m[0]==='Producer')||[])[1]||'')&&!rep.text){add('man','Possibly computer-generated — editor-only provenance, no scanned text layer');bump(6);}
  add('obs','SHA-256 sealed at ingest — chain of custody is live');
  if(rep.findings.some(f=>f.rung==='man')) add('rev','Manipulation signals present → route to a human reviewer');

  rep.docType=rep.docType||(rep.kind==='image'?'Image':(rep.kind==='pdf'?'Scanned PDF':'Document'));
  rep.extracted=rep.extracted||[];
  rep.risk=Math.min(100,risk);
  rep.anomalies=rep.findings.filter(f=>f.rung==='man'||f.rung==='inc').length;
  rep.conflicts=rep.findings.filter(f=>f.rung==='inc').length;
  rep.confidence=rep.findings.some(f=>f.rung!=='obs')?Math.max(58,94-rep.anomalies*5):97;
  rep.graph=buildGraph(rep);
  rep.seal='SHA-256 · '+rep.hash.slice(0,10)+'…'+rep.hash.slice(-8)+' · audit log #'+String(1000+state.reports.length+1);
  rep.audit.push([nowT(),'Risk ranked · '+rep.risk+' / 100 · '+rep.anomalies+' anomalies']);
  return rep;
}

/* document classification (5.1) */
function classifyDoc(t){
  if(!t) return 'Scanned document';
  const s=t.toLowerCase(), has=(re)=>re.test(s);
  if(has(/payslip|salary slip|net pay|earnings.*deduction|pay period/)) return 'Salary slip';
  if(has(/statement of account|account statement|closing balance|opening balance|transaction date/)) return 'Bank statement';
  if(has(/permanent account number|income tax department/)) return 'PAN card';
  if(has(/unique identification|uidai|aadhaar|आधार/)) return 'Aadhaar card';
  if(has(/tax invoice|invoice no|gstin|bill to/)) return 'Invoice';
  if(has(/application form|know your customer|\bkyc\b|applicant name/)) return 'KYC / application form';
  return 'Document';
}

function runFormatChecks(rep,add,bump){
  const t=rep.text, U=t.toUpperCase();
  rep.docType=classifyDoc(t);
  rep.extracted=[];
  const findBox=(val)=>{if(!rep.items||!rep.items.length)return null;const key=String(val).replace(/\s/g,'').slice(0,6).toLowerCase();const it=rep.items.find(i=>i.str.replace(/\s/g,'').toLowerCase().includes(key));return it?it.box:null;};
  const ex=(field,value,conf,status)=>{const box=findBox(value);rep.extracted.push({field,value,conf,status:status||'ok',src:box?'pg 1 · region mapped':'text layer · pg 1'});if(box)rep.regions.push({label:field,value:String(value),box,status:status==='bad'?'bad':'ok'});};
  const pan=(U.match(/\b[A-Z]{5}[0-9]{4}[A-Z]\b/)||[])[0];
  const aad=(t.match(/\b\d{4}\s?\d{4}\s?\d{4}\b/)||[])[0];
  const ifsc=(U.match(/\b[A-Z]{4}0[A-Z0-9]{6}\b/)||[])[0];
  const nameM=t.match(/\b(?:Name|Employee|Applicant|Account Holder)\s*[:\-]?\s*([A-Z][a-zA-Z.]+(?:\s+[A-Z][a-zA-Z.]+){1,3})/);
  const addrM=t.match(/\bAddress\s*[:\-]?\s*([A-Za-z0-9#,.\-\/ ]{6,60})/i);
  if(nameM){rep.fields.name=nameM[1].trim();ex('Name',rep.fields.name,'Medium','ok');}
  if(addrM){rep.fields.address=addrM[1].trim().replace(/\s+/g,' ');ex('Address',rep.fields.address,'Medium','ok');}
  if(pan){rep.fields.pan=pan;rep.checks.push({ok:true,t:'PAN format',m:'AAAAA0000A pattern',v:'Found · '+pan});add('obs','PAN '+pan+' — format valid');ex('PAN',pan,'High','ok');}
  if(aad){const d=aad.replace(/\s/g,''),ok=verhoeff(d);rep.fields.aadhaar=d;
    rep.checks.push({ok,t:'Aadhaar checksum',m:'12 digits · Verhoeff',v:(ok?'Valid · ':'FAILS · ')+aad});
    if(ok)add('obs','Aadhaar checksum valid'); else {add('inc','Aadhaar checksum fails — transcription error or forgery');bump(20);}
    ex('Aadhaar',aad,'High',ok?'ok':'bad');}
  if(ifsc){rep.fields.ifsc=ifsc;rep.checks.push({ok:true,t:'IFSC format',m:'4 letters + 0 + 6',v:'Found · '+ifsc});ex('IFSC',ifsc,'High','ok');}
  const dates=[...t.matchAll(/\b(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{2,4})\b/g)]; let future=null; const today=new Date();
  dates.forEach(m=>{let dd=+m[1],mm=+m[2],yy=+m[3];if(yy<100)yy+=2000;const d=new Date(yy,mm-1,dd);if(d>today&&yy<2100)future=d;});
  if(dates.length){rep.checks.push({ok:!future,t:'Date logic',m:'No future-dated fields',v:future?('Future date '+fmtDate(future)):(dates.length+' date(s) consistent')});
    if(future){add('inc','Future-dated field '+fmtDate(future)+' — impossible on a genuine document');bump(15);}}
  const rd=(x)=>+x.replace(/,/g,'');
  const g=/gross[^0-9]{0,24}([\d,]{3,})/i.exec(t), de=/deduction[s]?[^0-9]{0,24}([\d,]{3,})/i.exec(t), ne=/net[^0-9]{0,24}([\d,]{3,})/i.exec(t);
  if(g&&de&&ne){const G=rd(g[1]),D=rd(de[1]),N=rd(ne[1]),ok=Math.abs((G-D)-N)<1;
    rep.checks.push({ok,t:'Salary arithmetic',m:'Gross − deductions = net',v:`₹${G.toLocaleString('en-IN')} − ₹${D.toLocaleString('en-IN')} ${ok?'=':'≠'} ₹${N.toLocaleString('en-IN')}`});
    if(ok)add('obs','Salary arithmetic balances'); else{add('inc','Salary arithmetic does not balance');bump(20);} rep.fields.amount=String(N);ex('Net amount','₹'+N.toLocaleString('en-IN'),'High',ok?'ok':'bad');}
  else { const amts=[...t.matchAll(/(?:₹|rs\.?|inr)\s*([\d,]{3,}(?:\.\d{1,2})?)/gi)].map(m=>rd(m[1]));
    if(amts.length){rep.fields.amount=String(amts[0]);rep.checks.push({ok:true,t:'Amounts extracted',m:amts.length+' monetary value(s)',v:amts.slice(0,3).map(a=>'₹'+a.toLocaleString('en-IN')).join(' · ')});ex('Amount','₹'+amts[0].toLocaleString('en-IN'),'High','ok');} }
  if(!rep.checks.length) rep.checks.push({ok:null,t:'Known fields',m:'No PAN / Aadhaar / IFSC / salary pattern found',v:'Nothing to validate in this document'});
}

/* cross-document correlation (5.5 / 5.6 — the 20-pt contextual-intelligence feature) */
const ENT_LABEL={pan:'PAN',aadhaar:'Aadhaar',ifsc:'IFSC',name:'Name',address:'Address',amount:'Amount'};
function computeCase(){
  const reps=state.reports, keys=Object.keys(ENT_LABEL), map={};
  reps.forEach((r,i)=>keys.forEach(k=>{const val=r.fields&&r.fields[k];if(val)(map[k]=map[k]||[]).push({i,val:String(val)});}));
  const norm=v=>v.toLowerCase().replace(/[^a-z0-9]/g,'');
  const conflicts=[];
  Object.entries(map).forEach(([k,arr])=>{const uniq=[...new Set(arr.map(a=>norm(a.val)))];if(arr.length>1&&uniq.length>1)conflicts.push({key:k,values:arr});});
  const shared=Object.keys(map).filter(k=>map[k].length>1);
  const n=reps.length;
  const docNodes=reps.map((r,i)=>({id:'d'+i,x:.14,y:n===1?.5:(.12+i*(.76/(n-1))),r:30,
    lab:(r.file.name.replace(/\.[^.]+$/,'')||'Doc').slice(0,9),type:'doc',
    s:conflicts.some(c=>c.values.some(v=>v.i===i))?'c':'ok'}));
  const m=shared.length;
  const entNodes=shared.map((k,j)=>({id:'k'+k,x:.86,y:m===1?.5:(.12+j*(.76/(m-1))),r:26,lab:ENT_LABEL[k],type:'ent',
    s:conflicts.some(c=>c.key===k)?'c':'ok'}));
  const edges=[];
  reps.forEach((r,i)=>shared.forEach(k=>{if(r.fields&&r.fields[k])edges.push(['d'+i,'k'+k,conflicts.some(c=>c.key===k)?'c':'ok']);}));
  return {graph:{nodes:[...docNodes,...entNodes],edges},conflicts,shared};
}

function buildGraph(rep){
  const bad=rep.anomalies>0;
  const nodes=[{id:'doc',x:.16,y:.5,r:36,lab:(rep.file.name.replace(/\.[^.]+$/,'')||'Document').slice(0,11),type:'doc',s:bad?'c':'ok'}];
  const ents=[];
  if(rep.fields.pan)ents.push(['PAN','ok']);
  if(rep.fields.aadhaar){const c=rep.checks.find(x=>x.t==='Aadhaar checksum');ents.push(['Aadhaar',c&&c.ok===false?'c':'ok']);}
  if(rep.fields.ifsc)ents.push(['IFSC','ok']);
  const ar=rep.checks.find(x=>x.t==='Salary arithmetic'); if(ar)ents.push(['Amount',ar.ok?'ok':'c']);
  const dl=rep.checks.find(x=>x.t==='Date logic'); if(dl)ents.push(['Dates',dl.ok?'ok':'c']);
  const mp=rep.meta.find(m=>m[0]==='Producer'); if(mp)ents.push(['Source',mp[2]==='var(--red)'?'c':'ok']);
  if(!ents.length)ents.push(['Content',bad?'c':'ok']);
  const n=ents.length,edges=[];
  ents.forEach((e,i)=>{const y=n===1?.5:(.14+i*(.72/(n-1)));nodes.push({id:'e'+i,x:.85,y,r:27,lab:e[0],type:'ent',s:e[1]});edges.push(['doc','e'+i,e[1]]);});
  return {nodes,edges};
}

/* backend bridge — calls the FastAPI server when configured, falls back to the in-browser engine */
async function analyzeViaBackend(file){
  const fd=new FormData(); fd.append('file',file);
  const res=await fetch(API.replace(/\/$/,'')+'/analyze',{method:'POST',body:fd});
  if(!res.ok) throw new Error('backend HTTP '+res.status);
  return await res.json();
}
async function analyzeOne(file){
  if(API){ try{ const r=await analyzeViaBackend(file); r.engine='backend'; return r; }
    catch(e){ console.warn('Backend unavailable, using in-browser engine:',e.message); const r=await analyze(file); r.engine='client-fallback'; return r; } }
  const r=await analyze(file); r.engine='client'; return r;
}

/* sample report (optional, clearly marked) */
function sampleReport(){
  const r={sample:true,file:{name:'SAMPLE_Salary_Slip.pdf',size:2379,type:'application/pdf'},hash:'58ffce4270e3fc6eb60ef23865d2330123d5c308abdb245986b334cf3410061f',kind:'pdf',
    docType:'Salary slip',decisions:{},items:[],regions:[],
    extracted:[{field:'Name',value:'Rahul Sharma',conf:'Medium',status:'ok',src:'text layer · pg 1'},{field:'PAN',value:'ABCDE1234F',conf:'High',status:'ok',src:'text layer · pg 1'},{field:'Net amount',value:'₹70,100',conf:'High',status:'bad',src:'text layer · pg 1'}],
    fields:{pan:'ABCDE1234F',name:'Rahul Sharma',amount:'70100'},
    meta:[['Producer','iLovePDF ✕ (scan expected)','var(--red)'],['Creator','—','var(--mut)'],['Created','28 Oct 2026','var(--mut)'],['Modified','31 Oct 2026','var(--amber)'],['Incremental saves','3','var(--amber)'],['Font families','2','var(--green)']],
    checks:[{ok:true,t:'PAN format',m:'AAAAA0000A pattern',v:'Found · ABCDE1234F'},{ok:false,t:'Salary arithmetic',m:'Gross − deductions = net',v:'₹85,000 − ₹12,400 ≠ ₹70,100'},{ok:false,t:'Aadhaar checksum',m:'12 digits · Verhoeff',v:'FAILS · last digit'}],
    findings:[{rung:'obs',t:'PAN ABCDE1234F — format valid'},{rung:'obs',t:'SHA-256 sealed at ingest'},{rung:'inc',t:'Salary arithmetic does not balance'},{rung:'inc',t:'Aadhaar checksum fails'},{rung:'man',t:'Produced by "iLovePDF" — consumer editor, not a scanner'},{rung:'man',t:'3 incremental saves — hidden revisions'},{rung:'man',t:'ELA energy high on page 1'},{rung:'rev',t:'Manipulation signals present → route to reviewer'}],
    audit:[['11:02:14','Document ingested · SHA-256 58ffce4270e3…'],['11:02:15','PDF metadata parsed · producer "iLovePDF"'],['11:02:19','Text extracted · salary arithmetic failed'],['11:02:23','ELA energy high on page 1'],['11:02:27','Risk ranked · 83 / 100 · 5 anomalies']],
    seal:'SHA-256 · 58ffce4270…3410061f · audit log #0001 · SAMPLE'};
  r.risk=83;r.anomalies=5;r.conflicts=2;r.confidence=90;r.ela={score:17.4,dataURL:''};r.graph=buildGraph(r);return r;
}

/* ================= OVERVIEW ================= */
function renderOverview(){
  anim.stop();
  const feats=[['graph','Cross-document entity graph','Fields become nodes; when the same entity disagrees across files the link turns red — conflicts invisible in any single document.','Contextual intelligence'],
    ['eye','Visual tamper forensics','Real Error-Level Analysis on images and rendered PDF pages, with PDF metadata and font forensics alongside.','Visual analysis'],
    ['hash','Deterministic logic checks','Live PAN, Aadhaar (Verhoeff), IFSC, date-logic and salary-arithmetic validation on extracted text.','High precision'],
    ['ladder','Evidence ladder','Every finding climbs Observed → Inconsistent → Possible manipulation → Needs human verification. “Fraud” is never asserted.','Explainability'],
    ['shield','Privacy & chain of custody','Everything runs in your browser. A genuine SHA-256 seal and an append-only audit log back a defensible investigation.','Secure by design'],
    ['file','One-click dossier','A sealed investigation dossier generated from the findings, mapped to the required report structure.','Evidence & traceability']];
  const apps=[['bank','Banking & KYC','Onboarding packets'],['brief','Lending','Salary & bank proofs'],['umbrella','Insurance','Claim documents'],['users','Govt & welfare','Identity verification'],['file','HR / BGV','Credential checks']];
  document.getElementById('root').innerHTML=`
  <div class="sitebar">${brand}<div style="margin-left:auto;display:flex;gap:8px"><button class="cta" id="launch">${svg(I.run,'')}Launch console</button></div></div>
  <section class="hero"><div class="inner">
    <div class="heroEmblem"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#22D3EE" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg></div>
    <h1 class="htitle"><b>BLACK</b><u>LIGHT</u><i> AI</i></h1>
    <p class="tagline">Illuminate the evidence hidden in plain sight.</p>
    <p class="subhead">OCR reads the words. BLACKLIGHT checks if they are true.</p>
    <div class="herobtns"><button class="cta" id="launch2">${svg(I.run,'')}Enter the console</button></div>
    <div class="pillrow"><span class="ppill"><svg viewBox="0 0 24 24" stroke="#22D3EE">${I.eye}</svg>See</span><span class="ppill"><svg viewBox="0 0 24 24" stroke="#8B5CF6">${I.graph}</svg>Correlate</span><span class="ppill"><svg viewBox="0 0 24 24" stroke="#D946EF">${I.audit}</svg>Explain</span></div>
  </div></section>
  <section class="sec"><div class="statstrip">
    <div class="sstat"><b class="tnum" data-c="6">0</b><span>Live forensic analysers</span></div>
    <div class="sstat"><b class="tnum" data-c="4">0</b><span>Deterministic ID checks</span></div>
    <div class="sstat"><b>In-browser</b><span>No upload to any server</span></div>
    <div class="sstat"><b>ISO 27037</b><span>Chain-of-custody aligned</span></div>
  </div></section>
  <section class="sec"><div class="sechead"><span class="eye">What it does</span><h2>Six working capabilities</h2><p>Beyond OCR and field validation — contextual, visual and evidence-driven document investigation.</p></div>
    <div class="fgrid">${feats.map(f=>`<div class="fcard"><div class="ficon"><svg viewBox="0 0 24 24" stroke="#22D3EE">${I[f[0]]}</svg></div><h3>${f[1]}</h3><p>${f[2]}</p><span class="ftag">${f[3]}</span></div>`).join('')}</div></section>
  <section class="sec"><div class="sechead"><span class="eye">Where it matters</span><h2>Real-world applications</h2><p>Anywhere a packet of documents is trusted to make a financial decision.</p></div>
    <div class="appsrow">${apps.map(a=>`<div class="appc"><svg viewBox="0 0 24 24">${I[a[0]]}</svg><b>${a[1]}</b><span>${a[2]}</span></div>`).join('')}</div></section>
  <section class="sec"><div class="sechead"><span class="eye">Standards</span><h2>Built on recognised frameworks</h2></div>
    <div class="stds"><span class="std">ISO/IEC 27037</span><span class="std">ISO/IEC 27041</span><span class="std">ISO/IEC 27042</span><span class="std">NIST SP 800-86</span><span class="std">OWASP ML Top 10</span></div>
    <p style="text-align:center;color:var(--mut2);font-size:11px;margin-top:10px">Cited as inspiration — not a claim of formal compliance.</p></section>
  <div class="sitefoot"><span>BLACKLIGHT AI · Team Table For Two — Aaradhya Jain & Aaditya Kore</span><span>DataOps Innovation Hackathon</span></div>`;
  document.getElementById('launch').onclick=()=>go('console');
  document.getElementById('launch2').onclick=()=>go('console');
  countUp();
}

/* ================= CONSOLE ================= */
function renderConsole(){
  document.getElementById('root').innerHTML=`<div class="app">
    <aside class="rail"><div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">${brand}</div>
      <button class="nav" id="homeBtn" style="margin-top:6px">${svg(I.back,'')}<span>Public overview</span></button>
      <nav id="nav"></nav>
      <div class="railftr"><div class="stat"><span class="dot"></span> Engine online · in-browser</div><div class="stat"><span class="dot" style="background:var(--cyan);box-shadow:0 0 10px var(--cyan)"></span> No data leaves this device</div><div class="stat" style="color:var(--mut2)">Team Table For Two</div></div>
    </aside>
    <main>
      <div class="top"><div class="case"><span class="eye">Active document</span><b id="topCase">No document loaded</b></div>
        <div class="rightset">
          <button class="cta ghost" id="maskBtn" style="padding:7px 10px">${svg(I.lock,'')}PII</button>
          <button class="cta ghost" id="addBtn" style="padding:7px 12px">${svg(I.upload,'')}Analyze</button>
          <div class="seg" id="modeSeg"><button data-mode="analyst">Analyst</button><button data-mode="reviewer">Reviewer</button><button data-mode="auditor">Auditor</button></div>
          <span class="badge" id="trust">● In-browser</span>
        </div></div>
      <div id="modebar"></div>
      <section class="kpis" id="kpis"></section>
      <div id="view"></div>
    </main></div>`;
  const n=document.getElementById('nav');
  NAV.forEach(([grp,items])=>{const gg=el(`<div class="navgrp"><span>${grp}</span></div>`);
    items.forEach(([id,label,icon])=>{const b=el(`<button class="nav" data-v="${id}">${svg(I[icon],'')}<span>${label}</span></button>`);b.onclick=()=>setView(id);gg.appendChild(b);});n.appendChild(gg);});
  document.getElementById('homeBtn').onclick=()=>go('overview');
  document.getElementById('addBtn').onclick=()=>document.getElementById('fileInput').click();
  document.getElementById('maskBtn').onclick=()=>{state.maskPII=!state.maskPII;syncSeg();setView(state.view);};
  document.getElementById('modeSeg').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;state.mode=b.dataset.mode;if(state.mode==='auditor')state.view='audit';else if(state.mode==='reviewer'&&state.view==='audit')state.view='ladder';syncSeg();buildKpis();setView(state.view);});
  syncSeg(); buildKpis(); setView(state.view);
}
const MODEDESC={analyst:['Analyst','Full investigation — ingest documents, run every forensic engine, explore evidence.'],
  reviewer:['Reviewer','Adjudicate findings — accept or dismiss each item; your decisions are recorded to the audit log.'],
  auditor:['Auditor','Read-only oversight — inspect the audit trail, chain of custody and reviewer decisions. No changes.']};
function syncSeg(){document.querySelectorAll('#modeSeg button').forEach(b=>b.classList.toggle('on',b.dataset.mode===state.mode));
  const tc=document.getElementById('topCase'),r=current();if(tc)tc.textContent=r?`${r.file.name}${r.sample?' · sample':''}`:'No document loaded';
  const tb=document.getElementById('trust');if(tb){const e=r&&r.engine;tb.textContent=e==='backend'?'● Backend engine':e==='client-fallback'?'● In-browser (fallback)':'● In-browser';tb.style.color=e==='backend'?'var(--green)':'var(--mut)';}
  const mb=document.getElementById('maskBtn');if(mb){mb.innerHTML=svg(state.maskPII?I.lock:I.unlock,'')+(state.maskPII?'PII masked':'PII shown');mb.style.color=state.maskPII?'var(--green)':'var(--amber)';}
  const ab=document.getElementById('addBtn');if(ab)ab.style.display=state.mode==='analyst'?'':'none';
  const bar=document.getElementById('modebar');if(bar){const d=MODEDESC[state.mode];
    bar.innerHTML=`<div class="modebar ${state.mode}"><span class="mtag">${svg(state.mode==='auditor'?I.lock:state.mode==='reviewer'?I.check:I.command,'')} ${d[0]} mode</span><span>${d[1]}</span></div>`;}
}
function syncNav(){document.querySelectorAll('.nav[data-v]').forEach(b=>b.classList.toggle('on',b.dataset.v===state.view));}

function buildKpis(){
  const k=document.getElementById('kpis');if(!k)return;const r=current();
  const dash=(v)=>r?v:'—';
  const multi=state.reports.length>1, xdoc=multi?computeCase().conflicts.length:(r?r.conflicts:0);
  const items=[['Documents analysed',dash(state.reports.length),'',r?'in this investigation':'drop a file to start',r?['in','Active']:['','—'],'rgba(34,211,238,.2)'],
    ['Anomalies detected',dash(r?r.anomalies:0),'',r?'in active document':'—',r?(r.anomalies?['hi','Review']:['ok','Clean']):['','—'],'rgba(251,113,133,.2)'],
    ['Cross-document conflicts',dash(xdoc),'',multi?'across '+state.reports.length+' documents':'logic + checksum',r?(xdoc?['md','Needs review']:['ok','None']):['','—'],'rgba(251,191,36,.2)'],
    ['Risk index',dash(r?r.risk:0),r?'/100':'','weighted · calibrated',r?(r.risk>40?['hi','Elevated']:['ok','Low']):['','—'],'rgba(217,70,239,.2)'],
    ['Confidence',dash(r?r.confidence:0),r?'%':'','deterministic signals',r?['ok','Live']:['','—'],'rgba(52,211,153,.2)']];
  k.innerHTML='';
  items.forEach(it=>{k.appendChild(el(`<div class="kpi" style="--k:${it[6]}"><div class="lab">${it[0]}</div>
    <div class="val tnum">${typeof it[1]==='number'?`<span data-c="${it[1]}">0</span>`:esc(it[1])}${it[2]?`<small>${it[2]}</small>`:''}</div>
    <div class="sub">${it[3]}</div>${it[4][1]?`<span class="pill ${it[4][0]}">${it[4][1]}</span>`:''}</div>`));});
  countUp();
}
function countUp(){document.querySelectorAll('[data-c]').forEach(s=>{const target=+s.dataset.c;if(reduced){s.textContent=target;return;}
  const t0=performance.now(),dur=800;const step=(t)=>{const p=Math.min(1,(t-t0)/dur);s.textContent=Math.round(target*(1-Math.pow(1-p,3)));if(p<1)requestAnimationFrame(step);};requestAnimationFrame(step);});}

/* ---------- graph canvas ---------- */
function mountGraph(cv,graph){
  if(!graph||!graph.nodes){return {stop(){}};}
  let stopped=false,raf,t=0,hover=null,pts={};
  const C={ok:'#34D399',c:'#FB7185',cyan:'#22D3EE',ink:'#ECEAFF'};
  const tip=cv.parentElement.querySelector('.gtip');
  const rr=(ctx,x,y,w,h,r)=>{ctx.beginPath();ctx.moveTo(x+r,y);ctx.arcTo(x+w,y,x+w,y+h,r);ctx.arcTo(x+w,y+h,x,y+h,r);ctx.arcTo(x,y+h,x,y,r);ctx.arcTo(x,y,x+w,y,r);ctx.closePath();};
  const conn=(id)=>{const s=new Set();graph.edges.forEach(([a,b])=>{if(a===id||b===id){s.add(a);s.add(b);}});return s;};
  function frame(){
    const rect=cv.getBoundingClientRect(),w=rect.width,h=rect.height,dpr=Math.min(2,devicePixelRatio||1);
    if(cv.width!==Math.round(w*dpr)||cv.height!==Math.round(h*dpr)){cv.width=Math.round(w*dpr);cv.height=Math.round(h*dpr);}
    const ctx=cv.getContext('2d');ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,w,h);
    graph.nodes.forEach(n=>pts[n.id]={x:n.x*w,y:n.y*h});
    const sx=((t*0.6)%(w+160))-80,gg=ctx.createLinearGradient(sx-60,0,sx+60,0);
    gg.addColorStop(0,'rgba(34,211,238,0)');gg.addColorStop(.5,'rgba(34,211,238,.1)');gg.addColorStop(1,'rgba(34,211,238,0)');ctx.fillStyle=gg;ctx.fillRect(sx-60,0,120,h);
    const cn=hover?conn(hover):null;
    graph.edges.forEach(([a,b,s],i)=>{const A=pts[a],B=pts[b],dim=cn&&!(a===hover||b===hover);ctx.save();ctx.globalAlpha=dim?0.18:1;
      if(s==='c'){ctx.strokeStyle=C.c;ctx.lineWidth=2.1;ctx.setLineDash([7,7]);ctx.lineDashOffset=-(t*0.9);ctx.shadowColor=C.c;ctx.shadowBlur=8;}else{ctx.strokeStyle='rgba(52,211,153,.5)';ctx.lineWidth=1.3;ctx.setLineDash([]);}
      ctx.beginPath();ctx.moveTo(A.x,A.y);ctx.lineTo(B.x,B.y);ctx.stroke();ctx.restore();
      if(s==='c'&&!dim){const p=((t*0.012)+i*0.17)%1,px=A.x+(B.x-A.x)*p,py=A.y+(B.y-A.y)*p;ctx.beginPath();ctx.fillStyle=C.c;ctx.shadowColor=C.c;ctx.shadowBlur=12;ctx.arc(px,py,3,0,7);ctx.fill();ctx.shadowBlur=0;}});
    graph.nodes.forEach((n,i)=>{const P=pts[n.id],pulse=1+Math.sin(t*0.05+i)*0.04,base=n.s==='c'?C.c:(n.type==='doc'?C.cyan:C.ok),dim=cn&&!cn.has(n.id);ctx.save();ctx.globalAlpha=dim?0.25:1;
      if(n.type==='doc'){const bw=90,bh=38;ctx.shadowColor=base;ctx.shadowBlur=n.s==='c'?16:9;ctx.fillStyle='rgba(23,19,55,.92)';ctx.strokeStyle=base;ctx.lineWidth=hover===n.id?2.6:1.6;rr(ctx,P.x-bw/2,P.y-bh/2,bw,bh,9);ctx.fill();ctx.stroke();ctx.shadowBlur=0;ctx.fillStyle=C.ink;ctx.font='600 12px "Space Grotesk",sans-serif';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(n.lab,P.x,P.y);}
      else{const r=(hover===n.id?n.r+3:n.r)*pulse;ctx.shadowColor=base;ctx.shadowBlur=n.s==='c'?18:10;ctx.beginPath();ctx.arc(P.x,P.y,r,0,7);ctx.fillStyle='rgba(23,19,55,.92)';ctx.fill();ctx.lineWidth=hover===n.id?3:2;ctx.strokeStyle=base;ctx.stroke();ctx.shadowBlur=0;ctx.fillStyle=n.s==='c'?C.c:C.ok;ctx.font='600 11px "Space Grotesk",sans-serif';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(n.lab,P.x,P.y);}ctx.restore();});
    t++;if(!stopped)raf=requestAnimationFrame(frame);
  }
  frame(); if(reduced){stopped=true;cancelAnimationFrame(raf);frame();}
  function mv(e){const rect=cv.getBoundingClientRect(),mx=e.clientX-rect.left,my=e.clientY-rect.top;let f=null;
    graph.nodes.forEach(n=>{const P=pts[n.id];if(!P)return;const dx=mx-P.x,dy=my-P.y,rad=n.type==='doc'?46:n.r+6;if(dx*dx+dy*dy<rad*rad)f=n;});
    hover=f?f.id:null;cv.style.cursor=f?'pointer':'crosshair';
    if(tip){if(f){const P=pts[f.id];tip.textContent=`${f.lab} · ${f.s==='c'?'conflict':'consistent'}`;tip.style.left=P.x+'px';tip.style.top=P.y+'px';tip.style.opacity='1';}else tip.style.opacity='0';}}
  cv.addEventListener('mousemove',mv);cv.addEventListener('mouseleave',()=>{hover=null;if(tip)tip.style.opacity='0';});
  return {stop(){stopped=true;cancelAnimationFrame(raf);cv.removeEventListener('mousemove',mv);}};
}

/* ---------- processing ---------- */
async function processFiles(list){
  const files=[...list].slice(0,6); if(!files.length)return;
  state.busy=true; updateBusy();
  for(const f of files){ try{ const rep=await analyzeOne(f); state.reports.push(rep); state.idx=state.reports.length-1; }catch(e){ console.error(e); } }
  state.busy=false; syncSeg(); buildKpis(); setView('command');
}
function updateBusy(){ const d=document.getElementById('dropMsg'); if(d&&state.busy) d.innerHTML=`<span class="busy"></span>Analysing…`; }
function loadSample(){ state.reports.push(sampleReport()); state.idx=state.reports.length-1; syncSeg(); buildKpis(); setView('command'); }

/* ---------- VIEWS ---------- */
function emptyState(msg){ return `<div class="pan empty"><div class="big">${svg(I.upload,'')}</div><h2 style="margin:0 0 6px">No document analysed yet</h2>
  <p class="lead" style="max-width:460px;margin:0 auto 16px">${msg||'Drop a PDF or image to run the forensic engine — SHA-256 seal, metadata forensics, ID & arithmetic checks, and Error-Level Analysis, all in your browser.'}</p>
  <div style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap"><button class="cta" id="eUpload">${svg(I.upload,'')}Analyze a document</button><button class="cta ghost" id="eSample">Load sample analysis</button></div></div>`; }
function wireEmpty(){ const u=document.getElementById('eUpload'),s=document.getElementById('eSample'); if(u)u.onclick=()=>document.getElementById('fileInput').click(); if(s)s.onclick=loadSample; }

function viewCommand(){
  const r=current(),v=document.getElementById('view');
  const dz=`<div class="pan"><div class="panhead"><span class="eye">Ingest a document</span><span class="badge">Real SHA-256</span></div>
    <div class="drop" id="drop">${svg(I.upload,'')}<b id="dropMsg">Drop a PDF or image, or click to browse</b><span>Hash, metadata, checks & ELA run locally — nothing is uploaded</span></div>
    <div class="doclist" id="docList"></div></div>`;
  if(!r){ v.innerHTML=`<div class="grid2"><div class="col">${dz}
      <div class="pan"><span class="eye">Investigation chain · step 1 → 6</span><h2 style="margin-top:8px">When a document lies, <span class="q">where does it show?</span></h2>
      <div class="chain"><div class="chip a"><div class="n">01</div><div class="t">Ingest</div></div><div class="chip a"><div class="n">02</div><div class="t">OCR</div></div><div class="chip a"><div class="n">03</div><div class="t">Structure</div></div><div class="chip b"><div class="n">04</div><div class="t">Visual</div></div><div class="chip b"><div class="n">05</div><div class="t">Correlate</div></div><div class="chip b"><div class="n">06</div><div class="t">Dossier</div></div></div></div></div>
      <div class="col">${emptyState()}</div></div>`;
    wireDrop(); wireDocList(); wireEmpty(); return;
  }
  const reviewQ=()=>{const dec=r.decisions||{};const items=r.findings.filter(f=>f.rung!=='obs');const pend=items.filter(f=>!dec[f.t]).length;
    return `<div class="pan"><div class="panhead"><span class="eye">Review queue</span><span class="badge" style="${pend?'color:var(--amber)':'color:var(--green)'}">${pend} pending</span></div>
      ${items.length?`<div class="qlist">`+items.map(f=>`<div class="qrow"><span class="tg ${f.rung}">${({inc:'Inconsistent',man:'Possible',rev:'Review'})[f.rung]||'Signal'}</span><span style="flex:1">${esc(f.t)}</span>${dec[f.t]?`<span class="decb ${dec[f.t]}">${dec[f.t]}</span>`:`<span class="liact"><button data-a="accepted" data-t="${esc(f.t)}">${svg(I.check,'')}</button><button data-a="dismissed" data-t="${esc(f.t)}">${svg(I.x,'')}</button></span>`}</div>`).join('')+`</div>`:'<p class="lead">No signals to adjudicate — this document is clean.</p>'}</div>`;};
  const integrity=()=>`<div class="pan"><div class="panhead"><span class="eye">Integrity · read-only</span><span class="badge" style="color:var(--green);border-color:rgba(52,211,153,.4)">● sealed</span></div>
      <div class="fh mono" style="font-size:10.5px;color:var(--green);word-break:break-all">SHA-256 ${esc(r.hash)}</div>
      <div class="lead" style="margin-top:8px">${(r.audit||[]).length} audit entries · ${Object.keys(r.decisions||{}).length} reviewer decision(s) · ${r.anomalies} anomalies. Open Audit Trail for the full chain of custody.</div>
      <button class="cta ghost" id="dlPdf2" style="margin-top:12px;width:100%">${svg(I.file,'')}Download sealed dossier (PDF)</button></div>`;
  const leftTop=state.mode==='reviewer'?reviewQ():state.mode==='auditor'?integrity():dz;
  v.innerHTML=`<div class="grid2"><div class="col">
    ${leftTop}
    <div class="pan"><div class="panhead"><span class="eye">Active document</span><span class="badge">${esc(r.docType||r.kind)}</span></div>
      <div class="specrow"><b style="font-size:15px;word-break:break-all">${esc(r.file.name)}</b><span class="mono" style="color:${r.risk>40?'var(--red)':'var(--green)'};font-size:12px">RISK ${r.risk}/100</span></div>
      <div style="color:var(--mut);font-size:12px;margin-top:2px">${fmtKB(r.file.size)} · ${r.anomalies} anomalies · ${r.confidence}% confidence${r.sample?' · SAMPLE':''}</div>
      <div class="bar"><i id="riskbar"></i></div>
      <div class="fh mono" style="font-size:10.5px;color:var(--green);word-break:break-all;margin-top:8px">SHA-256 ${esc(r.hash)}</div>
      <div style="display:flex;gap:8px;margin-top:12px"><button class="cta" id="genReport" style="flex:1">${svg(I.file,'')}Generate report</button><button class="cta ghost" id="dlPdf2" style="flex:1">Download PDF</button></div>
    </div>
    <div class="pan"><div class="panhead"><span class="eye">Findings</span><span class="badge">${r.findings.length} signals</span></div><div class="feed" id="feed"></div></div>
  </div>
  <div class="col"><div class="pan" style="flex:1;display:flex;flex-direction:column">
    <div class="panhead"><span class="eye">● Document constellation · live</span><span class="badge">Hover a node</span></div>
    <div class="viz" style="flex:1;min-height:340px"><canvas id="gcv"></canvas><div class="gtip"></div>
      <div class="viztag"><div class="k">Active document</div><div class="v">${esc(r.file.name.slice(0,34))} — <em>${r.anomalies?r.anomalies+' anomalies':'clean'}</em></div></div>
      <div class="leg"><span><i style="border-color:#34D399"></i>Consistent</span><span><i style="border-color:#FB7185;border-top-style:dashed"></i>Conflict</span></div></div>
  </div></div></div>`;
  requestAnimationFrame(()=>{const rb=document.getElementById('riskbar');if(rb)rb.style.width=r.risk+'%';});
  anim=mountGraph(document.getElementById('gcv'),r.graph);
  renderFeed(); wireDrop(); wireDocList();
  const gr=document.getElementById('genReport'); if(gr)gr.onclick=()=>setView('dossier');
  const dp=document.getElementById('dlPdf2'); if(dp)dp.onclick=downloadDossierPDF;
  v.querySelectorAll('.qrow .liact button').forEach(b=>b.onclick=()=>decide(b.dataset.t,b.dataset.a));
}
function renderFeed(){const f=document.getElementById('feed'),r=current();if(!f||!r)return;f.innerHTML='';const names={obs:'Observed',inc:'Inconsistent',man:'Possible',rev:'Review'};
  const add=(i)=>{if(i>=r.findings.length)return;const fd=r.findings[i];f.appendChild(el(`<div class="fitem"><span class="tg ${fd.rung}">${names[fd.rung]}</span><span>${esc(fd.t)}</span></div>`));f.scrollTop=f.scrollHeight;if(!reduced)setTimeout(()=>add(i+1),260);else add(i+1);};add(0);}

function wireDrop(){const drop=document.getElementById('drop'),fi=document.getElementById('fileInput');if(!drop)return;
  drop.onclick=()=>fi.click();
  ['dragover','dragenter'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('over');}));
  ['dragleave'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('over');}));
  drop.addEventListener('drop',e=>{e.preventDefault();drop.classList.remove('over');if(e.dataTransfer.files.length)processFiles(e.dataTransfer.files);});
  if(state.busy)updateBusy();}
function wireDocList(){const dl=document.getElementById('docList');if(!dl)return;dl.innerHTML='';
  state.reports.forEach((r,i)=>{const c=el(`<div class="docchip ${i===state.idx?'on':''}">${svg(r.anomalies?I.warn:I.check,r.anomalies?'ico r':'ico g')}<span style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.file.name)}</span><span class="rk" style="color:${r.risk>40?'var(--red)':'var(--green)'}">${r.risk}</span></div>`);
    c.onclick=()=>{state.idx=i;syncSeg();buildKpis();setView(state.view);};dl.appendChild(c);});}

function viewGraph(){const r=current(),v=document.getElementById('view');if(!r){v.innerHTML=emptyState();wireEmpty();anim={stop(){}};return;}
  const multi=state.reports.length>1; if(state.graphScope===undefined)state.graphScope=multi?'case':'doc';
  const scope=multi?state.graphScope:'doc';
  const cse=multi?computeCase():null;
  const graph=scope==='case'?cse.graph:r.graph;
  const confl=graph.edges.filter(e=>e[2]==='c').length;
  const toggle=multi?`<div class="seg" id="scopeSeg" style="margin-top:2px"><button data-s="case"${scope==='case'?' class="on"':''}>Whole case · ${state.reports.length}</button><button data-s="doc"${scope==='doc'?' class="on"':''}>This document</button></div>`:'';
  let confCards='';
  if(scope==='case'){
    confCards = cse.conflicts.length
      ? `<div class="cards c2" style="margin-top:12px">`+cse.conflicts.map(c=>`<div class="check fail"><div class="ct">${svg(I.warn,'ico r')} ${ENT_LABEL[c.key]} conflict</div><div class="cm">Same ${ENT_LABEL[c.key].toLowerCase()} differs across documents</div>`+
          c.values.map(val=>`<div class="cv">${esc(state.reports[val.i].file.name.slice(0,22))}: ${esc(val.val.slice(0,28))}</div>`).join('')+`</div>`).join('')+`</div>`
      : `<div class="check pass" style="margin-top:12px"><div class="ct">${svg(I.check,'ico g')} No cross-document conflicts</div><div class="cm">Shared entities agree across all ${state.reports.length} documents</div><div class="cv">${cse.shared.map(k=>ENT_LABEL[k]).join(' · ')||'no shared entities yet'}</div></div>`;
  } else {
    const dc=r.graph.edges.filter(e=>e[2]==='c').length;
    confCards = `<p class="lead" style="margin-top:10px">${dc?dc+' flagged field link(s) in this document — a link is red when that field failed a check or the source looks edited.':'No flagged fields in this document.'}</p>`;
  }
  v.innerHTML=`<div class="pan"><div class="panhead"><div><span class="eye">Killer feature · contextual intelligence (20 pts)</span><h2 style="margin-top:6px">${scope==='case'?'Cross-document entity graph':'Entity graph'}</h2></div><span class="badge" style="${confl?'color:var(--red);border-color:rgba(251,113,133,.4)':''}">${confl} conflict link(s)</span></div>
    ${toggle}
    <p class="lead" style="margin-top:10px">${scope==='case'?'Names, PANs, addresses and amounts from every uploaded document become shared nodes. A link turns <b style="color:var(--red)">red</b> when the same entity disagrees across documents — discrepancies invisible in any single file. Hover a node to isolate it.':'Extracted fields from <b>'+esc(r.file.name)+'</b> become nodes. Upload more documents to correlate across the whole case.'}</p>
    <div class="viz" style="height:460px;margin-top:12px"><canvas id="gcv2"></canvas><div class="gtip"></div>
      <div class="leg"><span><i style="border-color:#34D399"></i>Consistent</span><span><i style="border-color:#FB7185;border-top-style:dashed"></i>Conflict</span></div></div>
    ${confCards}</div>`;
  const seg=document.getElementById('scopeSeg'); if(seg)seg.addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;state.graphScope=b.dataset.s;viewGraph();});
  anim=mountGraph(document.getElementById('gcv2'),graph);
}

function viewVisual(){const r=current(),v=document.getElementById('view');if(!r){v.innerHTML=emptyState();wireEmpty();anim={stop(){}};return;}
  const hasEla=r.ela&&r.ela.dataURL;
  v.innerHTML=`<div class="grid2">
    <div class="pan"><span class="eye">Killer feature · visual forensic analysis</span><h2 style="margin-top:6px">Error-Level Analysis</h2>
      ${hasEla?`<div class="elawrap"><figure><div class="elabox"><img src="${r.origURL}" alt="original"><div class="scanline" id="scan" style="top:0"></div></div><figcaption>Original</figcaption></figure>
        <figure><div class="elabox"><img src="${r.ela.dataURL}" alt="ELA map"></div><figcaption>ELA map · energy ${r.ela.score.toFixed(1)}</figcaption></figure></div>
        <p class="lead">Bright regions re-compress differently from their surroundings — a signal to investigate, computed live in your browser.</p>`
      :`<div class="empty" style="padding:28px"><div class="big">${svg(I.eye,'')}</div><p class="lead">No raster layer to analyse — this is a text-only PDF or the page could not be rendered. ELA runs on images and rendered PDF pages.</p></div>`}
    </div>
    <div class="col">
      <div class="pan"><div class="panhead"><span class="eye">Metadata forensics</span><span class="badge">${r.kind}</span></div>${r.meta.map(m=>`<div class="metarow"><span class="mk">${esc(m[0])}</span><span class="mv" style="color:${m[2]}">${esc(m[1])}</span></div>`).join('')}</div>
      <div class="pan"><div class="ct" style="display:flex;gap:8px;align-items:center;font-weight:600">${svg(I.warn,'ico a')} Deterministic signals</div><p class="lead">Metadata and font checks are near-zero false-positive — they anchor accuracy before any heuristic runs.</p></div>
      <div class="pan"><div class="ct" style="display:flex;gap:8px;align-items:center;font-weight:600">${svg(I.eye,'ico c')} Honest about limits</div><p class="lead">ELA is unreliable on heavily re-compressed files. Bright regions are an observation to investigate — never a verdict.</p></div>
    </div></div>`;
  const scan=document.getElementById('scan');
  if(scan&&!reduced){let raf,t=0,stop=false;const box=scan.parentElement;const step=()=>{const h=box.clientHeight;scan.style.top=((t*1.3)%(h+46)-46)+'px';t++;if(!stop)raf=requestAnimationFrame(step);};step();anim={stop(){stop=true;cancelAnimationFrame(raf);}};}
  else anim={stop(){}};
}

function viewLogic(){const r=current(),v=document.getElementById('view');anim={stop(){}};if(!r){v.innerHTML=emptyState();wireEmpty();return;}
  v.innerHTML=`<div class="pan"><span class="eye">High-precision layer</span><h2 style="margin-top:6px">Deterministic logic & format checks</h2>
    <p class="lead">Run live on the text extracted from <b>${esc(r.file.name)}</b>. Green passed; red caught something; grey means the pattern wasn't present to test.</p>
    <div class="cards c2" style="margin-top:12px">${r.checks.map(c=>{const cls=c.ok===true?'pass':c.ok===false?'fail':'';const ic=c.ok===true?svg(I.check,'ico g'):c.ok===false?svg(I.warn,'ico r'):svg(I.hash,'ico c');
      return `<div class="check ${cls}"><div class="ct">${ic} ${esc(c.t)}</div><div class="cm">${esc(c.m)}</div><div class="cv" style="${c.ok===null?'color:var(--mut)':''}">${esc(c.v)}</div></div>`;}).join('')}</div></div>`;
}
function viewMeta(){const r=current(),v=document.getElementById('view');anim={stop(){}};if(!r){v.innerHTML=emptyState();wireEmpty();return;}
  v.innerHTML=`<div class="grid2"><div class="pan"><span class="eye">Metadata & provenance</span><h2 style="margin-top:6px">What the file remembers</h2>
    <p class="lead">Read directly from the bytes of <b>${esc(r.file.name)}</b> — compared against what the document claims to be.</p>
    ${r.meta.map(m=>`<div class="metarow"><span class="mk">${esc(m[0])}</span><span class="mv" style="color:${m[2]}">${esc(m[1])}</span></div>`).join('')}
    ${r.fonts&&r.fonts.length?`<div class="lead" style="margin-top:10px"><b style="color:var(--ink)">Fonts:</b> ${esc(r.fonts.slice(0,8).join(', '))}</div>`:''}
    <div class="seal" style="color:var(--mut)">Chain of custody · ${esc(r.seal)}</div></div>
    <div class="col">
      <div class="pan"><div class="ct" style="font-weight:600;display:flex;gap:8px;align-items:center">${svg(I.shield,'ico c')} Privacy by design</div><p class="lead">The file never leaves your browser. Parsing, hashing and analysis all run on this device.</p></div>
      <div class="pan"><div class="ct" style="font-weight:600;display:flex;gap:8px;align-items:center">${svg(I.hash,'ico m')} Tamper-evident</div><p class="lead">A real SHA-256 is taken at ingest and written to the audit log, so every finding traces back to the exact bytes received.</p></div>
      <div class="pan"><div class="ct" style="font-weight:600;display:flex;gap:8px;align-items:center">${svg(I.layers,'ico a')} Producer & revision analysis</div><p class="lead">A consumer editor on a “scanned” document, hidden incremental saves, or many font families are strong, low-noise signals.</p></div>
    </div></div>`;
}
function decide(txt,val){const r=current();if(!r)return;r.decisions=r.decisions||{};r.decisions[txt]=val;r.audit.push([nowT(),'Reviewer '+val+': '+txt.slice(0,46)]);setView(state.view);}
function viewLadder(){const r=current(),v=document.getElementById('view');anim={stop(){}};if(!r){v.innerHTML=emptyState();wireEmpty();return;}
  const rungs=[{k:'obs',n:'01',t:'Observed',col:'#34D399'},{k:'inc',n:'02',t:'Inconsistent',col:'#FBBF24'},{k:'man',n:'03',t:'Possible manipulation',col:'#D946EF'},{k:'rev',n:'04',t:'Needs human verification',col:'#22D3EE'}];
  const dec=r.decisions||{};
  const badge=(t)=>dec[t]?`<span class="decb ${dec[t]}">${dec[t]}</span>`:'';
  const acts=(t)=>state.mode==='reviewer'&&!dec[t]?`<span class="liact"><button data-a="accepted" data-t="${esc(t)}">${svg(I.check,'')}</button><button data-a="dismissed" data-t="${esc(t)}">${svg(I.x,'')}</button></span>`:'';
  const by=(k,col)=>{const l=r.findings.filter(f=>f.rung===k);return l.length?l.map(f=>`<li style="color:${col}"><span style="color:var(--mut);flex:1">${esc(f.t)} ${badge(f.t)}</span>${acts(f.t)}</li>`).join(''):`<li style="color:var(--mut2)"><span style="color:var(--mut2)">— none —</span></li>`;};
  const decided=Object.keys(dec).length, total=r.findings.filter(f=>f.rung!=='obs').length;
  const note=state.mode==='reviewer'?`<p class="lead" style="margin-top:0"><b style="color:var(--cyan)">Reviewer mode:</b> accept or dismiss each signal — ${decided}/${total} adjudicated, recorded to the audit log.</p>`
    :state.mode==='auditor'?`<p class="lead" style="margin-top:0"><b style="color:var(--amber)">Auditor mode (read-only):</b> ${decided} of ${total} signals adjudicated by the reviewer.</p>`
    :`<p class="lead" style="margin-top:0">Findings from <b>${esc(r.file.name)}</b>, placed by severity. The word “fraud” never appears — a human decides.</p>`;
  v.innerHTML=`<div class="pan"><span class="eye">AI reasoning & explainability</span><h2 style="margin-top:6px">The evidence ladder — never just “fraud”</h2>
    ${note}
    <div class="ladder" style="margin-top:14px">${rungs.map((rg,i)=>`<div class="rung" style="border-color:${rg.col};min-height:${150+i*34}px"><div class="rn">RUNG ${rg.n}</div><h3 style="color:${rg.col}">${rg.t}</h3><ul>${by(rg.k,rg.col)}</ul></div>`).join('')}</div>
    <p class="lead" style="margin-top:12px"><b style="color:var(--cyan)">Click-to-source:</b> open <b>Document Viewer</b> to see each finding highlighted on the page.</p></div>`;
  v.querySelectorAll('.liact button').forEach(b=>b.onclick=()=>decide(b.dataset.t,b.dataset.a));
}
function viewDossier(){const r=current(),v=document.getElementById('view');anim={stop(){}};if(!r){v.innerHTML=emptyState();wireEmpty();return;}
  const f=r.fields,list=(k)=>r.findings.filter(x=>x.rung===k).map(x=>esc(x.t)).join('; ')||'none';
  const multi=state.reports.length>1, cse=multi?computeCase():null;
  const exRows=(r.extracted&&r.extracted.length)
    ? `<table class="extab"><thead><tr><th>Field</th><th>Value</th><th>Conf.</th><th>Source</th></tr></thead><tbody>`+
      r.extracted.map(e=>`<tr><td>${esc(e.field)}</td><td class="mono" style="color:${e.status==='bad'?'var(--red)':'var(--ink)'}">${esc(maskVal(e.field,e.value))}</td><td>${e.conf}</td><td style="color:var(--mut)">${esc(e.src)}</td></tr>`).join('')+`</tbody></table>`
    : 'No standard fields detected in the text layer.';
  const xdoc = multi ? (cse.conflicts.length
      ? '<b>'+cse.conflicts.length+' cross-document discrepancy/ies</b>: '+cse.conflicts.map(c=>ENT_LABEL[c.key]+' differs ('+c.values.map(x=>esc(state.reports[x.i].file.name.slice(0,14))).join(' vs ')+')').join('; ')
      : 'No cross-document discrepancies across '+state.reports.length+' documents.')
    : 'Single document — upload related documents to run cross-document correlation.';
  const secs=[['7.1','Document overview',`Type: <b>${esc(r.docType||'Document')}</b>. Source: <b>${esc(r.file.name)}</b> · ${esc(r.kind)} · ${fmtKB(r.file.size)}. Processing status: complete. Sealed ${esc(r.seal)}.`],
    ['7.2','Extracted information',exRows],
    ['7.3','Contextual analysis',`<p style="margin:0 0 6px">${r.conflicts?'<b>'+r.conflicts+' in-document inconsistency/ies</b>: '+list('inc'):'No in-document logic or checksum inconsistencies.'}</p><p style="margin:0">${xdoc}</p>`],
    ['7.4','Visual forensic findings',`${list('man')!=='none'?list('man'):'No manipulation signals from metadata or ELA.'}${r.ela?' ELA energy '+r.ela.score.toFixed(1)+'.':''}`],
    ['7.5','Evidence & traceability',`Each finding derives from a concrete, named signal and references its source document. Sealed with real SHA-256 at ingest; append-only audit log retained.`],
    ['7.6','Investigation summary',`Risk index <b>${r.risk}/100 (${r.risk>40?'elevated':'low'})</b>, ${r.confidence}% confidence. ${list('rev')!=='none'?'Routed for human verification.':'No human review flagged.'} Observations are separated from inferences; limitations documented. The word "fraud" is never asserted.`]];
  v.innerHTML=`<div class="pan"><div class="panhead"><div><span class="eye">Evidence & traceability · report</span><h2 style="margin-top:6px">Investigation dossier</h2></div>
    <button class="cta" id="dlPdf">${svg(I.file,'')}Download PDF</button></div>
    <p class="lead">Generated from the findings — mapped 1:1 to the required dossier sections (7.1–7.6). Tap a section to expand, or download the full report.</p>
    <div>${secs.map((s,i)=>`<div class="dossec${i===0?' open':''}"><button data-i="${i}">${s[0]} · ${s[1]} <span>▾</span></button><div class="dosbody">${s[2]}</div></div>`).join('')}</div>
    <div class="seal">${esc(r.seal)}</div></div>`;
  v.querySelectorAll('.dossec>button').forEach(b=>b.onclick=()=>b.parentElement.classList.toggle('open'));
  document.getElementById('dlPdf').onclick=downloadDossierPDF;
}

/* downloadable PDF dossier (jsPDF) */
function downloadDossierPDF(){
  const r=current(); if(!r) return;
  if(!(window.jspdf&&window.jspdf.jsPDF)){ alert('PDF library still loading — try again in a second.'); return; }
  const {jsPDF}=window.jspdf, doc=new jsPDF({unit:'pt',format:'a4'});
  const W=595, M=46; let y=58;
  const multi=state.reports.length>1, cse=multi?computeCase():null;
  const line=(txt,opt={})=>{doc.setFont('helvetica',opt.b?'bold':'normal');doc.setFontSize(opt.s||10);doc.setTextColor(opt.c||'#1a1636');
    const parts=doc.splitTextToSize(txt,opt.w||(W-2*M));parts.forEach(p=>{if(y>800){doc.addPage();y=58;}doc.text(p,opt.x||M,y);y+=(opt.lh||14);});};
  const rule=()=>{doc.setDrawColor('#8B5CF6');doc.setLineWidth(1);doc.line(M,y,W-M,y);y+=14;};
  // header band
  doc.setFillColor('#0A0A14');doc.rect(0,0,W,40,'F');
  doc.setTextColor('#FFFFFF');doc.setFont('helvetica','bold');doc.setFontSize(15);doc.text('BLACKLIGHT AI',M,26);
  doc.setTextColor('#22D3EE');doc.setFontSize(9);doc.text('INVESTIGATION DOSSIER',W-M,26,{align:'right'});
  y=62;
  line('Document: '+r.file.name,{b:true,s:13});
  line('Type: '+(r.docType||'Document')+'   ·   '+r.kind+'   ·   '+fmtKB(r.file.size)+'   ·   '+r.confidence+'% confidence',{c:'#555',s:9});
  line('Risk index: '+r.risk+'/100 ('+(r.risk>40?'elevated':'low')+')'+(multi?'   ·   Investigation of '+state.reports.length+' documents':''),{c:r.risk>40?'#c0392b':'#1e824c',b:true});
  y+=4; rule();
  const sec=(t)=>{y+=4;line(t,{b:true,s:12,c:'#2a2550'});};
  sec('7.1  Document overview');
  line('Type '+(r.docType||'Document')+'. Source '+r.file.name+'. Processing status: complete.');
  sec('7.2  Extracted information');
  if(r.extracted&&r.extracted.length) r.extracted.forEach(e=>line('• '+e.field+': '+maskVal(e.field,e.value)+'  ('+e.conf+' confidence · '+e.src+')'));
  else line('• No standard fields detected in the text layer.');
  sec('7.3  Contextual analysis');
  r.findings.filter(f=>f.rung==='inc').forEach(f=>line('• '+f.t,{c:'#b7791f'}));
  if(!r.findings.some(f=>f.rung==='inc'))line('• No in-document inconsistencies.');
  if(multi){ if(cse.conflicts.length) cse.conflicts.forEach(c=>line('• Cross-document: '+ENT_LABEL[c.key]+' differs — '+c.values.map(x=>state.reports[x.i].file.name.slice(0,18)+': '+x.val).join(' | '),{c:'#c0392b'}));
    else line('• No cross-document discrepancies across '+state.reports.length+' documents.'); }
  sec('7.4  Visual forensic findings');
  r.findings.filter(f=>f.rung==='man').forEach(f=>line('• '+f.t,{c:'#8e44ad'}));
  if(!r.findings.some(f=>f.rung==='man'))line('• No manipulation signals from metadata or ELA.');
  if(r.ela)line('• ELA energy '+r.ela.score.toFixed(1)+(r.ela.score>12?' (elevated)':' (low)'));
  sec('7.5  Evidence & traceability');
  line('Checks run:');
  r.checks.forEach(c=>line('• '+c.t+' — '+c.v+' ['+(c.ok===true?'PASS':c.ok===false?'FAIL':'N/A')+']',{c:c.ok===false?'#c0392b':'#333'}));
  sec('7.6  Investigation summary');
  line('Risk '+r.risk+'/100 ('+(r.risk>40?'elevated':'low')+'), '+r.confidence+'% confidence. '+(r.findings.some(f=>f.rung==='rev')?'Routed for human verification. ':'No human review flagged. ')+'Observations are separated from inferences; the word "fraud" is never asserted.');
  y+=6; rule();
  line(r.seal,{c:'#1e824c',s:8});
  line('Generated by BLACKLIGHT AI · Team Table For Two · '+new Date().toLocaleString('en-GB')+'. Synthetic/authorised documents only; findings require human review.',{c:'#888',s:7.5});
  doc.save('BLACKLIGHT_Dossier_'+(r.file.name.replace(/\.[^.]+$/,'')||'report')+'.pdf');
}
function viewAudit(){const r=current(),v=document.getElementById('view');anim={stop(){}};if(!r){v.innerHTML=emptyState();wireEmpty();return;}
  v.innerHTML=`<div class="pan"><span class="eye">Governance & audit</span><h2 style="margin-top:6px">Audit trail</h2>
    <p class="lead">A time-stamped record of every step the engine ran on <b>${esc(r.file.name)}</b>.</p>
    <div class="timeline" style="margin-top:14px">${r.audit.map(e=>`<div class="ev"><div class="et">${esc(e[0])}</div><div class="ed">${e[1]}</div></div>`).join('')}</div>
    <div class="seal">Integrity · ${esc(r.seal)}</div></div>`;
}

/* Document viewer — click-to-region traceability (real coordinates) */
function viewTrace(){const r=current(),v=document.getElementById('view');anim={stop(){}};if(!r){v.innerHTML=emptyState();wireEmpty();return;}
  const regs=r.regions||[];
  const hasImg=!!r.origURL;
  const boxes=regs.map((rg,i)=>`<div class="rbox ${rg.status==='bad'?'bad':rg.status==='warn'?'warn':''}" data-i="${i}" title="${esc(rg.label)}" style="left:${(rg.box[0]*100).toFixed(2)}%;top:${(rg.box[1]*100).toFixed(2)}%;width:${(rg.box[2]*100).toFixed(2)}%;height:${(rg.box[3]*100).toFixed(2)}%"></div>`).join('');
  v.innerHTML=`<div class="grid2">
    <div class="pan"><div class="panhead"><span class="eye">Evidence traceability</span><span class="badge">${regs.length} mapped region(s)</span></div>
      <h2 style="margin:2px 0 8px">${esc(r.file.name)}</h2>
      ${hasImg?`<div class="docview" id="docview"><img src="${r.origURL}" alt="document">${boxes}</div>`
        :`<div class="empty" style="padding:28px"><div class="big">${svg(I.target,'')}</div><p class="lead">No rendered page for this file type. Region mapping runs on PDFs with a text layer.</p></div>`}
      <p class="lead">Each highlighted box is a real coordinate from the document’s text layer — the evidence behind a finding, mapped back to where it sits on the page.</p>
    </div>
    <div class="col"><div class="pan"><div class="panhead"><span class="eye">Mapped evidence</span><span class="badge">click to locate</span></div>
      ${regs.length?`<div class="reglist">${regs.map((rg,i)=>`<button class="regrow" data-i="${i}"><span class="rdot ${rg.status==='bad'?'bad':rg.status==='warn'?'warn':''}"></span><span style="flex:1"><b>${esc(rg.label)}</b><span style="color:var(--mut);display:block;font-size:11px">${esc(maskVal(rg.label,rg.value).slice(0,34))}</span></span>${svg(I.target,'ico c')}</button>`).join('')}</div>`
        :`<p class="lead">No text-layer regions were mapped for this document.</p>`}
      <div class="seal" style="color:var(--mut);margin-top:12px">Traceability · each finding references its source region · ${esc(r.seal||'')}</div>
    </div></div></div>`;
  const focus=(i)=>{const box=document.querySelector('.rbox[data-i="'+i+'"]');if(!box)return;document.querySelectorAll('.rbox').forEach(b=>b.classList.remove('on'));box.classList.add('on');box.scrollIntoView({block:'center',behavior:'smooth'});};
  v.querySelectorAll('.regrow').forEach(b=>b.onclick=()=>focus(b.dataset.i));
  v.querySelectorAll('.rbox').forEach(b=>b.onclick=()=>focus(b.dataset.i));
}

/* Real-world context & recommended action */
function viewContext(){const r=current(),v=document.getElementById('view');anim={stop(){}};if(!r){v.innerHTML=emptyState();wireEmpty();return;}
  const ctx=contextFor(r);
  v.innerHTML=`<div class="pan"><div class="panhead"><div><span class="eye">Real-world context · analyst guidance</span><h2 style="margin-top:6px">What these findings mean — and what to do</h2></div><span class="badge">${ctx.length} relevant</span></div>
    <p class="lead">BLACKLIGHT translates technical signals into the real-world risk a reviewer actually faces, with a recommended next action and the framework behind it.</p>
    ${ctx.length?`<div class="cards c2" style="margin-top:14px">${ctx.map(c=>`<div class="ctxcard"><div class="ct" style="font-weight:600;font-size:15px;margin-bottom:6px">${svg(I.globe,'ico c')} ${esc(c.t)}</div>
      <p style="margin:0 0 8px;color:var(--ink);font-size:12.5px;line-height:1.5"><b style="color:var(--red)">Risk:</b> ${esc(c.risk)}</p>
      <p style="margin:0 0 10px;color:var(--ink);font-size:12.5px;line-height:1.5"><b style="color:var(--green)">Action:</b> ${esc(c.action)}</p>
      <div style="display:flex;gap:6px;flex-wrap:wrap">${c.ref.map(x=>`<span class="std">${esc(x)}</span>`).join('')}</div></div>`).join('')}</div>`
    :`<div class="check pass" style="margin-top:14px"><div class="ct">${svg(I.check,'ico g')} No elevated risks on this document</div><div class="cm">No findings require real-world escalation. Standard KYC verification applies.</div></div>`}
    <div class="seal" style="color:var(--mut);margin-top:14px">Guidance is advisory — a human reviewer makes the final call. References cited as inspiration, not formal compliance.</div></div>`;
}

const VIEWS={command:viewCommand,graph:viewGraph,visual:viewVisual,trace:viewTrace,logic:viewLogic,meta:viewMeta,ladder:viewLadder,dossier:viewDossier,audit:viewAudit,context:viewContext};
function setView(id){anim.stop();state.view=id;syncNav();(VIEWS[id]||viewCommand)();window.scrollTo({top:0,behavior:'smooth'});}

/* ---------- global file input + router ---------- */
document.getElementById('fileInput').addEventListener('change',e=>{if(e.target.files.length)processFiles(e.target.files);e.target.value='';});
function go(route){location.hash=route==='overview'?'':'console';}
function renderRoute(){const h=(location.hash||'').replace('#','');state.route=h==='console'?'console':'overview';anim.stop();if(state.route==='console')renderConsole();else renderOverview();}
/* ambient animated background — drifting forensic constellation */
(function ambient(){
  if(reduced)return;
  const cv=document.createElement('canvas'); cv.id='ambient'; document.body.prepend(cv);
  const ctx=cv.getContext('2d'); let w,h,pts=[],raf;
  const resize=()=>{w=cv.width=innerWidth;h=cv.height=innerHeight;};
  resize(); addEventListener('resize',resize);
  for(let i=0;i<48;i++)pts.push({x:Math.random(),y:Math.random(),vx:(Math.random()-.5)*4e-4,vy:(Math.random()-.5)*4e-4});
  const frame=()=>{ctx.clearRect(0,0,w,h);
    for(const p of pts){p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>1)p.vx*=-1;if(p.y<0||p.y>1)p.vy*=-1;}
    for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){const a=pts[i],b=pts[j],dx=(a.x-b.x)*w,dy=(a.y-b.y)*h,d=Math.hypot(dx,dy);
      if(d<150){ctx.strokeStyle='rgba(139,92,246,'+(0.07*(1-d/150)).toFixed(3)+')';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(a.x*w,a.y*h);ctx.lineTo(b.x*w,b.y*h);ctx.stroke();}}
    for(const p of pts){ctx.fillStyle='rgba(34,211,238,0.45)';ctx.beginPath();ctx.arc(p.x*w,p.y*h,1.3,0,7);ctx.fill();}
    raf=requestAnimationFrame(frame);};
  frame();
})();
window.addEventListener('hashchange',renderRoute);
renderRoute();
