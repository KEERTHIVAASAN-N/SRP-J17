
// content.js - analyze page and send mlProb to background
class DOMAnalyzer {
  constructor(){
    this.mlModel = null;
    this.init();
    this.initML();
  }
  initML(){
    try{
      if(typeof PhishingMLModel === 'undefined'){
        setTimeout(()=>this.initML(),300);
        return;
      }
      this.mlModel = new PhishingMLModel();
      this.mlModel.ready().then(()=>console.log('Content ML ready:', this.mlModel.isModelLoaded)).catch(()=>{});
    }catch(e){ console.warn(e); this.mlModel=null; }
  }
  init(){
    if(document.readyState==='loading'){
      document.addEventListener('DOMContentLoaded', ()=>this.analyzePage());
    } else this.analyzePage();
  }
  extractDOMFeatures(){
    const features={};
    const forms=document.querySelectorAll('form');
    features.hasLoginForm=false; features.formActionMismatch=false; features.hasAutoSubmitForm=false;
    forms.forEach(form=>{
      const inputs=form.querySelectorAll('input');
      const hasPassword=Array.from(inputs).some(i=> (i.type && i.type.toLowerCase()==='password') || (i.name && i.name.toLowerCase().includes('password')));
      const hasEmail=Array.from(inputs).some(i=> (i.type && i.type.toLowerCase()==='email') || (i.name && i.name.toLowerCase().includes('email')));
      if(hasPassword||hasEmail){
        features.hasLoginForm=true;
        const formAction=form.action||form.getAttribute('action')||'';
        try{ const actionUrl=new URL(formAction, window.location.href); if(actionUrl.hostname!==window.location.hostname) features.formActionMismatch=true; }catch(e){ features.formActionMismatch=true; }
        if(form.hasAttribute('onsubmit')||form.querySelector('script')) features.hasAutoSubmitForm=true;
      }
    });
    const scripts=document.querySelectorAll('script[src]');
    features.externalScriptCount=0; scripts.forEach(s=>{ try{ const u=new URL(s.src, window.location.href); if(u.hostname!==window.location.hostname) features.externalScriptCount++; }catch(e){ features.externalScriptCount++; } });
    features.hasUrgentLanguage=/urgent.{0,20}action/i.test(document.body?.innerText||'')||/verify.{0,20}immediately/i.test(document.body?.innerText||'');
    features.hasPopups=document.querySelectorAll('[onclick*="window.open"], [onclick*="popup"]').length>0;
    features.numForms=document.querySelectorAll('form').length;
    features.numInputs=document.querySelectorAll('input,textarea,select').length;
    features.hasIframe=document.querySelectorAll('iframe').length>0;
    return features;
  }
  async analyzePage(){
    try{
      const domFeatures=this.extractDOMFeatures();
      let mlProb=null;
      if(this.mlModel && this.mlModel.isModelLoaded){
        try{
          const url=window.location.href;
          const urlFeatures={url, urlLength:url.length, hasIP:/\b\d{1,3}\./.test(window.location.hostname)?1:0, subdomainCount:window.location.hostname.split('.').length-2, hasHttps:window.location.protocol==='https:', hasSuspiciousChars:/[^\x00-\x7F]/.test(window.location.href)?1:0, hasUrlShortener:/(bit\.ly|tinyurl|t\.co|goo\.gl)/.test(window.location.href)?1:0, mimicsLegitimate:false};
          const {arr}=this.mlModel.extractMLFeatures(urlFeatures, domFeatures);
          mlProb = await this.mlModel.predictPhishing({arr});
          console.log('Content ML prob', mlProb);
        }catch(e){ console.warn('ml predict content failed', e); }
      }
      chrome.runtime.sendMessage({type:'ANALYZE_PAGE', domFeatures, mlProb, url:window.location.href}, (resp)=>{ if(resp && resp.level && resp.level!=='safe') this.showWarning(resp); });
    }catch(e){ console.error(e); }
  }
  showWarning(resp){
    if(resp.whitelisted) return;
    if(resp.level==='dangerous' || resp.level==='critical'){
      const overlay=document.createElement('div'); overlay.id='ph_guard'; overlay.style= 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:2147483647;display:flex;align-items:center;justify-content:center;'; overlay.innerHTML=`<div style="background:white;padding:24px;border-radius:10px;max-width:520px;"><h2>Warning: ${resp.level.toUpperCase()}</h2><p>Score: ${resp.score}/100</p><p>${(resp.reasons||[]).slice(0,5).join('<br>')}</p><div style="display:flex;gap:8px;margin-top:14px"><button id="pg_back">Go Back</button><button id="pg_wh">Trust</button><button id="pg_cont">Continue</button></div></div>`;
      document.body.appendChild(overlay);
      document.getElementById('pg_back').onclick=()=>history.back();
      document.getElementById('pg_wh').onclick=()=>{ chrome.runtime.sendMessage({type:'WHITELIST_SITE', url: window.location.href}); overlay.remove(); };
      document.getElementById('pg_cont').onclick=()=>overlay.remove();
    }
  }
}
new DOMAnalyzer();
