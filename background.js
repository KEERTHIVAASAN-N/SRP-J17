
// background.js - simplified
try { importScripts('libs/tf.min.js'); } catch(e){ console.warn('importScripts libs/tf.min.js failed', e); }
importScripts && typeof importScripts === 'function' && importScripts('phishing_fallback.js'); // ensure fallback available in SW (if possible)

class ModelLoader {
  constructor(){
    this.tfModel = null; this.fallback = null; this.isLoaded=false; this.loadError=null;
    this._init();
  }
  async _init(){
    if(typeof tf !== 'undefined' && tf.loadLayersModel){
      try{ this.tfModel = await tf.loadLayersModel(chrome.runtime.getURL('model/model.json')); this.isLoaded=true; console.log('TF model loaded in SW'); return; }catch(e){ console.warn('TF load failed in SW', e); this.tfModel=null; this.loadError=e; }
    }else{ console.warn('tf not present in SW'); }
    if(typeof PhishingMLModel !== 'undefined'){ try{ this.fallback = new PhishingMLModel(); await this.fallback.ready(); this.isLoaded=true; console.log('Fallback loaded in SW'); }catch(e){ this.loadError=e; } }
  }
  async predict(featureObj, featureArr=null){
    if(this.tfModel){
      try{
        const arr = featureArr || Object.values(featureObj);
        const input = tf.tensor2d([arr],[1,arr.length],'float32');
        const out = this.tfModel.predict(input);
        const vals = await out.data();
        tf.dispose([input,out]);
        return Number(vals[0]);
      }catch(e){ console.warn('TF predict failed in SW', e); }
    }
    if(this.fallback){
      return await this.fallback.predictPhishing({obj:featureObj, arr:featureArr});
    }
    return null;
  }
}
const modelLoader = new ModelLoader();

class PhishingDetector {
  constructor(){ this.thresholds={safe:30,suspicious:50,dangerous:70}; }
  extractUrlFeatures(url){
    const f={}; try{ const u=new URL(url); f.hasIP=/\b\d{1,3}\./.test(u.hostname); f.urlLength=url.length; f.subdomainCount=u.hostname.split('.').length-2; f.hasHttps=u.protocol==='https:'; f.hasSuspiciousChars=/[^\x00-\x7F]/.test(url); f.hasUrlShortener=/(bit\.ly|tinyurl|t\.co|goo\.gl)/.test(url); f.mimicsLegitimate=false; }catch(e){ f.malformed=true;} return f;
  }
  getSecurityLevel(score){ if(score < this.thresholds.safe) return 'safe'; if(score < this.thresholds.suspicious) return 'suspicious'; if(score < this.thresholds.dangerous) return 'dangerous'; return 'critical'; }
  async calculatePhishingScore(urlFeatures, domFeatures={}, mlProb=null){
    let score=0; const reasons=[]; let mlUsed=false, mlConfidence=0;
    if(mlProb!==null && mlProb!==undefined){ const mlScore=Math.round(mlProb*100); score=mlScore; mlUsed=true; mlConfidence=mlProb; reasons.push('ML prediction: '+mlScore+'%'); }
    if(urlFeatures.hasIP){ score += mlUsed?5:25; reasons.push('URL uses IP'); }
    if(urlFeatures.urlLength>75){ score += mlUsed?3:15; reasons.push('Long URL'); }
    if(urlFeatures.subdomainCount>3){ score += mlUsed?4:20; reasons.push('Many subdomains'); }
    if(!urlFeatures.hasHttps){ score += mlUsed?2:10; reasons.push('No HTTPS'); }
    if(urlFeatures.hasSuspiciousChars){ score += mlUsed?6:30; reasons.push('Suspicious chars'); }
    if(urlFeatures.hasUrlShortener){ score += mlUsed?3:15; reasons.push('URL shortener'); }
    if(domFeatures.hasLoginForm && domFeatures.formActionMismatch){ score += 25; reasons.push('Login form posts elsewhere'); }
    if(domFeatures.externalScriptCount>10){ score += 15; reasons.push('Many external scripts'); }
    if(domFeatures.hasAutoSubmitForm){ score += 20; reasons.push('Auto-submit form'); }
    if(domFeatures.hasUrgentLanguage){ score += 15; reasons.push('Urgent language'); }
    if(domFeatures.hasPopups){ score += 10; reasons.push('Popup scripts'); }
    return { score: Math.min(score,100), level: this.getSecurityLevel(score), reasons, mlUsed, mlConfidence };
  }
}
const detector = new PhishingDetector();

chrome.runtime.onMessage.addListener((message, sender, sendResponse)=>{
  (async ()=>{
    try{
      if(message.type==='ANALYZE_PAGE'){
        const url = message.url || (sender.tab && sender.tab.url) || '';
        if(!url){ sendResponse({ error:'no url' }); return; }
        if(message.mlProb===undefined || message.mlProb===null){
          // if content didn't send mlProb, try to compute here using modelLoader
          try{
            const urlFeatures = detector.extractUrlFeatures(url);
            const dom = message.domFeatures || {};
            const mf = modelLoader; // build feature object matching ml_model
            const featuresObj = {...urlFeatures, ...dom};
            const prob = await modelLoader.predict(featuresObj, null);
            message.mlProb = prob;
          }catch(e){ console.warn('background compute ml failed', e); }
        }
        const urlFeatures = detector.extractUrlFeatures(url);
        const result = await detector.calculatePhishingScore(urlFeatures, message.domFeatures || {}, message.mlProb || null);
        await chrome.storage.session.set({ ['analysis_'+(sender.tab?sender.tab.id:'unknown')]: {...result, url, timestamp:Date.now()} });
        sendResponse(result);
      } else if(message.type==='WHITELIST_SITE'){
        const hostname = new URL(message.url).hostname;
        const r = await chrome.storage.local.get(['whitelist']); const wl = r.whitelist||[]; if(!wl.includes(hostname)){ wl.push(hostname); await chrome.storage.local.set({ whitelist: wl }); }
        sendResponse({ success:true });
      } else if(message.type==='GET_PAGE_STATUS'){
        const key = 'analysis_'+message.tabId; const r=await chrome.storage.session.get([key]); sendResponse(r[key]||{score:0,level:'unknown',reasons:[]});
      } else sendResponse({ error:'unknown' });
    }catch(e){ console.error(e); sendResponse({ error: e.message }); }
  })();
  return true;
});

chrome.tabs.onUpdated.addListener(async(tabId, changeInfo, tab)=>{
  if(changeInfo.status==='complete' && tab.url){
    const r = await chrome.storage.session.get(['analysis_'+tabId]); const analysis = r['analysis_'+tabId];
    if(analysis){
      const badges = { safe:{text:'✓',color:'#22c55e'}, suspicious:{text:'?',color:'#f59e0b'}, dangerous:{text:'!',color:'#ef4444'}, critical:{text:'⚠',color:'#dc2626'} };
      const badge = badges[analysis.level] || {text:'', color: '#6b7280'};
      chrome.action.setBadgeText({ tabId, text: badge.text }); chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
    }
  }
});
