
// PhishingMLModel - simple JS logistic fallback
class PhishingMLModel {
  constructor(){ this.isModelLoaded=false; this.readyPromise=this._init(); }
  async _init(){ await new Promise(r=>setTimeout(r,150)); this.isModelLoaded=true; }
  async ready(){ if(this.readyPromise) await this.readyPromise; return this.isModelLoaded; }
  extractMLFeatures(urlFeatures={}, domFeatures={}){
    const f = {
      urlLength: urlFeatures.urlLength||0,
      hasIP: urlFeatures.hasIP?1:0,
      subdomainCount: urlFeatures.subdomainCount||0,
      hasHttps: urlFeatures.hasHttps?1:0,
      hasSuspiciousChars: urlFeatures.hasSuspiciousChars?1:0,
      hasUrlShortener: urlFeatures.hasUrlShortener?1:0,
      mimicsLegitimate: urlFeatures.mimicsLegitimate?1:0,
      numForms: domFeatures.numForms||0,
      numInputs: domFeatures.numInputs||0,
      hasIframe: domFeatures.hasIframe?1:0,
      externalScriptCount: domFeatures.externalScriptCount||0,
      hasAutoSubmitForm: domFeatures.hasAutoSubmitForm?1:0
    };
    const arr=[f.urlLength,f.hasIP,f.subdomainCount,f.hasHttps,f.hasSuspiciousChars,f.hasUrlShortener,f.mimicsLegitimate,f.numForms,f.numInputs,f.hasIframe,f.externalScriptCount,f.hasAutoSubmitForm];
    return {obj:f,arr};
  }
  _sigmoid(z){ return 1/(1+Math.exp(-z)); }
  async predictPhishing(features){
    if(!features) return 0.02;
    const f = features.obj || {urlLength:features.urlLength||0, hasIP:features.hasIP||0, subdomainCount:features.subdomainCount||0, hasHttps:features.hasHttps||0, hasSuspiciousChars:features.hasSuspiciousChars||0, hasUrlShortener:features.hasUrlShortener||0, mimicsLegitimate:features.mimicsLegitimate||0, numForms:features.numForms||0, numInputs:features.numInputs||0, hasIframe:features.hasIframe||0, externalScriptCount:features.externalScriptCount||0, hasAutoSubmitForm:features.hasAutoSubmitForm||0};
    let z = -3.0 + 0.01*f.urlLength + 1.5*f.hasIP + 0.6*f.subdomainCount -1.2*f.hasHttps + 2.0*f.hasSuspiciousChars + 1.4*f.hasUrlShortener + 2.5*f.mimicsLegitimate + 0.4*f.numForms + 0.02*f.numInputs + 1.0*f.hasIframe + 0.08*f.externalScriptCount + 1.7*f.hasAutoSubmitForm;
    return this._sigmoid(z);
  }
}
window.PhishingMLModel = window.PhishingMLModel || PhishingMLModel;
globalThis.PhishingMLModel = globalThis.PhishingMLModel || PhishingMLModel;
