
// ml_model.js - wrapper that tries to use tf if available, otherwise exposes PhishingMLModel fallback.
// If you add real tf.min.js and model/model.json+weights.bin, ml will use them.
(function(){
  const getURL = (p)=>{ try{ return chrome.runtime.getURL(p); }catch(e){ return p;} };
  class PhishingMLModelWrapper {
    constructor(opts={}){
      this.modelPath = opts.modelPath || 'model/model.json';
      this._model = null;
      this.isModelLoaded = false;
      this.loadError = null;
      this._loadingPromise = this._init();
    }
    async _init(){
      // wait for tf availability briefly
      const waitForTF = ()=> new Promise((resolve)=>{
        const t0 = Date.now();
        const check = ()=>{ if(typeof tf !== 'undefined' && tf.loadLayersModel) return resolve(true); if(Date.now()-t0>3000) return resolve(false); setTimeout(check,100); };
        check();
      });
      const hasTF = await waitForTF();
      if(hasTF){
        try{
          this._model = await tf.loadLayersModel(getURL(this.modelPath));
          // warmup
          try{ const dummy = tf.zeros([1,12]); const out = this._model.predict(dummy); await out.data(); tf.dispose([dummy,out]); }catch(e){}
          this.isModelLoaded = true;
          return true;
        }catch(e){
          console.warn('TF model load failed in wrapper:', e);
          this.loadError = e;
          this.isModelLoaded = false;
        }
      }
      // Fallback: if PhishingMLModel (simple JS) exists, use it
      if(typeof PhishingMLModel !== 'undefined'){
        try{
          this.fallback = new PhishingMLModel();
          await this.fallback.ready();
          this.isModelLoaded = true;
          return true;
        }catch(e){ this.loadError = e; this.isModelLoaded = false; }
      }
      return false;
    }
    async ready(){ if(this._loadingPromise) await this._loadingPromise; return this.isModelLoaded; }
    extractMLFeatures(urlFeatures={}, domFeatures={}){
      // same ordering as training expectation (12 features)
      const f = {
        urlLength: Number(urlFeatures.urlLength||0),
        hasIP: Number(urlFeatures.hasIP||0),
        subdomainCount: Number(urlFeatures.subdomainCount||0),
        hasHttps: Number(urlFeatures.hasHttps||0),
        hasSuspiciousChars: Number(urlFeatures.hasSuspiciousChars||0),
        hasUrlShortener: Number(urlFeatures.hasUrlShortener||0),
        mimicsLegitimate: Number(urlFeatures.mimicsLegitimate||0),
        numForms: Number(domFeatures.numForms||0),
        numInputs: Number(domFeatures.numInputs||0),
        hasIframe: Number(domFeatures.hasIframe||0),
        externalScriptCount: Number(domFeatures.externalScriptCount||0),
        hasAutoSubmitForm: Number(domFeatures.hasAutoSubmitForm||0)
      };
      const arr = [f.urlLength,f.hasIP,f.subdomainCount,f.hasHttps,f.hasSuspiciousChars,f.hasUrlShortener,f.mimicsLegitimate,f.numForms,f.numInputs,f.hasIframe,f.externalScriptCount,f.hasAutoSubmitForm];
      return {obj:f,arr};
    }
    async predictPhishing(features){
      if(this._model){
        try{
          const arr = features.arr || (features.obj?features.arr:Object.values(features));
          const input = tf.tensor2d([arr],[1,arr.length],'float32');
          const out = this._model.predict(input);
          const vals = await out.data();
          tf.dispose([input,out]);
          return Number(vals[0]);
        }catch(e){
          console.warn('TF predict failed, fallback to JS model.',e);
        }
      }
      if(this.fallback){
        return await this.fallback.predictPhishing(features.obj || features);
      }
      return null;
    }
  }
  window.PhishingMLModel = window.PhishingMLModel || PhishingMLModelWrapper;
  globalThis.PhishingMLModel = globalThis.PhishingMLModel || PhishingMLModelWrapper;
})();
