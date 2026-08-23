package server

import "net/http"

const passkeyJS = `
const dec=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0))};
const enc=b=>{let s='';new Uint8Array(b).forEach(v=>s+=String.fromCharCode(v));return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
function decodeOptions(o){o.challenge=dec(o.challenge);if(o.user)o.user.id=dec(o.user.id);for(const k of ['excludeCredentials','allowCredentials'])if(o[k])o[k].forEach(c=>c.id=dec(c.id));return o}
function serialize(c){const r={id:c.id,rawId:enc(c.rawId),type:c.type,clientExtensionResults:c.getClientExtensionResults(),authenticatorAttachment:c.authenticatorAttachment,response:{clientDataJSON:enc(c.response.clientDataJSON)}};for(const k of ['attestationObject','authenticatorData','signature','userHandle'])if(c.response[k])r.response[k]=enc(c.response[k]);if(c.response.getTransports)r.response.transports=c.response.getTransports();return r}
const button=document.getElementById('passkey');button.addEventListener('click',async()=>{const out=document.getElementById('status');try{out.textContent='Waiting for your passkey…';const b=await fetch(button.dataset.begin,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({continue:button.dataset.continue,bootstrap:button.dataset.bootstrap})});const x=await b.json();if(!b.ok)throw new Error(x.error||'Could not begin');const credential=await navigator.credentials[button.dataset.method]({publicKey:decodeOptions(x.options.publicKey)});const f=await fetch(button.dataset.finish+'?transaction='+encodeURIComponent(x.transaction),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(serialize(credential))});const y=await f.json();if(!f.ok)throw new Error(y.error||'Could not finish');location.href=y.redirect||'/account'}catch(e){out.textContent=e.message}});
`

func (a *App) passkeyAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(passkeyJS))
}
