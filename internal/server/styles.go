package server

import "net/http"

// claustraCSS is the whole interface: a flat, dark, purple-accented system
// served from the origin so the strict style-src and script-src policy stays
// intact.
const claustraCSS = `
:root{
  color-scheme:dark;
  --bg:#0a0810;
  --glow-a:rgba(124,58,237,.20);
  --glow-b:rgba(168,85,247,.09);
  --raised:#120e1c;
  --line:#2a2140;
  --line-soft:#201930;
  --text:#f1eefa;
  --muted:#a79fc4;
  --faint:#8d85ac;
  --accent:#a855f7;
  --accent-2:#c084fc;
  --accent-deep:#6d28d9;
  --danger:#ff7085;
  --ok:#5ee2a0;
  --warn:#fbbf5f;
  --radius:10px;
  --font:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0;min-height:100dvh;display:flex;flex-direction:column;
  line-height:1.55;font-family:var(--font);color:var(--text);
  background:
    radial-gradient(52rem 34rem at 6% -14%,var(--glow-a),transparent 62%),
    radial-gradient(44rem 30rem at 106% -6%,var(--glow-b),transparent 58%),
    var(--bg);
  background-attachment:fixed;
  -webkit-font-smoothing:antialiased;
}
::selection{background:rgba(168,85,247,.35)}
a{color:var(--accent-2)}
h1,h2,h3{margin:0;letter-spacing:-.02em;line-height:1.25;font-weight:640}
h1{font-size:1.6rem}
h2{font-size:1.02rem}
h3{font-size:.92rem}
p{margin:0}
code,pre{font-family:var(--mono)}

/* chrome */
.site-header{position:sticky;top:0;z-index:30;background:rgba(10,8,16,.72);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-bottom:1px solid var(--line-soft)}
.site-header__inner,.shell{max-width:56rem;margin:0 auto;padding:0 1.5rem;width:100%}
.site-header__inner{display:flex;align-items:center;gap:1rem;height:3.5rem}
.brand{display:inline-flex;align-items:center;gap:.6rem;text-decoration:none;color:var(--text);
  font-weight:640;letter-spacing:-.02em}
.brand__mark{width:26px;height:26px;flex:none;display:grid;place-items:center;border-radius:8px;color:#fff;
  background:linear-gradient(145deg,var(--accent-deep),var(--accent))}
.brand__mark svg{width:15px;height:15px}
.site-nav{margin-left:auto;display:flex;align-items:center;gap:1.1rem;flex-wrap:wrap}
.site-nav a{color:var(--muted);text-decoration:none;font-size:.9rem;transition:color .15s}
.site-nav a:hover{color:var(--text)}
.site-nav a[aria-current=page]{color:var(--text)}
main.shell{flex:1 0 auto;padding-top:2.75rem;padding-bottom:4rem}
.site-footer{margin-top:auto;border-top:1px solid var(--line-soft);color:var(--faint);font-size:.8rem}
.site-footer .shell{display:flex;gap:1.25rem;flex-wrap:wrap;padding-top:1rem;padding-bottom:1.25rem}
.site-footer a{color:var(--faint);text-decoration:none}
.site-footer a:hover{color:var(--muted)}

/* page furniture */
.page-head{display:grid;gap:.35rem;margin-bottom:2.25rem}
.eyebrow{font-size:.7rem;text-transform:uppercase;letter-spacing:.16em;color:var(--accent-2);font-weight:600}
.lede{color:var(--muted);max-width:54ch}
.faint{color:var(--faint);font-size:.85rem}
.error{color:var(--danger)}
.row-actions{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}
.push{margin-left:auto}
.row-actions--spaced{margin-top:1.35rem}
.spaced{margin-top:1.15rem}

/* sections replace panels: hairline rules, no boxes */
.section{padding:2.25rem 0;border-top:1px solid var(--line-soft)}
.section:first-child{border-top:0;padding-top:0}
.section__head{display:flex;align-items:center;gap:1rem;flex-wrap:wrap;margin-bottom:1.15rem}
.section__head p{color:var(--faint);font-size:.85rem}
.section--danger h2{color:var(--danger)}
.section>form{max-width:34rem}
.section>form+form{margin-top:1.5rem}

/* notice */
.notice{display:grid;gap:.7rem;padding:.15rem 0 .15rem 1.1rem;border-left:2px solid var(--warn);
  max-width:44rem;margin-bottom:2.25rem}
.notice h2{font-size:.95rem}
.notice__head{display:flex;align-items:center;gap:.7rem;flex-wrap:wrap}

/* forms */
form{display:grid;gap:.9rem}
.field{display:grid;gap:.35rem;font-size:.85rem;color:var(--muted)}
.field>span{font-weight:550}
.field small{color:var(--faint)}
input,select,textarea{
  font:inherit;font-size:.95rem;color:var(--text);width:100%;
  background:var(--raised);border:1px solid var(--line);border-radius:var(--radius);
  padding:.6rem .75rem;transition:border-color .15s,box-shadow .15s}
input::placeholder{color:#5f587a}
input:focus-visible,select:focus-visible,textarea:focus-visible{outline:none;border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(168,85,247,.2)}
input[type=file]{padding:.45rem;color:var(--muted)}
input[type=file]::file-selector-button{font:inherit;font-size:.85rem;margin-right:.75rem;cursor:pointer;
  color:var(--text);background:#1b1428;border:1px solid var(--line);border-radius:8px;padding:.35rem .7rem}
.check{display:flex;align-items:center;gap:.6rem;font-size:.9rem;color:var(--muted)}
.check input{width:1.05rem;height:1.05rem;accent-color:var(--accent);flex:none}
.checks{display:grid;gap:.55rem}
.form-grid{display:grid;gap:.9rem;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr))}
.form-grid .field--wide{grid-column:1/-1}

/* buttons */
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:.5rem;
  font:inherit;font-size:.88rem;font-weight:600;
  color:var(--text);background:#1b1428;border:1px solid var(--line);
  border-radius:var(--radius);padding:.55rem .95rem;cursor:pointer;text-decoration:none;
  transition:transform .12s,border-color .15s,background .15s,box-shadow .2s,color .15s}
.btn:hover{border-color:#3a2d59;background:#221a33}
.btn:active{transform:translateY(1px)}
.btn:focus-visible{outline:none;box-shadow:0 0 0 3px rgba(168,85,247,.35)}
.btn--primary{border-color:transparent;color:#fff;
  background:linear-gradient(135deg,var(--accent-deep),var(--accent))}
.btn--primary:hover{background:linear-gradient(135deg,#7c33ee,#b366fb);border-color:transparent}
.btn--quiet{background:transparent;border-color:transparent;color:var(--muted);padding-inline:.25rem}
.btn--quiet:hover{background:transparent;color:var(--text);border-color:transparent;text-decoration:underline}
.btn--danger{color:var(--danger);border-color:rgba(255,112,133,.28);background:transparent}
.btn--danger:hover{color:#fff;background:rgba(255,112,133,.2);border-color:rgba(255,112,133,.5)}
.btn--sm{font-size:.8rem;padding:.35rem .7rem}
.btn--block{width:100%}
.btn svg{width:1rem;height:1rem;flex:none}

/* badges */
.badge{display:inline-flex;align-items:center;gap:.35rem;font-size:.68rem;font-weight:600;letter-spacing:.06em;
  text-transform:uppercase;white-space:nowrap;color:var(--faint)}
.badge::before{content:"";width:5px;height:5px;border-radius:50%;background:currentColor}
.badge--ok{color:var(--ok)}
.badge--warn{color:var(--warn)}
.badge--off{color:var(--danger)}
.badge--accent{color:var(--accent-2)}

/* lists */
.rows{display:grid}
.row{display:flex;align-items:center;gap:1rem;flex-wrap:wrap;
  padding:.85rem 0;border-bottom:1px solid var(--line-soft)}
.row:first-child{border-top:1px solid var(--line-soft)}
.row form{display:contents}
.row__glyph{width:17px;height:17px;flex:none;color:var(--accent-2);opacity:.85}
.row__main{display:grid;gap:.1rem;min-width:0;flex:1 1 13rem}
.row__title{font-weight:600;font-size:.92rem;display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
.row__meta{color:var(--faint);font-size:.8rem;word-break:break-word}
.row .btn{margin-left:auto}
.rows+form{margin-top:1.5rem}
.empty{color:var(--faint);font-size:.88rem;padding:.85rem 0;border-top:1px solid var(--line-soft)}

/* table */
.table-wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.88rem;min-width:32rem}
th{text-align:left;font-size:.68rem;text-transform:uppercase;letter-spacing:.12em;color:var(--faint);font-weight:600;
  padding:.55rem 1rem .55rem 0;border-bottom:1px solid var(--line)}
td{padding:.8rem 1rem .8rem 0;border-bottom:1px solid var(--line-soft);vertical-align:middle}
th:last-child,td:last-child{padding-right:0;text-align:right}
tbody tr:last-child td{border-bottom:0}
td code{font-size:.82rem;color:var(--accent-2)}
td .row-actions{justify-content:flex-end}

/* misc */
pre{margin:0;overflow-x:auto;background:var(--raised);border:1px solid var(--line-soft);border-radius:var(--radius);
  padding:.9rem 1rem;font-size:.82rem;color:var(--accent-2);white-space:pre-wrap;word-break:break-word;line-height:1.6;
  max-width:44rem}
.secret{color:#fff;font-size:.9rem}
.avatar{width:64px;height:64px;border-radius:50%;object-fit:cover;flex:none}
.avatar--placeholder{display:grid;place-items:center;color:#fff;
  background:linear-gradient(145deg,var(--accent-deep),var(--accent))}
.avatar--placeholder svg{width:28px;height:28px;opacity:.92}
.identity{display:flex;align-items:center;gap:1.1rem;flex-wrap:wrap}
.identity__text{display:grid;gap:.3rem;min-width:0}
.identity__name{font-size:1.35rem;font-weight:640;letter-spacing:-.02em}
.scopes{display:grid;gap:.8rem;margin:0;padding:0;list-style:none;text-align:left}
.scopes li{display:flex;gap:.75rem;align-items:center;font-size:.95rem;color:var(--muted)}
.scopes svg{width:1.05rem;height:1.05rem;flex:none;color:var(--accent-2);opacity:.85}
.status{min-height:1.4rem;font-size:.88rem;color:var(--muted)}
.center{max-width:25rem;margin:2rem auto 0;display:grid;gap:1.35rem;justify-items:center;text-align:center}
.center form,.center .row-actions{justify-content:center;width:100%}
.center .page-head{margin-bottom:0}
.hero{display:grid;gap:1.35rem;padding-top:3rem;justify-items:center;text-align:center}
.hero h1{font-size:clamp(1.9rem,5.5vw,2.6rem);max-width:15ch}
.hero .lede{font-size:1.02rem}

/* Log in with Claustra */
.claustra-login{
  --cl-1:#4c1d95;--cl-2:#6d28d9;--cl-3:#9333ea;
  position:relative;isolation:isolate;overflow:hidden;
  display:inline-flex;align-items:center;gap:.9rem;width:100%;max-width:17rem;
  padding:.8rem 1rem;border-radius:12px;border:1px solid rgba(216,180,254,.38);
  font:600 .95rem/1.2 var(--font);color:#fff;text-decoration:none;cursor:pointer;
  background:linear-gradient(135deg,var(--cl-1) 0%,var(--cl-2) 46%,var(--cl-3) 100%);
  box-shadow:0 1px 0 rgba(255,255,255,.18) inset,0 16px 34px -18px rgba(147,51,234,.95);
  transition:transform .14s ease,box-shadow .28s ease,filter .28s ease}
.claustra-login::before{
  content:"";position:absolute;inset:0;z-index:-1;pointer-events:none;opacity:.9;
  background-image:
    radial-gradient(1.7px 1.7px at 14% 32%,#ffffff,transparent 60%),
    radial-gradient(1.2px 1.2px at 27% 70%,#f5e9ff,transparent 60%),
    radial-gradient(1.9px 1.9px at 46% 22%,#ffffff,transparent 60%),
    radial-gradient(1.1px 1.1px at 58% 76%,#e9d5ff,transparent 60%),
    radial-gradient(1.5px 1.5px at 72% 38%,#ffffff,transparent 60%),
    radial-gradient(1.2px 1.2px at 88% 64%,#f3e8ff,transparent 60%);
  animation:claustra-twinkle 3.4s ease-in-out infinite}
.claustra-login::after{
  content:"";position:absolute;top:-30%;left:-70%;width:45%;height:160%;z-index:-1;pointer-events:none;
  transform:skewX(-18deg);
  background:linear-gradient(100deg,transparent,rgba(255,255,255,.42),transparent);
  animation:claustra-sheen 4.6s cubic-bezier(.4,0,.2,1) infinite}
.claustra-login__label{white-space:nowrap}
.claustra-login__lock{width:19px;height:19px;flex:none;margin-left:auto;
  filter:drop-shadow(0 0 6px rgba(233,213,255,.65));transition:transform .18s ease}
.claustra-login:hover{transform:translateY(-1px);filter:saturate(1.12) brightness(1.06);
  box-shadow:0 1px 0 rgba(255,255,255,.24) inset,0 0 0 4px rgba(168,85,247,.16),0 22px 40px -18px rgba(147,51,234,1)}
.claustra-login:hover .claustra-login__lock{transform:translateX(2px) rotate(-6deg)}
.claustra-login:active{transform:translateY(0)}
.claustra-login:focus-visible{outline:none;
  box-shadow:0 1px 0 rgba(255,255,255,.24) inset,0 0 0 3px rgba(233,213,255,.9),0 16px 34px -18px rgba(147,51,234,.95)}
@keyframes claustra-twinkle{
  0%,100%{opacity:.35;transform:scale(1)}
  40%{opacity:1;transform:scale(1.04)}
  70%{opacity:.55;transform:scale(.99)}}
@keyframes claustra-sheen{
  0%{left:-70%}
  55%,100%{left:130%}}
@media (prefers-reduced-motion:reduce){
  .claustra-login::before{animation:none;opacity:.7}
  .claustra-login::after{animation:none;opacity:0}
  .claustra-login,.claustra-login__lock,.btn{transition:none}}

@media (max-width:34rem){
  .site-header__inner,.shell{padding:0 1.15rem}
  main.shell{padding-top:2rem}
  .section{padding:1.75rem 0}
  .claustra-login{max-width:none}
  .row .btn{margin-left:0}
}
`

// buttonKitCSS is the stand-alone drop-in that relying parties copy or link.
const buttonKitCSS = `
/* Log in with Claustra - drop-in button. Self-contained, no dependencies. */
.claustra-login{
  --cl-1:#4c1d95;--cl-2:#6d28d9;--cl-3:#9333ea;
  position:relative;isolation:isolate;overflow:hidden;box-sizing:border-box;
  display:inline-flex;align-items:center;gap:.9rem;width:100%;max-width:17rem;
  padding:.8rem 1rem;border-radius:12px;border:1px solid rgba(216,180,254,.38);
  font:600 .95rem/1.2 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  color:#fff;text-decoration:none;cursor:pointer;
  background:linear-gradient(135deg,var(--cl-1) 0%,var(--cl-2) 46%,var(--cl-3) 100%);
  box-shadow:0 1px 0 rgba(255,255,255,.18) inset,0 16px 34px -18px rgba(147,51,234,.95);
  transition:transform .14s ease,box-shadow .28s ease,filter .28s ease}
.claustra-login::before{
  content:"";position:absolute;inset:0;z-index:-1;pointer-events:none;opacity:.9;
  background-image:
    radial-gradient(1.7px 1.7px at 14% 32%,#ffffff,transparent 60%),
    radial-gradient(1.2px 1.2px at 27% 70%,#f5e9ff,transparent 60%),
    radial-gradient(1.9px 1.9px at 46% 22%,#ffffff,transparent 60%),
    radial-gradient(1.1px 1.1px at 58% 76%,#e9d5ff,transparent 60%),
    radial-gradient(1.5px 1.5px at 72% 38%,#ffffff,transparent 60%),
    radial-gradient(1.2px 1.2px at 88% 64%,#f3e8ff,transparent 60%);
  animation:claustra-twinkle 3.4s ease-in-out infinite}
.claustra-login::after{
  content:"";position:absolute;top:-30%;left:-70%;width:45%;height:160%;z-index:-1;pointer-events:none;
  transform:skewX(-18deg);
  background:linear-gradient(100deg,transparent,rgba(255,255,255,.42),transparent);
  animation:claustra-sheen 4.6s cubic-bezier(.4,0,.2,1) infinite}
.claustra-login__label{white-space:nowrap}
.claustra-login__lock{width:19px;height:19px;flex:none;margin-left:auto;
  filter:drop-shadow(0 0 6px rgba(233,213,255,.65));transition:transform .18s ease}
.claustra-login:hover{transform:translateY(-1px);filter:saturate(1.12) brightness(1.06);
  box-shadow:0 1px 0 rgba(255,255,255,.24) inset,0 0 0 4px rgba(168,85,247,.16),0 22px 40px -18px rgba(147,51,234,1)}
.claustra-login:hover .claustra-login__lock{transform:translateX(2px) rotate(-6deg)}
.claustra-login:active{transform:translateY(0)}
.claustra-login:focus-visible{outline:none;
  box-shadow:0 1px 0 rgba(255,255,255,.24) inset,0 0 0 3px rgba(233,213,255,.9),0 16px 34px -18px rgba(147,51,234,.95)}
.claustra-login--wide{max-width:none}
@keyframes claustra-twinkle{
  0%,100%{opacity:.35;transform:scale(1)}
  40%{opacity:1;transform:scale(1.04)}
  70%{opacity:.55;transform:scale(.99)}}
@keyframes claustra-sheen{
  0%{left:-70%}
  55%,100%{left:130%}}
@media (prefers-reduced-motion:reduce){
  .claustra-login::before{animation:none;opacity:.7}
  .claustra-login::after{animation:none;opacity:0}
  .claustra-login,.claustra-login__lock{transition:none}}
`

func (a *App) styleAsset(w http.ResponseWriter, r *http.Request) {
	writeCSS(w, claustraCSS)
}

func (a *App) buttonKitAsset(w http.ResponseWriter, r *http.Request) {
	writeCSS(w, buttonKitCSS)
}

func writeCSS(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(body))
}

const markSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#6d28d9"/><stop offset="1" stop-color="#a855f7"/></linearGradient></defs><rect width="32" height="32" rx="9" fill="url(#g)"/><g fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="15" width="16" height="10" rx="2.5"/><path d="M11.5 15v-3.6a4.5 4.5 0 0 1 8.9-.9"/></g><circle cx="16" cy="20" r="1.2" fill="#fff"/></svg>`

func (a *App) markAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(markSVG))
}
