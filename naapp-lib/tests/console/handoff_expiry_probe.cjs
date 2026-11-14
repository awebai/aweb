// Executes the exact page script with a DOM/fetch double. This is a page
// state-ordering control, not browser, passkey or consumer qualification.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
let now = Date.now();
const expiresAt = new Date(now + 60000).toISOString();
const elements = new Map();
const expiryTimers = [];
const el = id => {
  if (!elements.has(id)) elements.set(id, {textContent:'', hidden:false, disabled:false, events:{},
    addEventListener(name, fn) { this.events[name] = fn; }, focus() {}, replaceChildren(...parts) {this.textContent=parts.join('');}});
  return elements.get(id);
};
const request = {operation:'human-role.revoke', variant:'default', subject:{principal:'holder',role:'reader',app_id:'app',installation_id:'install'},
  artifact:{issued_at:new Date(now).toISOString()},requester:'requester'};
let sent = false;
let answer;
const context = {
  URL, URLSearchParams, console,
  Date:class extends Date { static now() {return now;} },
  document:{body:{dataset:{handoffId:'h1',purpose:'governance'}},getElementById:el,createElement:()=>el('created')},
  window:{location:{hash:'#k=disposable-test-token',pathname:'/handoff/h1',origin:'https://human.example'}},
  history:{replaceState(){}}, sessionStorage:{getItem(){return null;},removeItem(){}},
  PublicKeyCredential:{parseRequestOptionsFromJSON:o=>o},
  navigator:{credentials:{get:async()=>({toJSON:()=>({})})}},
  validateProtectedPresentation:async state=>({request:state.payload.request,subject:state.payload.request.subject}),
  validateProtectedReceiptPresentation:async state=>({request:state.payload.request,subject:state.payload.request.subject}),
  operationTable:{'human-role.revoke|default':{display:{}}},
  renderDisplay:()=>({title:'Remove holder from reader?',consequences:[],names:[],technical:[]}),
  displayRefusal:()=>null,
  setTimeout:fn=>{expiryTimers.push(fn);return expiryTimers.length;},
  fetch:async path=>{
    if (path.endsWith('/options')) return {ok:true,json:async()=>({userVerification:'required'})};
    if (path.endsWith('/decide')) {
      sent=true;
      return await new Promise(resolve=>{answer=resolve;});
    }
    return {ok:true,json:async()=>({mode:'governance-link',operation_id:'operation',digest:'a'.repeat(64),
      expires_at:expiresAt,payload:{request}})};
  },
};
let source=fs.readFileSync('naapp-lib/src/aweb_naapp/console/browser/handoff.js','utf8');
source=source.replace(/^import .*;\n/gm,'');
vm.runInNewContext(source,context,{filename:'exact-handoff.js'});
(async()=>{
  for(let n=0;n<20 && !expiryTimers.length;n++) await new Promise(setImmediate);
  assert.equal(expiryTimers.length,1,'page did not finish loading');
  assert.equal(el('handoff-action').disabled,false,'valid pending neighbor not enabled');
  const deciding=el('handoff-action').events.click();
  for(let n=0;n<20 && !sent;n++) await new Promise(setImmediate);
  assert.equal(sent,true,'decision was never submitted');
  now += 60001;
  expiryTimers[0]();
  console.log(JSON.stringify({submitted:sent,pageState:context.document.body.dataset.handoffState,
    title:el('handoff-title').textContent,status:el('handoff-status').textContent}));
  const falseFinal=/Nothing was signed|without a decision/.test(el('handoff-status').textContent);
  answer({ok:true,json:async()=>({state:'committed',result:{signing:'signed',signature:'signature'}})});
  await deciding;
  assert.equal(el('handoff-title').textContent,'Approved','committed response neighbor failed');
  assert.equal(falseFinal,false,'expiry claimed no signature while a submitted decision could already have committed');
})().catch(error=>{console.error(error.message);process.exitCode=1;});
