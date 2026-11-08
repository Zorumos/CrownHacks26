import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';

const speechSource=await readFile(new URL('../public/read-aloud.js',import.meta.url),'utf8');
function speechHarness({supported=true,voices=[{name:'Local English',lang:'en-US',localService:true}]}={}) {
  const handlers={}, buttons=['all-disclosures','privacy-copy','terms-copy'].map(readAloud=>({dataset:{readAloud},disabled:false}));
  const items={'speech-pause':{},'speech-stop':{},'speech-rate':{value:'0.8'},'speech-status':{textContent:''}};
  const privacy=[{textContent:'Privacy information.'},{textContent:'We save protected account information.'}];
  const terms=[{textContent:'Terms and conditions.'},{textContent:'This is a demo.'}];
  for(const [id,copy] of Object.entries({'privacy-copy':privacy,'terms-copy':terms,'all-disclosures':[...privacy,...terms]}))
    items[id]={querySelectorAll:selector=>{assert.equal(selector,'h2,h3,p');return copy;}};
  const spoken=[];let cancelled=0,pauses=0,resumes=0,voicesChanged;
  const synth={getVoices:()=>voices,speak:u=>spoken.push(u),cancel:()=>cancelled++,pause:()=>pauses++,resume:()=>resumes++,addEventListener:(name,fn)=>{voicesChanged=fn;}};
  const context=vm.createContext({document:{getElementById:id=>items[id],querySelectorAll:()=>buttons,addEventListener:(name,fn)=>handlers[name]=fn},
    addEventListener:(name,fn)=>handlers[name]=fn,
    ...(supported?{speechSynthesis:synth,SpeechSynthesisUtterance:class{constructor(text){this.text=text;}}}:{})});
  vm.runInContext(speechSource,context);context.CyberOneSpeech.refresh();
  function click(id) {
    const read=buttons.find(b=>b.dataset.readAloud===id);
    handlers.click({target:{closest:selector=>selector==='[data-read-aloud]'?read:selector==='#'+id?{}:null}});
  }
  return {items,buttons,spoken,context,click,handlers,voices,setVoices:v=>{voices=v;voicesChanged();},counts:()=>({cancelled,pauses,resumes})};
}
test('speech reads chosen public section only with a local English voice and selected speed',()=>{
  const h=speechHarness();h.click('privacy-copy');
  assert.equal(h.spoken[0].text,'Privacy information.');assert.equal(h.spoken[0].voice.localService,true);assert.equal(h.spoken[0].rate,.8);
  h.spoken[0].onend();assert.equal(h.spoken[1].text,'We save protected account information.');
  h.spoken[1].onend();assert.equal(h.spoken.length,2);assert.match(h.items['speech-status'].textContent,/Finished reading/);
  assert.equal(h.items['speech-pause'].disabled,true);
});
test('pause, resume, stop and page exit manage the speech lifecycle',()=>{
  const h=speechHarness();h.click('terms-copy');h.click('speech-pause');
  assert.equal(h.items['speech-pause'].textContent,'Resume');assert.equal(h.counts().pauses,1);
  h.click('speech-pause');assert.equal(h.items['speech-pause'].textContent,'Pause');
  const old=h.spoken[0];h.click('speech-stop');assert.equal(h.counts().cancelled,1);
  old.onend();assert.equal(h.spoken.length,1,'cancelled callbacks cannot continue reading');
  h.click('terms-copy');h.handlers.pagehide();assert.equal(h.counts().cancelled,2);
});
test('no remote voice fallback, unsupported browser, and asynchronously loaded voices',()=>{
  const remote=speechHarness({voices:[{lang:'en-US',localService:false}]});
  assert.ok(remote.buttons.every(b=>b.disabled));remote.click('privacy-copy');assert.equal(remote.spoken.length,0);
  remote.setVoices([{lang:'en-GB',localService:true}]);assert.ok(remote.buttons.every(b=>!b.disabled));
  const unsupported=speechHarness({supported:false});assert.ok(unsupported.buttons.every(b=>b.disabled));assert.match(unsupported.items['speech-status'].textContent,/not supported/);
});
test('speech errors leave the written text usable and both-section reading reaches terms',()=>{
  const h=speechHarness();h.click('all-disclosures');h.spoken[0].onend();h.spoken[1].onend();
  assert.equal(h.spoken[2].text,'Terms and conditions.');h.spoken[2].onerror();
  assert.match(h.items['speech-status'].textContent,/Try again/);assert.equal(h.items['speech-stop'].disabled,true);
});

const appSource=(await readFile(new URL('../public/app.js',import.meta.url),'utf8')).split('(async()=>')[0];
function appHarness(active=false) {
  const handlers={},main={innerHTML:'',focus(){}},nav={innerHTML:''},location={value:'Germany'};
  const context=vm.createContext({document:{querySelector:id=>id==='main'||id==='#main'?main:id==='#nav'?nav:id==='#location'?location:{textContent:''},addEventListener:(name,fn)=>handlers[name]=fn},
    clearInterval(){},setInterval(){return 1;},setTimeout(){},calls:[]});
  vm.runInContext(appSource,context);
  vm.runInContext(`user={role:'owner',username:'demo',name:'',alerts:[],family:[],lease:${active?"{id:'fixture-lease',active:true,location:'United States',sharedActive:true}":'null'}};
    api=async(action,body)=>{calls.push({action,body});return {user:{...user,lease:{id:'fixture-lease',active:action!=='disconnect',location:'United States'}}};};`,context);
  async function click(action){const el={dataset:{action},disabled:false};await handlers.click({target:{closest:()=>el}});}
  return {context,main,click,location};
}
test('connection page has one on/off control and off works after changing location',async()=>{
  const h=appHarness(true);vm.runInContext('dashboard()',h.context);
  assert.equal((h.main.innerHTML.match(/class="power /g)||[]).length,1);
  assert.doesNotMatch(h.main.innerHTML,/data-action="off"/);
  await h.click('connect');assert.equal(h.context.calls[0].action,'disconnect');
  assert.match(h.main.innerHTML,/aria-pressed="false"/);
  await h.click('connect');assert.equal(h.context.calls[1].action,'connect');
  assert.match(h.main.innerHTML,/aria-pressed="true"/);
});
test('Auto while active does not turn the profile off or send another toggle',async()=>{
  const h=appHarness(true);await h.click('auto');assert.equal(h.location.value,'Auto');assert.equal(h.context.calls.length,0);
});
test('updated disclosure retains required acknowledgements and matching backend version',async()=>{
  const h=appHarness();vm.runInContext('disclosure()',h.context);
  assert.match(h.main.innerHTML,/name="privacy" required/);assert.match(h.main.innerHTML,/name="terms" required/);
  assert.match(h.main.innerHTML,/name="signature" type="text" required/);
  assert.match(h.main.innerHTML,/2026-11-demo-v3/);
  assert.match(h.main.innerHTML,/does not change your public IP address/);
  assert.match(h.main.innerHTML,/provider.*own rules/s);
  assert.match(await readFile(new URL('../api/index.js',import.meta.url),'utf8'),/version:'2026-11-demo-v3'/);
});
