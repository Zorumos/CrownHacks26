'use strict';
// Tokens and enrollment secrets never enter localStorage, query strings or console logs.
let token = '', disclosure = null;
const $ = id => document.getElementById(id);
const notice = text => { $('notice').textContent = text; };
async function api(path, method='GET', body) {
  const headers = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch('/api' + path, {method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials:'omit'});
  const data = await response.json();
  if (!response.ok) throw new Error([data.error?.message || 'The request failed.', data.error?.action || ''].join(' '));
  return data;
}
function action(id, callback) {
  $(id).addEventListener('click', async () => {
    $(id).disabled=true;
    try { await callback(); } catch(e) { notice(e.message); }
    finally { $(id).disabled=false; }
  });
}
function form(id, callback) {
  $(id).addEventListener('submit', async event => {
    event.preventDefault();
    const button = event.target.querySelector('button');
    button.disabled=true;
    const data = Object.fromEntries(new FormData(event.target));
    try { await callback(data); }
    catch(e) { notice(e.message); }
    finally { event.target.querySelectorAll('input[type="password"],input[name="code"],input[name="name"],input[name="signature"]').forEach(x => x.value=''); button.disabled=false; }
  });
}
function showConnection(data) {
  $('connection').textContent=JSON.stringify(data,null,2);
  $('warnings').replaceChildren();
  for(const warning of data.warnings || []) {
    const box=document.createElement('div'); box.className='warning '+warning.severity;
    const title=document.createElement('strong'); title.textContent=warning.title;
    const text=document.createElement('p'); text.textContent=warning.message+' '+warning.action;
    box.append(title,text);
    if(warning.announce) {box.setAttribute('role', warning.interrupt ? 'alert':'status'); box.setAttribute('aria-live',warning.aria_live);}
    $('warnings').append(box);
  }
  notice(data.headline || data.message || 'Server access was removed. Turn off your native client too.');
}
async function refresh() {
  const [devices, servers]=await Promise.all([api('/devices'),api('/servers')]);
  $('devices').replaceChildren();
  for(const d of devices.devices) $('devices').add(new Option(d.label,d.id));
  $('servers').replaceChildren(new Option('Auto · first available configured server','auto'));
  for(const s of servers.servers) $('servers').add(new Option(s.country+' · '+s.city,s.id));
  notice(servers.servers.length ? 'Choose a device to prepare server access.' : 'No VPN server is configured. Ask the operator to complete server setup.');
}
function deviceId(){const id=$('devices').value;if(!id)throw new Error('Register or choose a device first.');return id;}
action('load-disclosure', async()=>{
  disclosure=await api('/disclosure'); const area=$('disclosure');area.replaceChildren();
  for(const [key,value] of Object.entries(disclosure)){
    if(['version','document_hash'].includes(key))continue;
    const heading=document.createElement('h3');heading.textContent=key.replaceAll('_',' ');area.append(heading);
    for(const item of Array.isArray(value)?value:[value]){const p=document.createElement('p');p.textContent=item;area.append(p);}
  }
  $('register-button').disabled=false;notice('Review the disclosure before agreeing.');
});
form('register',async data=>{
  if(!disclosure)throw new Error('Read the disclosure first.');
  const result=await api('/auth/register','POST',{...data,invitation:data.invitation||null,agreed:data.agreed==='on',disclosure_version:disclosure.version,document_hash:disclosure.document_hash});
  token=result.access_token;notice('Account created. Set up your authenticator next.');$('mfa-setup').focus();
});
form('login',async data=>{const result=await api('/auth/login','POST',data);token=result.access_token;if(result.scope==='full')await refresh();else notice('Finish authenticator setup.');});
action('mfa-setup',async()=>{const result=await api('/auth/mfa/setup');$('mfa-secret').textContent=result.secret;notice(result.action);});
form('mfa-confirm',async data=>{
  const result=await api('/auth/mfa/confirm','POST',data);token=result.access_token;$('mfa-secret').textContent='';
  $('recovery').textContent='Save these one-use recovery codes privately:\n'+result.recovery_codes.join('\n');
  await refresh();notice('Authenticator confirmed. Save your recovery codes before continuing.');
});
form('device',async data=>{await api('/devices','POST',data);await refresh();});
action('refresh',refresh);
action('connect',async()=>showConnection(await api('/connections','POST',{device_id:deviceId(),server_id:$('servers').value,adblock:$('adblock').checked})));
action('status',async()=>showConnection(await api('/connections/'+deviceId())));
action('disconnect',async()=>showConnection(await api('/connections/'+deviceId(),'DELETE')));
action('invite',async()=>{const result=await api('/family/invites','POST');notice('One-use family invitation (valid one hour): '+result.invitation+' Share it privately.');});
action('logout',async()=>{try{await api('/auth/logout','POST');}finally{token='';$('mfa-secret').textContent='';$('recovery').textContent='';$('connection').textContent='';$('warnings').replaceChildren();$('devices').replaceChildren();notice('Signed out of the website. An active native VPN connection is not automatically disconnected.');}});
