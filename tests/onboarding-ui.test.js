import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
test('backup-code button requires both ten elapsed seconds and saved-code acknowledgement',async()=>{
 const source=(await readFile(new URL('../public/app.js',import.meta.url),'utf8')).split('(async()=>')[0];
 let clock=100000,update;
 const elements={main:{innerHTML:'',focus(){}},'#nav':{innerHTML:''},'#saved':{checked:false,addEventListener(){}},'#codes-next':{disabled:false,textContent:''},'#codes-countdown':{textContent:''}};
 const context=vm.createContext({document:{querySelector:key=>elements[key==='#main'?'main':key]||{textContent:''},addEventListener(){}},Date:class extends Date{static now(){return clock;}},setInterval:fn=>{update=fn;return 1;},clearInterval(){},setTimeout(){}});
 vm.runInContext(source,context);vm.runInContext('register()',context);assert.match(elements.main.innerHTML,/id="sample"[^>]*required/);assert.doesNotMatch(elements.main.innerHTML,/sample image \(optional\)/);
 vm.runInContext('showCodes()',context);assert.equal(elements['#codes-next'].disabled,true);assert.match(elements['#codes-next'].textContent,/10 seconds/);
 elements['#saved'].checked=true;clock+=9999;update();assert.equal(elements['#codes-next'].disabled,true);
 clock+=1;update();assert.equal(elements['#codes-next'].disabled,false);assert.match(elements['#codes-next'].textContent,/Continue to disclosure/);
 elements['#saved'].checked=false;update();assert.equal(elements['#codes-next'].disabled,true);
});
test('signup requires recovery emails and login offers account recovery',async()=>{
 const source=(await readFile(new URL('../public/app.js',import.meta.url),'utf8')).split('(async()=>')[0];const main={innerHTML:'',focus(){}};const context=vm.createContext({document:{querySelector:key=>key==='main'||key==='#main'?main:{innerHTML:''},addEventListener(){}},clearInterval(){},setInterval(){},setTimeout(){}});vm.runInContext(source,context);vm.runInContext('register()',context);assert.match(main.innerHTML,/name="email" type="email" required/);vm.runInContext('login()',context);assert.match(main.innerHTML,/Forgot username, password or codes/);vm.runInContext("user={role:'owner',username:'parent',family:[]};familyRegister()",context);assert.match(main.innerHTML,/Family member’s recovery email/);assert.match(main.innerHTML,/name="email" type="email" required/);vm.runInContext('recover()',context);assert.match(main.innerHTML,/value="all"/);assert.match(main.innerHTML,/value="username"/);vm.runInContext('verifyEmailPage()',context);assert.match(main.innerHTML,/id="verify-email"/);assert.match(main.innerHTML,/Verify email/);
});
