// Targeted IndexedDB cache migration, using a real browser and mocked pages.
const assert = require('node:assert/strict');
const path = require('node:path');
const playwright = require('playwright');
(async () => {
  const engine = process.env.BROWSER || 'chromium';
  const browser = await playwright[engine].launch({headless:true,executablePath:process.env.CHROME_PATH || undefined});
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(10000);
    let build='a'.repeat(64), preparations=0;
    await page.route('https://gate.test/**',async route=>{
      const url=new URL(route.request().url());
      if(url.pathname==='/_lanternfish/jellyfin-cache.js')return route.fulfill({path:path.join(__dirname,'../internal/gate/web/jellyfin-cache.js')});
      if(url.pathname==='/seed')return route.fulfill({contentType:'text/html',body:'<!doctype html><title>seed</title>'});
      if(url.pathname==='/web/'){
        const cookie=await route.request().headerValue('cookie') || '';
        if(!cookie.split('; ').includes('lf_jellyfin_cache_build='+build)){
          preparations++;
          return route.fulfill({contentType:'text/html',body:`<!doctype html><p id="status"></p><button id="retry" hidden>Retry</button><script src="/_lanternfish/jellyfin-cache.js" data-build="${build}"></script>`});
        }
        return route.fulfill({contentType:'text/html',body:'<!doctype html><h1>Jellyfin application started</h1>'});
      }
      return route.fulfill({status:404,body:''});
    });
    await page.goto('https://gate.test/seed');
    await page.evaluate(async()=>{
      async function put(dbname,store,records){await new Promise((resolve,reject)=>{const req=indexedDB.open(dbname,1);req.onupgradeneeded=()=>req.result.createObjectStore(store);req.onerror=()=>reject(req.error);req.onsuccess=()=>{const db=req.result,tx=db.transaction(store,'readwrite');for(const [key,value]of records)tx.objectStore(store).put(value,key);tx.oncomplete=()=>{db.close();resolve();};tx.onerror=()=>reject(tx.error);};});}
      const keys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
      await put('lanternfish-gate','keys',[['device',{privateKey:keys.privateKey}]]);
      await put('keyval-store','keyval',[['jellyfin-query-cache',{bad:'old schema'}],['unrelated-preference','keep']]);
      localStorage.setItem('jellyfin-login','keep-login');
    });
    async function inspect(){return page.evaluate(async()=>{
      async function get(dbname,store,key){return new Promise((resolve,reject)=>{const req=indexedDB.open(dbname);req.onerror=()=>reject(req.error);req.onsuccess=()=>{const db=req.result,tx=db.transaction(store),r=tx.objectStore(store).get(key);tx.oncomplete=()=>{db.close();resolve(r.result);};};});}
      const dev=await get('lanternfish-gate','keys','device');
      const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},dev.privateKey,new TextEncoder().encode('still enrolled'));
      return {cache:await get('keyval-store','keyval','jellyfin-query-cache'),preference:await get('keyval-store','keyval','unrelated-preference'),login:localStorage.getItem('jellyfin-login'),signatureBytes:signature.byteLength};
    });}
    await page.goto('https://gate.test/web/#/dashboard');
    await page.getByRole('heading',{name:'Jellyfin application started'}).waitFor();
    assert.equal(preparations,1);
    const state=await inspect();assert.equal(state.cache,undefined);assert.equal(state.preference,'keep');assert.equal(state.login,'keep-login');assert.equal(state.signatureBytes,64);
    assert.match(page.url(),/#\/dashboard$/);
    await page.evaluate(()=>new Promise(resolve=>{const r=indexedDB.open('keyval-store');r.onsuccess=()=>{const db=r.result,tx=db.transaction('keyval','readwrite');tx.objectStore('keyval').put(['fresh'],'jellyfin-query-cache');tx.oncomplete=()=>{db.close();resolve();};};}));
    await page.reload();await page.getByRole('heading',{name:'Jellyfin application started'}).waitFor();
    assert.deepEqual((await inspect()).cache,['fresh']);assert.equal(preparations,1);
    build='b'.repeat(64);
    await page.reload();await page.getByRole('heading',{name:'Jellyfin application started'}).waitFor();
    assert.equal((await inspect()).cache,undefined);assert.equal(preparations,2);
    await page.evaluate(()=>new Promise((resolve,reject)=>{const r=indexedDB.deleteDatabase('keyval-store');r.onsuccess=()=>resolve();r.onerror=()=>reject(r.error);}));
    build='c'.repeat(64);
    await page.reload();await page.getByRole('heading',{name:'Jellyfin application started'}).waitFor();
    assert.equal(await page.evaluate(async()=>(await indexedDB.databases()).some(d=>d.name==='keyval-store')),false);
    assert.equal(preparations,3);
    build='d'.repeat(64);
    await page.addInitScript(()=>{indexedDB.open=()=>{throw new DOMException('Storage blocked','SecurityError');};});
    await page.reload();await page.getByRole('button',{name:'Retry',exact:true}).waitFor();
    assert.match(await page.locator('#status').textContent(),/have not been cleared/);
    assert.equal((await page.context().cookies()).find(c=>c.name==='lf_jellyfin_cache_build').value,'c'.repeat(64));
    console.log(engine+': upgrade clears only Jellyfin query cache; device key, login, route and current-build cache preserved');
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
