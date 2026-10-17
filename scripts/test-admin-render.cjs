// Run with Node.js and Playwright installed. Uses only mocked local responses.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({executablePath: process.env.CHROME_PATH || undefined, headless: true, args: ['--no-sandbox']});
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    const root = path.join(__dirname, '../internal/gate/web');
    const responses = {
      '/_lanternfish/admin/session': {name:'test-admin',csrf:'test-csrf'},
      '/_lanternfish/admin/v2/profiles': {profiles:[]},
      '/_lanternfish/admin/v2/subjects': {subjects:[{id:'owner',name:'Owner',status:'active'}]},
      '/_lanternfish/admin/v1/tickets': {tickets:[]},
      '/_lanternfish/admin/v2/email': {enabled:false,port:25,from_name:'LanternFish',from_email:'sender@example.com'},
      '/_lanternfish/admin/v2/email/invitations': {invitations:[]},
      '/_lanternfish/admin/v2/jellyfin': {url:'',key_configured:false},
      '/_lanternfish/admin/v2/jellyfin/libraries': {libraries:[{Name:'Movies',ItemId:'a'.repeat(32)}]},
    };
    await page.route('https://gate.test/**', async route => {
      const pathname = new URL(route.request().url()).pathname;
      if (Object.hasOwn(responses,pathname)) return route.fulfill({json:responses[pathname]});
      const file = pathname.endsWith('/') ? 'admin.html' : path.basename(pathname);
      if (['admin.html','admin.js','admin.css'].includes(file)) return route.fulfill({path:path.join(root,file)});
      throw new Error('Unexpected request: '+pathname);
    });
    for (const [tab,heading] of [['tickets','New enrollment ticket'],['email','Email delivery']]) {
      await page.goto('https://gate.test/_lanternfish/admin/?render='+tab+'#'+tab);
      await page.getByRole('heading',{name:heading,exact:true}).waitFor();
      await page.getByRole('button',{name:'Load libraries',exact:true}).click();
      await page.getByText('Movies',{exact:true}).waitFor();
      assert.equal(await page.locator('#flash').isVisible(),false,await page.locator('#flash').textContent());
      assert.match(await page.locator('#view').textContent(),/Allow media playback/);
      console.log(tab+' rendered, including Jellyfin library controls');
    }
    assert.deepEqual(errors,[]);
  } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exitCode=1;});
