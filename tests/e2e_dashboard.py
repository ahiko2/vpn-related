"""Live UI smoke test. Adds and always revokes its own temporary peer only."""
import os
from pathlib import Path
import sys
import time
import urllib.request
import json
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright

url=sys.argv[1]
parsed=urlsplit(url)
base=f'{parsed.scheme}://{parsed.netloc}'
token=parsed.fragment
name='ui-check-'+str(int(time.time()))
created=False
root=Path(__file__).parents[1]


def api(path,method='GET'):
    request=urllib.request.Request(base+'/api/'+path,method=method,headers={'Authorization':'Bearer '+token})
    with urllib.request.urlopen(request,timeout=330) as response:return json.load(response)

try:
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True,executable_path='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
        page=browser.new_page(viewport={'width':1440,'height':1080},device_scale_factor=1)
        errors=[]
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(url)
        page.get_by_role('cell',name='windows',exact=False).wait_for(timeout=120000)
        assert page.locator('#server-status').inner_text()=='VPN running'
        assert 'Standard' in page.locator('#credits').inner_text()
        page.screenshot(path=str(root/'.dashboard/overview.png'),full_page=True)
        page.get_by_role('button',name='Add device',exact=False).click()
        page.get_by_label('Device name').fill(name)
        page.get_by_role('button',name='Create device',exact=True).click()
        row=page.locator('tr').filter(has=page.get_by_text(name,exact=True))
        row.wait_for(timeout=180000)
        created=True
        with page.expect_download(timeout=90000) as download:
            row.get_by_role('button',name='Config ↓').click()
        assert download.value.suggested_filename==f'home-vpn-{name}.conf'
        payload=Path(download.value.path()).read_bytes()
        assert b'AllowedIPs = 0.0.0.0/0, ::/0' in payload
        download.value.delete()
        row.get_by_role('button',name='QR code').click()
        page.locator('#qr-dialog[open]').wait_for(timeout=90000)
        page.wait_for_function("document.getElementById('qr-image').naturalWidth > 100")
        page.get_by_role('button',name='Done',exact=True).click()
        row.get_by_role('button',name='Revoke',exact=True).click()
        page.get_by_role('button',name='Revoke access',exact=True).click()
        row.wait_for(state='detached',timeout=120000)
        created=False
        page.get_by_role('cell',name='windows',exact=False).wait_for()
        page.get_by_role('cell',name='iphone',exact=False).wait_for()
        page.set_viewport_size({'width':390,'height':844})
        assert page.locator('h1').is_visible()
        assert page.locator('#add').is_visible()
        page.screenshot(path=str(root/'.dashboard/mobile.png'),full_page=True)
        assert not errors,errors
        browser.close()
    print('PASS: live device list, add, download, QR display, revoke, Windows/iPhone preservation and mobile layout.')
finally:
    # Also reconcile if the browser fails after enrollment but before setting created=True.
    state=api('status')
    if any(d['name']==name for d in state['devices']):
        api('devices/'+name,'DELETE')
        print('Temporary test device revoked during cleanup.')
    file=root/'.dashboard/clients'/f'{name}.conf'
    file.unlink(missing_ok=True)
    for filename in ('overview.png','mobile.png'):
        path=root/'.dashboard'/filename
        if path.exists():path.chmod(0o600)
