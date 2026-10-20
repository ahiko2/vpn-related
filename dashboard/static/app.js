'use strict';
const $ = id => document.getElementById(id);
const fragment = location.hash.slice(1);
if (fragment) {sessionStorage.setItem('vpn-token', fragment); history.replaceState(null, '', '/');}
const token = sessionStorage.getItem('vpn-token') || '';
let busy = false, qrURL = null, qrName = '', revokeName = '';
function notice(message, success=false) {$('notice').textContent=message; $('notice').className='notice'+(success?' success':''); $('notice').hidden=false;}
async function api(path, options={}) {
 const response=await fetch('/api/'+path,{...options,headers:{Authorization:'Bearer '+token,...(options.body?{'Content-Type':'application/json'}:{}),...options.headers}});
 if(!response.ok){let data;try{data=await response.json();}catch{data={error:'The server could not complete this request.'};}throw new Error(data.error||'Request failed.');}
 return response;
}
function bytes(n){if(n<1024)return n+' B';const units=['KiB','MiB','GiB','TiB'];let value=n/1024,i=0;while(value>=1024&&i<units.length-1){value/=1024;i++;}return value.toFixed(value<10?2:1)+' '+units[i];}
function age(time){if(!time)return 'Not yet connected';const seconds=Math.max(0,Math.floor(Date.now()/1000-time));if(seconds<60)return 'Just now';if(seconds<3600)return Math.floor(seconds/60)+' min ago';if(seconds<86400)return Math.floor(seconds/3600)+' hr ago';return Math.floor(seconds/86400)+' days ago';}
function button(label, fn, cls=''){const b=document.createElement('button');b.textContent=label;b.className=cls;b.onclick=()=>fn().catch(e=>notice(e.message));return b;}
function saveBlob(blob, filename){const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
async function download(name){const r=await api('devices/'+encodeURIComponent(name)+'/conf');saveBlob(await r.blob(),'home-vpn-'+name+'.conf');}
async function showQR(name){if(qrURL)URL.revokeObjectURL(qrURL);const r=await api('devices/'+encodeURIComponent(name)+'/qr');qrURL=URL.createObjectURL(await r.blob());qrName=name;$('qr-name').textContent=name;$('qr-image').src=qrURL;$('qr-dialog').showModal();}
function render(state){
 $('server-meta').textContent=state.type+' · '+state.instance;
 $('server-status').textContent=state.active?'VPN running':'VPN inactive';$('server-status').className='pill'+(state.active?'':' warning');
 $('ip').textContent=state.ip;$('credits').textContent=state.credits==='standard'?'Standard · Unlimited off':state.credits+' · check AWS';
 if(state.credits!=='standard')notice('The instance is not using standard CPU credits. Review the AWS setting.');
 let up=0,down=0,recent=0;const body=$('devices');body.replaceChildren();
 for(const device of state.devices){up+=device.upload;down+=device.download;if(device.handshake&&Date.now()/1000-device.handshake<180)recent++;
  const row=document.createElement('tr');const cell=document.createElement('td');cell.className='device';const icon=document.createElement('span');icon.className='device-icon';icon.textContent=/phone|ipad|android/.test(device.name)?'▯':'▱';cell.append(icon);const details=document.createElement('div');const title=document.createElement('span');title.textContent=device.name;const sub=document.createElement('small');sub.textContent=device.slot?'10.66.66.'+device.slot:'Unrecognized address';details.append(title,sub);cell.append(details);row.append(cell);
  for(const text of [age(device.handshake),bytes(device.download),bytes(device.upload)]){const td=document.createElement('td');td.textContent=text;row.append(td);}
  const actions=document.createElement('td');const wrap=document.createElement('div');wrap.className='actions';if(device.export){wrap.append(button('QR code',()=>showQR(device.name)),button('Config ↓',()=>download(device.name)));}
  if(device.managed)wrap.append(button('Revoke',async()=>{revokeName=device.name;$('revoke-description').textContent='Remove access for '+device.name+'? Its tunnel will stop working immediately.';$('revoke-error').textContent='';$('revoke-dialog').showModal();},'revoke'));
  if(!device.managed){const label=document.createElement('span');label.textContent='Managed outside this dashboard';wrap.append(label);}
  actions.append(wrap);row.append(actions);body.append(row);
 }
 if(!state.devices.length){const row=document.createElement('tr'),td=document.createElement('td');td.colSpan=5;td.className='empty';td.textContent='No devices yet. Add your first device to get connected.';row.append(td);body.append(row);}
 $('total').textContent=bytes(up+down);$('upload').textContent=bytes(up);$('download').textContent=bytes(down);$('count').textContent=state.devices.length;$('recent').textContent=recent+' with a handshake in the last 3 minutes';$('checked').textContent='Checked '+new Date(state.checked_at*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',timeZone:'Asia/Tokyo'})+' JST';
}
async function refresh(){if(busy)return;busy=true;$('refresh').disabled=true;$('refresh').textContent='Checking…';try{const state=await (await api('status')).json();render(state);}catch(e){notice(e.message);$('server-status').textContent='Check failed';$('server-status').className='pill warning';}finally{busy=false;$('refresh').disabled=false;$('refresh').textContent='↻ Refresh';}}
$('refresh').onclick=refresh;
$('add').onclick=()=>{$('create-error').textContent='';$('device-name').value='';$('create-dialog').showModal();$('device-name').focus();};
for(const close of document.querySelectorAll('.close'))close.onclick=()=>close.closest('dialog').close();
$('qr-dialog').addEventListener('close',()=>{if(qrURL){URL.revokeObjectURL(qrURL);qrURL=null;}$('qr-image').removeAttribute('src');});
$('qr-download').onclick=async()=>{if(qrURL){const r=await fetch(qrURL);saveBlob(await r.blob(),'home-vpn-'+qrName+'-qr.png');}};
$('create-form').onsubmit=async event=>{event.preventDefault();const b=$('create-submit');b.disabled=true;b.textContent='Creating securely…';$('create-error').textContent='';try{const name=$('device-name').value.trim();await api('devices',{method:'POST',body:JSON.stringify({name})});$('create-dialog').close();notice('Device created. Download its config or open its QR code to connect.',true);await refresh();}catch(e){$('create-error').textContent=e.message;}finally{b.disabled=false;b.textContent='Create device';}};
$('revoke-confirm').onclick=async()=>{const b=$('revoke-confirm');b.disabled=true;try{await api('devices/'+encodeURIComponent(revokeName),{method:'DELETE'});$('revoke-dialog').close();notice('Device access revoked. Other devices are unchanged.',true);await refresh();}catch(e){$('revoke-error').textContent=e.message;}finally{b.disabled=false;}};
refresh();
