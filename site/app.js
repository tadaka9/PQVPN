const menu=document.querySelector('.menu');const links=document.querySelector('.nav-links');menu?.addEventListener('click',()=>{const open=menu.getAttribute('aria-expanded')==='true';menu.setAttribute('aria-expanded',String(!open));links.classList.toggle('open',!open)});links?.addEventListener('click',()=>{menu?.setAttribute('aria-expanded','false');links.classList.remove('open')});
const observer=new IntersectionObserver(entries=>entries.forEach(entry=>{if(entry.isIntersecting){entry.target.classList.add('visible');observer.unobserve(entry.target)}}),{threshold:.12});document.querySelectorAll('.reveal').forEach(el=>observer.observe(el));

const repositoryUrl='https://github.com/tadaka9/PQVPN';
async function loadRepositorySignal(){
  const count=document.querySelector('#star-count');const signal=document.querySelector('#github-signal');
  if(!count||!signal)return;
  try{
    const response=await fetch('https://api.github.com/repos/tadaka9/PQVPN',{cache:'no-store',headers:{Accept:'application/vnd.github+json'}});
    if(!response.ok)throw new Error(`GitHub API ${response.status}`);
    const repository=await response.json();
    const stars=Number(repository.stargazers_count)||0;const forks=Number(repository.forks_count)||0;
    count.textContent=`${stars.toLocaleString()} star${stars===1?'':'s'}`;
    signal.textContent=`Live from GitHub · ${stars.toLocaleString()} stars · ${forks.toLocaleString()} forks · updated ${new Date(repository.updated_at).toLocaleDateString()}`;
  }catch{count.textContent='View project';signal.textContent='Public counts are temporarily unavailable. The repository link remains available.'}
}
document.querySelector('#share-project')?.addEventListener('click',async event=>{
  const data={title:'PQVPN — Post-quantum paths you control',text:'Inspect PQVPN, an experimental C++23 peer network with hybrid post-quantum identity.',url:location.href.split('#')[0]};
  try{if(navigator.share){await navigator.share(data);event.currentTarget.textContent='Shared'}else{await navigator.clipboard.writeText(data.url);event.currentTarget.textContent='Link copied'}}catch(error){if(error.name!=='AbortError')event.currentTarget.textContent='Share unavailable'}
});
document.querySelector('#copy-bitcoin')?.addEventListener('click',async event=>{const address=document.querySelector('#bitcoin-address')?.textContent.trim();try{await navigator.clipboard.writeText(address);event.currentTarget.textContent='BTC address copied'}catch{event.currentTarget.textContent='Copy unavailable'}});
document.querySelector('#copy-iban')?.addEventListener('click',async event=>{const iban=document.querySelector('#iban-address')?.textContent.trim();try{await navigator.clipboard.writeText(iban);event.currentTarget.textContent='IBAN copied'}catch{event.currentTarget.textContent='Copy unavailable'}});
loadRepositorySignal();
const registryUrl=new URL('mainnet/peers.json',location.href).href;document.querySelector('#copy-registry')?.addEventListener('click',async event=>{try{await navigator.clipboard.writeText(registryUrl);event.currentTarget.textContent='Copied'}catch{event.currentTarget.textContent='Copy unavailable'}});
let registryLoading=false;
async function loadRegistry(){
  if(registryLoading)return;
  registryLoading=true;
  const refresh=document.querySelector('#refresh-registry');
  if(refresh)refresh.disabled=true;
  try{
    const url=new URL(registryUrl);url.searchParams.set('live',String(Date.now()));
    const response=await fetch(url,{cache:'no-store',headers:{Accept:'application/json'}});
    if(!response.ok)throw new Error(`HTTP ${response.status}`);
    const registry=await response.json();
    const peers=Array.isArray(registry.peers)?registry.peers:[];
    document.querySelector('#registry-status').textContent=peers.length?`${peers.length} declared peer${peers.length===1?'':'s'} · live`:'Registry online · no public peers yet';
    const releaseBasis=registry.release_basis?` · ${registry.release_basis}`:'';
    document.querySelector('#registry-meta').textContent=`Schema ${registry.schema_version} · source ${registry.updated_at}${releaseBasis} · synced ${new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'})}`;
    document.querySelector('#registry-network').textContent=registry.network||'pqvpn-mainnet-alpha';
    document.querySelector('#registry-notice').textContent=registry.notice||'Opt-in discovery only.';
    const list=document.querySelector('#peer-list');
    if(!peers.length){list.innerHTML='<p class="empty"><strong>The registry is online and intentionally empty.</strong><br>No operator has completed the public consent review yet. Private PQVPN networks continue to work with manually configured bootstrap peers.</p>';return}
    list.innerHTML=peers.map(peer=>{const families=[peer.ipv4?'IPv4':'',peer.ipv6?'IPv6':''].filter(Boolean).join(' + ')||'address unpublished';const roles=Array.isArray(peer.roles)?peer.roles.join(', '):'role unpublished';const endpoints=Array.isArray(peer.endpoints)&&peer.endpoints.length?peer.endpoints.join(' · '):peer.endpoint;const addressStatus=peer.address_status||families;return`<article class="peer"><strong>${escapeText(peer.name)}</strong><span>${escapeText(endpoints)}</span><span>${escapeText(peer.region)} · ${escapeText(roles)}</span><span>${escapeText((peer.transports||[]).join(' / ').toUpperCase())} · ${escapeText(families)} · ${escapeText(peer.release||'release pending')}</span><span>${escapeText(addressStatus)}</span><span class="peer-status">${escapeText(peer.status||'status unpublished')} · <a href="${safeHref(peer.policy_url)}">Policy</a></span></article>`}).join('');
  }catch(error){document.querySelector('#registry-status').textContent='Registry unavailable';document.querySelector('#registry-meta').textContent=`${error.message} · retrying automatically`;document.querySelector('#peer-list').innerHTML='<p class="empty">The live registry could not be loaded. The page will retry; use the repository copy and verify its history before connecting.</p>'}
  finally{registryLoading=false;if(refresh)refresh.disabled=false}
}
document.querySelector('#refresh-registry')?.addEventListener('click',loadRegistry);
loadRegistry();setInterval(()=>{if(!document.hidden)loadRegistry()},60000);document.addEventListener('visibilitychange',()=>{if(!document.hidden)loadRegistry()});
function escapeText(value){const node=document.createElement('span');node.textContent=String(value);return node.innerHTML}
function safeHref(value){try{const url=new URL(String(value),location.href);return url.protocol==='https:'?escapeText(url.href):'#'}catch{return'#'}}
document.querySelector('#open-registry')?.addEventListener('click',event=>{const details=document.querySelector('#registry-details');const open=event.currentTarget.getAttribute('aria-expanded')==='true';event.currentTarget.setAttribute('aria-expanded',String(!open));event.currentTarget.textContent=open?'Open peer registry':'Close peer registry';details.hidden=open});

const releasePage='https://github.com/tadaka9/PQVPN/releases';
const downloadButtons=[...document.querySelectorAll('[data-platform-download]')];
const downloadButton=document.querySelector('#platform-download');
const detectedLabel=document.querySelector('#platform-detected');
const releaseLabel=document.querySelector('#download-release');
const projectVersion=document.querySelector('#project-version');
const downloadLinks=new Map([...document.querySelectorAll('[data-download-key]')].map(link=>[link.dataset.downloadKey,link]));
const assetMatchers={
  'windows-x64':name=>/windows-x64\.msi$/i.test(name),
  'windows-portable-x64':name=>/windows-x64-.+-portable\.zip$/i.test(name),
  'macos-arm64':name=>name.endsWith('macos-arm64.tar.gz'),
  'macos-x64':name=>name.endsWith('macos-x86_64.tar.gz'),
  'deb-x64':name=>name.endsWith('_amd64.deb'),
  'deb-arm64':name=>name.endsWith('_arm64.deb'),
  'rpm-x64':name=>name.endsWith('.x86_64.rpm'),
  'rpm-arm64':name=>name.endsWith('.aarch64.rpm'),
  arch:name=>name==='PKGBUILD',
  'linux-x64':name=>name.endsWith('linux-x86_64-desktop-test.tar.gz'),
  'linux-arm64':name=>name.endsWith('linux-arm64-desktop-test.tar.gz'),
  'android-arm64':name=>name.endsWith('android-arm64-preview-test-signed.apk'),
  'ios-arm64':name=>name.endsWith('ios-arm64-preview-unsigned.zip')
};
async function platformFacts(){
  const ua=navigator.userAgent.toLowerCase();
  const basicPlatform=(navigator.userAgentData?.platform||navigator.platform||'').toLowerCase();
  let architecture='';
  let bitness='';
  if(navigator.userAgentData?.getHighEntropyValues){
    try{const hints=await navigator.userAgentData.getHighEntropyValues(['architecture','bitness']);architecture=(hints.architecture||'').toLowerCase();bitness=(hints.bitness||'').toLowerCase()}catch{}
  }
  let architectureSource=architecture?'user-agent client hints':'browser user agent';
  if(!architecture){
    if(/aarch64|arm64/.test(ua))architecture='arm';
    else if(/x86_64|x86-64|x64|win64|wow64|amd64/.test(ua))architecture='x86';
    else if(/i[3-6]86|\bx86\b/.test(ua)){architecture='x86';bitness='32'}
  }
  const arm64=architecture==='arm'&&bitness!=='32';
  const x64=architecture==='x86'&&bitness!=='32';
  const unsupported32=bitness==='32';
  let os='unknown';
  if(/android/.test(ua))os='android';
  else if(/iphone|ipad|ipod/.test(ua))os='ios';
  else if(basicPlatform.includes('win')||ua.includes('windows'))os='windows';
  else if(basicPlatform.includes('mac')||ua.includes('mac os'))os='macos';
  else if(basicPlatform.includes('linux')||ua.includes('linux'))os='linux';
  let distro='';
  if(/arch linux|manjaro/.test(ua))distro='arch';
  else if(/fedora|rhel|red hat|centos|opensuse|suse/.test(ua))distro='rpm';
  else if(/ubuntu|debian|linux mint|pop!_os/.test(ua))distro='deb';
  return{os,arm64,x64,distro,unsupported32,architectureKnown:arm64||x64,architectureSource};
}
function recommendationFor(facts){
  const arch=facts.arm64?'arm64':'x64';
  if(facts.os==='android')return'android-arm64';
  if(facts.os==='ios')return'ios-arm64';
  if(facts.os==='windows')return facts.x64?'windows-x64':null;
  if(facts.os==='macos')return facts.architectureKnown?`macos-${arch}`:null;
  if(facts.os==='linux'){
    if(facts.distro==='arch')return'arch';
    if(!facts.architectureKnown)return null;
    if(facts.distro==='deb')return`deb-${arch}`;
    if(facts.distro==='rpm')return`rpm-${arch}`;
    return facts.architectureKnown?`linux-${arch}`:null;
  }
  return null;
}
function configureMobileCard(key,selection){
  const platform=key==='android-arm64'?'android':'ios';
  const link=document.querySelector(`#mobile-${platform}-link`);
  const status=document.querySelector(`#mobile-${platform}-status`);
  const qr=document.querySelector(`#mobile-${platform}-qr`);
  if(!link||!status||!qr)return;
  if(!selection){
    link.href=releasePage;link.setAttribute('aria-disabled','true');link.removeAttribute('download');
    status.textContent='No checksum-published preview is available yet.';qr.hidden=true;qr.removeAttribute('src');return;
  }
  link.href=selection.asset.browser_download_url;link.removeAttribute('aria-disabled');link.setAttribute('download','');
  link.textContent=platform==='android'?'Download unsigned APK':'Download unsigned iOS ZIP';
  status.textContent=`${selection.release.tag_name} · interface preview only · SHA256SUMS published`;
  qr.src=`assets/mobile-${platform}-qr.svg?release=${encodeURIComponent(selection.release.tag_name)}`;qr.hidden=false;
}
function platformDescription(facts){
  const arch=facts.arm64?'ARM64':facts.x64?'x86-64':facts.unsupported32?'32-bit (unsupported)':'architecture needs confirmation';
  const names={windows:'Windows',macos:'macOS',linux:'Linux',android:'Android',ios:'iOS',unknown:'unknown system'};
  return`${names[facts.os]} · ${arch}`;
}
async function configurePlatformDownload(){
  const facts=await platformFacts();
  const recommendation=recommendationFor(facts);
  detectedLabel.textContent=`Detected ${platformDescription(facts)} · checking published packages`;
  try{
    const response=await fetch('https://api.github.com/repos/tadaka9/PQVPN/releases?per_page=10',{cache:'no-store',headers:{Accept:'application/vnd.github+json'}});
    if(!response.ok)throw new Error(`GitHub API ${response.status}`);
    const releases=(await response.json()).filter(release=>!release.draft&&release.assets?.some(asset=>asset.name==='SHA256SUMS')).sort((a,b)=>new Date(b.published_at)-new Date(a.published_at));
    const selections=new Map();
    for(const[key,match]of Object.entries(assetMatchers)){
      for(const release of releases){
        const asset=release.assets.find(item=>match(item.name));
        if(asset){selections.set(key,{release,asset});break}
      }
    }
    if(!selections.size)throw new Error('No package release is published yet');
    for(const link of downloadLinks.values())link.classList.remove('recommended');
    for(const[key,link]of downloadLinks){
      const selection=selections.get(key);
      if(selection){link.href=selection.asset.browser_download_url;link.title=`${selection.release.tag_name} · checksum manifest available`;link.removeAttribute('aria-disabled');link.setAttribute('download','')}
      else{link.href=releasePage;link.removeAttribute('title');link.setAttribute('aria-disabled','true');link.removeAttribute('download')}
    }
    configureMobileCard('android-arm64',selections.get('android-arm64'));
    configureMobileCard('ios-arm64',selections.get('ios-arm64'));
    const newestRelease=releases[0];
    if(projectVersion)projectVersion.textContent=newestRelease.tag_name;
    releaseLabel.textContent=`${newestRelease.tag_name} · each selected package has a same-release SHA256SUMS manifest`;
    const recommendedLink=recommendation?downloadLinks.get(recommendation):null;
    if(recommendedLink&&recommendedLink.getAttribute('aria-disabled')!=='true'){
      recommendedLink.classList.add('recommended');
      for(const button of downloadButtons){button.href=recommendedLink.href;button.setAttribute('download','')}
      downloadButton.textContent=`Download ${recommendedLink.textContent.trim()}`;
      detectedLabel.textContent=`Detected ${platformDescription(facts)} · recommended package selected`;
    }else{
      for(const button of downloadButtons)button.href=newestRelease.html_url;
      downloadButton.textContent='Choose an available experimental package';
      document.querySelector('#download-panel').open=true;
      for(const button of downloadButtons)button.removeAttribute('download');
      const reason=(facts.os==='android'||facts.os==='ios')?'No mobile preview has been published yet':facts.unsupported32?'32-bit builds are not published':'Confirm your architecture or package manager';
      detectedLabel.textContent=`${platformDescription(facts)} · ${reason}`;
    }
  }catch(error){
    configureMobileCard('android-arm64',null);configureMobileCard('ios-arm64',null);
    for(const button of downloadButtons){button.href=releasePage;button.removeAttribute('download')}
    downloadButton.textContent='Open published releases';
    detectedLabel.textContent=`${platformDescription(facts)} · package list unavailable, choose from GitHub Releases`;
    releaseLabel.textContent=error.message;
    if(projectVersion)projectVersion.textContent='alpha · release feed unavailable';
  }
}
configurePlatformDownload();setInterval(()=>{if(!document.hidden)configurePlatformDownload()},900000);

const strangeForm=document.querySelector('#strangenet-connect');
const strangeRoom=document.querySelector('#strangenet-room');
const strangeMode=document.querySelector('#strangenet-target-mode');
const strangePeerField=document.querySelector('#strangenet-peer-field');
const strangePeer=document.querySelector('#strangenet-peer');
const strangeStatus=document.querySelector('#strangenet-status');

function setStrangeTargetMode(){
  const pinned=strangeMode.value==='single';
  strangePeerField.style.display=pinned?'grid':'none';
  strangePeer.disabled=!pinned;
  strangePeer.required=pinned;
  strangeStatus.textContent=pinned
    ? 'Enter the 64-character identity of the authenticated peer you want to contact.'
    : 'Universal mode: each send reaches up to 512 directly authenticated sessions with antiflood protection.';
}
strangeMode.addEventListener('change',setStrangeTargetMode);
setStrangeTargetMode();

function strangeValues(){
  return {
    room:strangeRoom.value.trim(),
    peer:strangeMode.value==='single'?strangePeer.value.trim():''
  };
}
function validStrange(values){
  if(!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(values.room)){
    strangeStatus.textContent='Use 1–64 letters, numbers, dots, underscores or hyphens for the room.';
    strangeRoom.focus();
    return false;
  }
  if(strangeMode.value==='single'&&!/^[0-9a-fA-F]{64}$/.test(values.peer)){
    strangeStatus.textContent='The selected peer identity must contain exactly 64 hexadecimal characters.';
    strangePeer.focus();
    return false;
  }
  return true;
}
function strangeCommand(values){
  const target=values.peer?` --strangenet-peer ${values.peer.toLowerCase()}`:'';
  return`pqvpn_node --config config.json --strangenet-room ${values.room}${target}`;
}
strangeForm.addEventListener('submit',async event=>{
  event.preventDefault();
  const values=strangeValues();
  if(!validStrange(values))return;
  try{
    await navigator.clipboard.writeText(strangeCommand(values));
    event.submitter.textContent='Command copied';
    strangeStatus.textContent='Run the copied command in a terminal where PQVPN is installed.';
  }catch{
    strangeStatus.textContent=`Clipboard unavailable. Run: ${strangeCommand(values)}`;
  }
});

function startPixelCommons(){
  const shell=document.querySelector('#pixel-world-game');
  const canvas=document.querySelector('#pixel-game-canvas');
  const status=document.querySelector('#pixel-game-status');
  const zoneLabel=document.querySelector('#pixel-game-zone');
  const hud=document.querySelector('#pixel-game-hud');
  const action=document.querySelector('#pixel-game-action');
  const reset=document.querySelector('#pixel-game-reset');
  const chat=document.querySelector('#pixel-game-chat');
  const chatMessage=document.querySelector('#pixel-game-message');
  if(!shell||!canvas||!status||!zoneLabel||!hud||!action||!reset||!chat||!chatMessage)return;
  const context=canvas.getContext('2d');
  const storageKey='pqvpn.pixelCommons.v1';
  const start={x:118,y:245,pq:0,signals:[],quest:false,complete:false};
  let state={...start,signals:[]};
  try{
    const saved=JSON.parse(localStorage.getItem(storageKey)||'null');
    if(saved&&Number.isFinite(saved.x)&&Number.isFinite(saved.y)&&Number.isInteger(saved.pq)&&Array.isArray(saved.signals)){
      const restoredSignals=[...new Set(saved.signals.filter(value=>['forge','garden','commons'].includes(value)))];
      state={x:Math.max(24,Math.min(936,saved.x)),y:Math.max(84,Math.min(456,saved.y)),pq:Math.max(0,Math.min(10000,saved.pq)),signals:restoredSignals,quest:Boolean(saved.quest),complete:Boolean(saved.complete&&restoredSignals.length===3)};
    }
  }catch{}
  const keeper={x:72,y:242,name:'SIGNAL KEEPER'};
  const signals=[
    {id:'forge',x:805,y:220,color:'#ff7c66',label:'FORGE SIGNAL'},
    {id:'garden',x:177,y:302,color:'#61d6c7',label:'GARDEN SIGNAL'},
    {id:'commons',x:778,y:297,color:'#ffd166',label:'COMMONS SIGNAL'}
  ];
  const solids=[
    {x:18,y:80,w:178,h:108},{x:755,y:80,w:186,h:108},
    {x:18,y:335,w:205,h:118},{x:735,y:330,w:206,h:123},
    {x:372,y:205,w:216,h:98}
  ];
  const keys=new Set();
  let target=null;
  let last=performance.now();
  let messageTimer=0;
  let saveTimer=0;
  let visible=true;
  let currentZone=zoneAt(state.x,state.y);
  const speech={player:'',playerUntil:0,keeper:'',keeperUntil:0};
  const reducedMotion=matchMedia('(prefers-reduced-motion: reduce)').matches;
  function save(){
    try{localStorage.setItem(storageKey,JSON.stringify({x:Math.round(state.x),y:Math.round(state.y),pq:state.pq,signals:state.signals,quest:state.quest,complete:state.complete}))}catch{}
  }
  function queueSave(){clearTimeout(saveTimer);saveTimer=setTimeout(save,900)}
  function say(message){status.textContent=message;messageTimer=performance.now()+8500}
  function zoneAt(x,y){
    if(x<260&&y<260)return'GATE';
    if(x>700&&y<260)return'FORGE';
    if(x<270&&y>300)return'GARDEN';
    if(x>690&&y>295)return'COMMONS';
    return'PATHS';
  }
  function collides(x,y){
    const radius=12;
    if(x<radius||x>canvas.width-radius||y<66+radius||y>canvas.height-radius)return true;
    return solids.some(rect=>x+radius>rect.x&&x-radius<rect.x+rect.w&&y+radius>rect.y&&y-radius<rect.y+rect.h);
  }
  function move(dx,dy){
    const nextX=state.x+dx;
    const nextY=state.y+dy;
    const beforeX=state.x,beforeY=state.y;
    if(!collides(nextX,state.y))state.x=nextX;
    if(!collides(state.x,nextY))state.y=nextY;
    if(state.x!==beforeX||state.y!==beforeY)queueSave();
    const zone=zoneAt(state.x,state.y);
    zoneLabel.textContent=zone;
    if(zone!==currentZone){
      currentZone=zone;
      const mood={GATE:'Trust begins with a choice.',FORGE:'Ideas ring louder near the Forge.',GARDEN:'The Garden leaves room between words.',COMMONS:'The Commons waits for real authenticated peers.',PATHS:'Every route reveals a different edge.'};
      say(mood[zone]);
    }
    target=null;
  }
  function distance(a,b){return Math.hypot(a.x-b.x,a.y-b.y)}
  function interact(){
    if(distance(state,keeper)<58){
      let reply='';
      if(!state.quest){state.quest=true;reply='Recover the three lost signals. Each restored signal grants 25 PQ. Return when all three answer.';save()}
      else if(state.signals.length===3&&!state.complete){state.complete=true;state.pq+=100;reply='The Commons can hear itself again. +100 PQ. Progress, not cryptocurrency.';save()}
      else if(state.complete)reply='The path is stable. Your PQ stay on this device; real E2E peers live in the native client.';
      else reply=`${3-state.signals.length} signal${state.signals.length===2?'':'s'} still silent.`;
      speech.keeper=reply;speech.keeperUntil=performance.now()+8500;say(`Signal Keeper: ${reply}`);
      updateHud();return;
    }
    const nearby=signals.find(signal=>!state.signals.includes(signal.id)&&distance(state,signal)<54);
    if(nearby){
      if(!state.quest){say('The signal is dormant. Speak with the Signal Keeper at the Gate first.');return}
      state.signals.push(nearby.id);state.pq+=25;
      say(`${nearby.label} restored. +25 PQ. ${3-state.signals.length} signals remain.`);save();updateHud();return;
    }
    say('Nothing answers here. Look for a pulsing signal or return to the Keeper.');
  }
  function updateHud(){hud.textContent=`${state.pq} PQ · ${state.signals.length}/3 SIGNALS${state.complete?' · PATH RESTORED':''}`}
  function tileRect(rect,color,label){
    context.fillStyle='#090d1a';context.fillRect(rect.x+7,rect.y+7,rect.w,rect.h);
    context.fillStyle=color;context.fillRect(rect.x,rect.y,rect.w,rect.h);
    context.strokeStyle='#a8b5df';context.lineWidth=3;context.strokeRect(rect.x+.5,rect.y+.5,rect.w-1,rect.h-1);
    context.fillStyle='#fff8e7';context.font='bold 16px monospace';context.textAlign='center';context.fillText(label,rect.x+rect.w/2,rect.y+32);
  }
  function avatar(x,y,color,label){
    context.fillStyle='#080b18';context.fillRect(x-9,y-22,18,15);context.fillRect(x-12,y-8,24,26);
    context.fillStyle=color;context.fillRect(x-6,y-19,12,10);context.fillRect(x-9,y-5,18,20);
    context.fillStyle='#fff8e7';context.font='bold 11px monospace';context.textAlign='center';context.fillText(label,x,y+35);
  }
  function speechBubble(x,y,text,accent){
    if(!text)return;
    const words=text.split(/\s+/);const lines=[''];
    for(const word of words){const index=lines.length-1;const candidate=(lines[index]+' '+word).trim();if(candidate.length>31&&lines.length<3)lines.push(word);else lines[index]=candidate}
    if(lines[2]?.length>31)lines[2]=`${lines[2].slice(0,28)}…`;
    context.font='bold 11px monospace';const width=Math.min(300,Math.max(96,...lines.map(line=>context.measureText(line).width+24)));const height=18+lines.length*15;
    const left=Math.max(8,Math.min(canvas.width-width-8,x-width/2));const top=Math.max(70,y-height-38);
    context.fillStyle='rgba(8,13,29,.96)';context.fillRect(left,top,width,height);context.strokeStyle=accent;context.lineWidth=2;context.strokeRect(left+.5,top+.5,width-1,height-1);
    context.fillStyle=accent;context.beginPath();context.moveTo(x-7,top+height);context.lineTo(x+7,top+height);context.lineTo(x,top+height+8);context.fill();
    context.fillStyle='#fff8e7';context.textAlign='left';lines.forEach((line,index)=>context.fillText(line,left+12,top+18+index*15));
  }
  function render(time){
    context.fillStyle='#202b4b';context.fillRect(0,0,canvas.width,canvas.height);
    const tile=24;
    for(let y=66;y<canvas.height;y+=tile)for(let x=0;x<canvas.width;x+=tile){context.fillStyle=((x/tile+y/tile)%2)?'#263456':'#2c3a60';context.fillRect(x,y,tile,tile/2);context.fillStyle=((x/tile+y/tile)%2)?'#233052':'#29375d';context.fillRect(x,y+tile/2,tile,tile/2)}
    context.fillStyle='#10172d';context.fillRect(0,0,canvas.width,66);
    context.fillStyle='#b7f34a';context.font='bold 14px monospace';context.textAlign='left';context.fillText('STRANGENET // LOCAL STORY INSTANCE',20,28);
    context.fillStyle='#aeb8d5';context.font='12px monospace';context.fillText('No telemetry · no simulated peers · native client = E2E multiplayer',20,49);
    tileRect(solids[0],'#493b70','GATE');tileRect(solids[1],'#6a3939','FORGE');tileRect(solids[2],'#2d5b50','GARDEN');tileRect(solids[3],'#315078','COMMONS');tileRect(solids[4],'#344163','ARCHIVE');
    context.strokeStyle='rgba(183,243,74,.32)';context.lineWidth=4;context.setLineDash([8,8]);context.strokeRect(270,112,420,310);context.setLineDash([]);
    avatar(keeper.x,keeper.y,'#b7f34a','KEEPER');
    for(const signal of signals){
      if(state.signals.includes(signal.id))continue;
      const pulse=reducedMotion?3:3+Math.sin(time/240+signal.x)*2;
      context.fillStyle=signal.color;context.fillRect(signal.x-8-pulse,signal.y-8-pulse,16+pulse*2,16+pulse*2);
      context.strokeStyle='#fff8e7';context.strokeRect(signal.x-13-pulse,signal.y-13-pulse,26+pulse*2,26+pulse*2);
    }
    avatar(state.x,state.y,'#71e9ff','YOU');
    if(time<speech.keeperUntil)speechBubble(keeper.x,keeper.y,speech.keeper,'#b7f34a');
    if(time<speech.playerUntil)speechBubble(state.x,state.y,speech.player,'#71e9ff');
    if(target){context.strokeStyle='#71e9ff';context.lineWidth=2;context.strokeRect(target.x-8,target.y-8,16,16)}
  }
  function tick(time){
    if(!visible){last=time;return}
    const frameInterval=reducedMotion?100:32;
    if(time-last<frameInterval){requestAnimationFrame(tick);return}
    const dt=Math.min(36,time-last);last=time;
    let dx=0,dy=0;
    if(keys.has('arrowleft')||keys.has('a'))dx--;
    if(keys.has('arrowright')||keys.has('d'))dx++;
    if(keys.has('arrowup')||keys.has('w'))dy--;
    if(keys.has('arrowdown')||keys.has('s'))dy++;
    if(dx||dy){const length=Math.hypot(dx,dy);move(dx/length*dt*.16,dy/length*dt*.16)}
    else if(target){const dxTarget=target.x-state.x,dyTarget=target.y-state.y;const length=Math.hypot(dxTarget,dyTarget);if(length>5)move(dxTarget/length*dt*.16,dyTarget/length*dt*.16);else target=null}
    if(messageTimer&&time>messageTimer){messageTimer=0;status.textContent=state.complete?'Path restored. Explore freely or reset the local story.':'Find the signals, then return to the Keeper.'}
    render(time);requestAnimationFrame(tick);
  }
  const acceptedKeys=new Set(['arrowleft','arrowright','arrowup','arrowdown','w','a','s','d']);
  shell.addEventListener('keydown',event=>{if(event.target.closest('input,textarea,select,button'))return;const key=event.key.toLowerCase();if(acceptedKeys.has(key)){event.preventDefault();keys.add(key);target=null}else if(key==='e'||key===' '||key==='enter'){event.preventDefault();interact()}});
  shell.addEventListener('keyup',event=>keys.delete(event.key.toLowerCase()));
  shell.addEventListener('blur',()=>keys.clear());
  canvas.addEventListener('pointerdown',event=>{const box=canvas.getBoundingClientRect();target={x:(event.clientX-box.left)/box.width*canvas.width,y:(event.clientY-box.top)/box.height*canvas.height};shell.focus()});
  document.querySelectorAll('[data-pixel-move]').forEach(button=>{
    const vectors={up:[0,-18],down:[0,18],left:[-18,0],right:[18,0]};
    let repeat=0;
    const stop=()=>{clearInterval(repeat);repeat=0};
    button.addEventListener('pointerdown',event=>{event.preventDefault();const[dx,dy]=vectors[button.dataset.pixelMove];move(dx,dy);stop();repeat=setInterval(()=>move(dx,dy),90);shell.focus()});
    button.addEventListener('pointerup',stop);button.addEventListener('pointercancel',stop);button.addEventListener('pointerleave',stop);
  });
  action.addEventListener('click',()=>{interact();shell.focus()});
  chat.addEventListener('submit',event=>{
    event.preventDefault();
    const message=chatMessage.value.trim().replace(/\s+/g,' ').slice(0,140);
    if(!message){chatMessage.focus();return}
    speech.player=message;speech.playerUntil=performance.now()+8000;chatMessage.value='';
    if(distance(state,keeper)<90){
      const lower=message.toLocaleLowerCase();
      let reply='I heard you. In this local story, silence is also a valid answer.';
      if(/\b(ciao|hello|hi|salve)\b/.test(lower))reply='Welcome, traveller. Identity is proven by keys, not by volume.';
      else if(/\b(pq|credit|credito|crediti)\b/.test(lower))reply='PQ mark local progress only. They cannot be bought, sold or transferred.';
      else if(/\b(help|aiuto|signal|segnal)/.test(lower))reply=`Seek the pulsing signals. ${3-state.signals.length} remain.`;
      else if(/\b(privacy|telemetr|ip)\b/.test(lower))reply='This bubble remains in memory and disappears. No IP or sentence leaves the page.';
      speech.keeper=reply;speech.keeperUntil=performance.now()+8500;say(`Signal Keeper: ${reply}`);
    }else say('Your words rise as a local bubble. Move near the Keeper for a reply.');
    shell.focus();
  });
  reset.addEventListener('click',()=>{try{localStorage.removeItem(storageKey)}catch{}state={...start,signals:[]};target=null;updateHud();zoneLabel.textContent='GATE';say('Local progress reset. Speak with the Signal Keeper to begin.');shell.focus()});
  window.addEventListener('pagehide',save);
  new IntersectionObserver(entries=>{const wasVisible=visible;visible=Boolean(entries[0]?.isIntersecting);last=performance.now();if(visible&&!wasVisible)requestAnimationFrame(tick)},{rootMargin:'160px'}).observe(shell);
  updateHud();zoneLabel.textContent=zoneAt(state.x,state.y);
  say(state.quest?'Local journey restored. Continue collecting signals.':'Speak with the Signal Keeper. Move with WASD or arrows; interact with E.');
  requestAnimationFrame(tick);
}
startPixelCommons();

async function startQuantumField(){const canvas=document.querySelector('#quantum-field');if(!canvas||!('WebAssembly'in window))return;const context=canvas.getContext('2d',{alpha:true});const image=context.createImageData(canvas.width,canvas.height);let pointerX=0,pointerY=0;canvas.closest('.hero-art')?.addEventListener('pointermove',event=>{const box=event.currentTarget.getBoundingClientRect();pointerX=(event.clientX-box.left)/box.width-.5;pointerY=(event.clientY-box.top)/box.height-.5},{passive:true});try{const response=await fetch('wasm/quantum_field.wasm');if(!response.ok)throw new Error(`WASM ${response.status}`);const bytes=await response.arrayBuffer();const {instance}=await WebAssembly.instantiate(bytes);const field=instance.exports.field;const reduced=matchMedia('(prefers-reduced-motion: reduce)').matches;let last=0;const paint=time=>{if(!reduced&&time-last<55){requestAnimationFrame(paint);return}last=time;const phase=reduced?0:time*.00018;for(let py=0;py<canvas.height;py+=2){for(let px=0;px<canvas.width;px+=2){const x=(px/canvas.width*2-1)*1.75+pointerX*.28;const y=(py/canvas.height*2-1)*1.75+pointerY*.28;const value=field(x,y,phase);const band=Math.abs(value-Math.floor(value)-.5)*2;const glow=Math.max(0,1-band*1.7);const coral=Math.max(0,1-Math.abs(value*.35-Math.round(value*.35))*3);const r=Math.round(53+202*coral),g=Math.round(70+173*glow),b=Math.round(160+64*(1-glow)),a=Math.round(18+105*glow);for(let oy=0;oy<2;oy++)for(let ox=0;ox<2;ox++){const index=((py+oy)*canvas.width+px+ox)*4;image.data[index]=r;image.data[index+1]=g;image.data[index+2]=b;image.data[index+3]=a}}}context.putImageData(image,0,0);if(!reduced)requestAnimationFrame(paint)};requestAnimationFrame(paint)}catch(error){canvas.hidden=true;console.warn('PQVPN quantum field fallback:',error.message)}}
startQuantumField();
