const menu=document.querySelector('.menu');const links=document.querySelector('.nav-links');menu?.addEventListener('click',()=>{const open=menu.getAttribute('aria-expanded')==='true';menu.setAttribute('aria-expanded',String(!open));links.classList.toggle('open',!open)});links?.addEventListener('click',()=>{menu?.setAttribute('aria-expanded','false');links.classList.remove('open')});
const observer=new IntersectionObserver(entries=>entries.forEach(entry=>{if(entry.isIntersecting){entry.target.classList.add('visible');observer.unobserve(entry.target)}}),{threshold:.12});document.querySelectorAll('.reveal').forEach(el=>observer.observe(el));
const registryUrl=new URL('mainnet/peers.json',location.href).href;document.querySelector('#copy-registry')?.addEventListener('click',async event=>{try{await navigator.clipboard.writeText(registryUrl);event.currentTarget.textContent='Copied'}catch{event.currentTarget.textContent='Copy unavailable'}});
fetch('mainnet/peers.json').then(response=>{if(!response.ok)throw new Error(`HTTP ${response.status}`);return response.json()}).then(registry=>{const peers=Array.isArray(registry.peers)?registry.peers:[];document.querySelector('#registry-status').textContent=peers.length?`${peers.length} declared peer${peers.length===1?'':'s'}`:'Registry online · no public peers yet';document.querySelector('#registry-meta').textContent=`Schema ${registry.schema_version} · updated ${registry.updated_at} · opt-in entries`;document.querySelector('#registry-network').textContent=registry.network||'pqvpn-mainnet-alpha';document.querySelector('#registry-notice').textContent=registry.notice||'Opt-in discovery only.';const list=document.querySelector('#peer-list');if(!peers.length){list.innerHTML='<p class="empty"><strong>The registry is online and intentionally empty.</strong><br>No operator has completed the public consent review yet. Private PQVPN networks continue to work with manually configured bootstrap peers.</p>';return}list.innerHTML=peers.map(peer=>`<article class="peer"><strong>${escapeText(peer.name)}</strong><span>${escapeText(peer.endpoint)}</span><span>${escapeText(peer.region)} · ${escapeText(peer.roles.join(', '))}</span><span>${escapeText((peer.transports||[]).join(' / ').toUpperCase())} · IPv4 + IPv6 · <a href="${safeHref(peer.policy_url)}">Policy</a></span></article>`).join('')}).catch(error=>{document.querySelector('#registry-status').textContent='Registry unavailable';document.querySelector('#registry-meta').textContent=error.message;document.querySelector('#peer-list').innerHTML='<p class="empty">The registry could not be loaded. Use the repository copy and verify its history before connecting.</p>'});
function escapeText(value){const node=document.createElement('span');node.textContent=String(value);return node.innerHTML}
function safeHref(value){try{const url=new URL(String(value),location.href);return url.protocol==='https:'?escapeText(url.href):'#'}catch{return'#'}}
document.querySelector('#open-registry')?.addEventListener('click',event=>{const details=document.querySelector('#registry-details');const open=event.currentTarget.getAttribute('aria-expanded')==='true';event.currentTarget.setAttribute('aria-expanded',String(!open));event.currentTarget.textContent=open?'Open peer registry':'Close peer registry';details.hidden=open});

const releasePage='https://github.com/tadaka9/PQVPN/releases';
const downloadButtons=[...document.querySelectorAll('[data-platform-download]')];
const downloadButton=document.querySelector('#platform-download');
const detectedLabel=document.querySelector('#platform-detected');
const releaseLabel=document.querySelector('#download-release');
const downloadLinks=new Map([...document.querySelectorAll('[data-download-key]')].map(link=>[link.dataset.downloadKey,link]));
const assetMatchers={
  'windows-x64':name=>name.endsWith('windows-x86_64.zip'),
  'macos-arm64':name=>name.endsWith('macos-arm64.tar.gz'),
  'macos-x64':name=>name.endsWith('macos-x86_64.tar.gz'),
  'deb-x64':name=>name.endsWith('_amd64.deb'),
  'deb-arm64':name=>name.endsWith('_arm64.deb'),
  'rpm-x64':name=>name.endsWith('.x86_64.rpm'),
  'rpm-arm64':name=>name.endsWith('.aarch64.rpm'),
  arch:name=>name==='PKGBUILD',
  'linux-x64':name=>name.endsWith('linux-x86_64.tar.gz'),
  'linux-arm64':name=>name.endsWith('linux-arm64.tar.gz')
};
async function platformFacts(){
  const ua=navigator.userAgent.toLowerCase();
  const basicPlatform=(navigator.userAgentData?.platform||navigator.platform||'').toLowerCase();
  let architecture='';
  let bitness='';
  if(navigator.userAgentData?.getHighEntropyValues){
    try{const hints=await navigator.userAgentData.getHighEntropyValues(['architecture','bitness']);architecture=(hints.architecture||'').toLowerCase();bitness=(hints.bitness||'').toLowerCase()}catch{}
  }
  if(!architecture){
    if(/aarch64|arm64/.test(ua))architecture='arm';
    else if(/x86_64|x64|win64|amd64/.test(ua))architecture='x86';
  }
  const arm64=architecture==='arm'&&bitness!=='32';
  const x64=architecture==='x86'&&bitness!=='32';
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
  return{os,arm64,x64,distro,architectureKnown:arm64||x64};
}
function recommendationFor(facts){
  const arch=facts.arm64?'arm64':'x64';
  if(facts.os==='windows')return facts.arm64?null:'windows-x64';
  if(facts.os==='macos')return facts.architectureKnown?`macos-${arch}`:null;
  if(facts.os==='linux'){
    if(facts.distro==='arch')return'arch';
    if(facts.distro==='deb')return`deb-${arch}`;
    if(facts.distro==='rpm')return`rpm-${arch}`;
    return facts.architectureKnown?`linux-${arch}`:null;
  }
  return null;
}
function platformDescription(facts){
  const arch=facts.arm64?'ARM64':facts.x64?'x86-64':'architecture unknown';
  const names={windows:'Windows',macos:'macOS',linux:'Linux',android:'Android',ios:'iOS',unknown:'unknown system'};
  return`${names[facts.os]} · ${arch}`;
}
async function configurePlatformDownload(){
  const facts=await platformFacts();
  const recommendation=recommendationFor(facts);
  detectedLabel.textContent=`Detected ${platformDescription(facts)} · checking published packages`;
  try{
    const response=await fetch('https://api.github.com/repos/tadaka9/PQVPN/releases?per_page=10',{headers:{Accept:'application/vnd.github+json'}});
    if(!response.ok)throw new Error(`GitHub API ${response.status}`);
    const releases=(await response.json()).filter(release=>!release.draft);
    const release=releases.find(candidate=>Object.values(assetMatchers).some(match=>candidate.assets?.some(asset=>match(asset.name))));
    if(!release)throw new Error('No package release is published yet');
    for(const[key,link]of downloadLinks){
      const asset=release.assets.find(item=>assetMatchers[key](item.name));
      if(asset){link.href=asset.browser_download_url;link.removeAttribute('aria-disabled');link.setAttribute('download','')}
      else{link.href=release.html_url;link.setAttribute('aria-disabled','true')}
    }
    releaseLabel.textContent=`${release.tag_name} · SHA256SUMS is included with every published format`;
    const recommendedLink=recommendation?downloadLinks.get(recommendation):null;
    if(recommendedLink&&recommendedLink.getAttribute('aria-disabled')!=='true'){
      recommendedLink.classList.add('recommended');
      for(const button of downloadButtons){button.href=recommendedLink.href;button.setAttribute('download','')}
      downloadButton.textContent=`Download ${recommendedLink.textContent.trim()}`;
      detectedLabel.textContent=`Detected ${platformDescription(facts)} · recommended package selected`;
    }else{
      for(const button of downloadButtons)button.href=release.html_url;
      downloadButton.textContent='Choose a verified build';
      document.querySelector('#download-panel').open=true;
      const reason=(facts.os==='android'||facts.os==='ios')?'Mobile platforms are not supported':'Choose your architecture or package manager';
      detectedLabel.textContent=`${platformDescription(facts)} · ${reason}`;
    }
  }catch(error){
    for(const button of downloadButtons)button.href=releasePage;
    downloadButton.textContent='Open verified releases';
    detectedLabel.textContent=`${platformDescription(facts)} · package list unavailable, choose from GitHub Releases`;
    releaseLabel.textContent=error.message;
  }
}
configurePlatformDownload();

const strangeForm=document.querySelector('#strangenet-connect');const strangeRoom=document.querySelector('#strangenet-room');const strangePeer=document.querySelector('#strangenet-peer');const strangeStatus=document.querySelector('#strangenet-status');
function strangeValues(){return{room:strangeRoom.value.trim(),peer:strangePeer.value.trim()}}
function validStrange(values){if(!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(values.room)){strangeStatus.textContent='Use 1–64 letters, numbers, dots, underscores or hyphens for the room.';strangeRoom.focus();return false}if(!/^[0-9a-fA-F]{64}$/.test(values.peer)){strangeStatus.textContent='The peer identity must contain exactly 64 hexadecimal characters.';strangePeer.focus();return false}return true}
function strangeCommand(values){return`pqvpn_node --config config.json --strangenet-room ${values.room} --strangenet-peer ${values.peer.toLowerCase()}`}
strangeForm?.addEventListener('submit',async event=>{event.preventDefault();const values=strangeValues();if(!validStrange(values))return;try{await navigator.clipboard.writeText(strangeCommand(values));event.submitter.textContent='Command copied';strangeStatus.textContent='Run the copied command in a terminal where PQVPN is installed.'}catch{strangeStatus.textContent=`Clipboard unavailable. Run: ${strangeCommand(values)}`}});

async function startQuantumField(){const canvas=document.querySelector('#quantum-field');if(!canvas||!('WebAssembly'in window))return;const context=canvas.getContext('2d',{alpha:true});const image=context.createImageData(canvas.width,canvas.height);let pointerX=0,pointerY=0;canvas.closest('.hero-art')?.addEventListener('pointermove',event=>{const box=event.currentTarget.getBoundingClientRect();pointerX=(event.clientX-box.left)/box.width-.5;pointerY=(event.clientY-box.top)/box.height-.5},{passive:true});try{const response=await fetch('wasm/quantum_field.wasm');if(!response.ok)throw new Error(`WASM ${response.status}`);const bytes=await response.arrayBuffer();const {instance}=await WebAssembly.instantiate(bytes);const field=instance.exports.field;const reduced=matchMedia('(prefers-reduced-motion: reduce)').matches;let last=0;const paint=time=>{if(!reduced&&time-last<55){requestAnimationFrame(paint);return}last=time;const phase=reduced?0:time*.00018;for(let py=0;py<canvas.height;py+=2){for(let px=0;px<canvas.width;px+=2){const x=(px/canvas.width*2-1)*1.75+pointerX*.28;const y=(py/canvas.height*2-1)*1.75+pointerY*.28;const value=field(x,y,phase);const band=Math.abs(value-Math.floor(value)-.5)*2;const glow=Math.max(0,1-band*1.7);const coral=Math.max(0,1-Math.abs(value*.35-Math.round(value*.35))*3);const r=Math.round(53+202*coral),g=Math.round(70+173*glow),b=Math.round(160+64*(1-glow)),a=Math.round(18+105*glow);for(let oy=0;oy<2;oy++)for(let ox=0;ox<2;ox++){const index=((py+oy)*canvas.width+px+ox)*4;image.data[index]=r;image.data[index+1]=g;image.data[index+2]=b;image.data[index+3]=a}}}context.putImageData(image,0,0);if(!reduced)requestAnimationFrame(paint)};requestAnimationFrame(paint)}catch(error){canvas.hidden=true;console.warn('PQVPN quantum field fallback:',error.message)}}
startQuantumField();
