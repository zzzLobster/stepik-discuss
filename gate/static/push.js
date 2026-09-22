function urlBase64ToUint8Array(s){s=s.replace(/-/g,"+").replace(/_/g,"/");const p="=".repeat((4-s.length%4)%4);const b=atob(s+p);const o=new Uint8Array(b.length);for(let i=0;i<b.length;i++)o[i]=b.charCodeAt(i);return o;}
function csrfFromCookie(){const m=document.cookie.match(/(?:^|; )__Host-csrf=([^;]*)/);return m?decodeURIComponent(m[1]):"";}
function isIosNotInstalled(){
  const ua=navigator.userAgent||"";
  const ios=/iPhone|iPad|iPod/.test(ua)||(/Macintosh/.test(ua)&&navigator.maxTouchPoints>1);
  if(!ios)return false;
  if(navigator.standalone)return false;
  if(window.matchMedia&&matchMedia("(display-mode: standalone)").matches)return false;
  return true;
}
function showIosHint(el){
  if(!el)return;
  try{
    if(localStorage.getItem("pwa_ios_hint")==="1")return;
  }catch(_){}
  el.textContent="На iPhone/iPad уведомления приходят только из значка на экране «Домой» (Поделиться → На экран «Домой»), а не из Safari. Откройте с иконки — тогда придут уведомления.";
  el.style.display="block";
  try{localStorage.setItem("pwa_ios_hint","1");}catch(_){}
}
async function healSubscription(){
  try{
    if(!("serviceWorker" in navigator)||!("PushManager" in window))return;
    const reg=await navigator.serviceWorker.ready;
    const body=document.body;
    const uid=body?body.getAttribute("data-uid"):"";
    if(!uid)return;
    let keyResp;
    try{
      const r=await fetch("/push/vapid-key",{credentials:"include"});
      if(r.status===429)return;
      if(!r.ok)return;
      keyResp=await r.json();
    }catch(_){return;}
    const fp=keyResp.fp;
    let sub=null;
    try{sub=await reg.pushManager.getSubscription();}catch(_){return;}
    if(sub==null){
      updateBell(false);
      return;
    }
    let storedUid=null,storedCids=null,storedFp=null;
    try{
      storedUid=localStorage.getItem("push_uid");
      storedCids=localStorage.getItem("push_cids");
      storedFp=localStorage.getItem("vapid_key_fp");
    }catch(_){}
    if(storedUid!==null&&storedUid!==String(uid)){
      try{await sub.unsubscribe();}catch(_){}
      try{await fetch("/push/unsubscribe",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfFromCookie()},body:JSON.stringify({endpoint:sub.endpoint})});}catch(_){}
      try{localStorage.removeItem("push_uid");localStorage.removeItem("push_cids");localStorage.removeItem("vapid_key_fp");}catch(_){}
      updateBell(false);
      return;
    }
    if(storedFp!==null&&storedFp!==fp){
      const oldEndpoint=sub.endpoint;
      try{await sub.unsubscribe();}catch(_){}
      let fresh=null;
      try{fresh=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:urlBase64ToUint8Array(keyResp.key)});}catch(_){updateBell(false);return;}
      const fj=fresh.toJSON();
      try{await fetch("/push/unsubscribe",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfFromCookie()},body:JSON.stringify({endpoint:oldEndpoint})});}catch(_){}
      const cids=storedCids||"all";
      let cidsVal="all";
      try{cidsVal=(cids==="all")?"all":JSON.parse(cids);}catch(_){cidsVal="all";}
      try{
        await fetch("/push/subscribe",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfFromCookie()},body:JSON.stringify({endpoint:fresh.endpoint,keys:fj.keys,device:{ua:navigator.userAgent},cids:cidsVal})});
        try{localStorage.setItem("push_uid",String(uid));localStorage.setItem("push_cids",typeof cidsVal==="string"?cidsVal:JSON.stringify(cidsVal));localStorage.setItem("vapid_key_fp",fp);}catch(_){}
        updateBell(true);
      }catch(_){updateBell(false);}
      return;
    }
    const cids=storedCids||"all";
    let cidsVal="all";
    try{cidsVal=(cids==="all")?"all":JSON.parse(cids);}catch(_){cidsVal="all";}
    try{
      const sj=sub.toJSON();
      await fetch("/push/subscribe",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfFromCookie()},body:JSON.stringify({endpoint:sub.endpoint,keys:sj.keys,device:{ua:navigator.userAgent},cids:cidsVal})});
      try{localStorage.setItem("push_uid",String(uid));if(!storedCids)localStorage.setItem("push_cids",typeof cidsVal==="string"?cidsVal:JSON.stringify(cidsVal));localStorage.setItem("vapid_key_fp",fp);}catch(_){}
    }catch(_){}
  }catch(_){}
}
function updateBell(on){
  const bells=document.querySelectorAll("[data-bell]");
  bells.forEach((b)=>{
    b.textContent=on?"🔔 Уведомлять о новых комментариях [Вкл]":"🔔 Уведомлять о новых комментариях [Выкл]";
    b.setAttribute("data-state",on?"on":"off");
  });
  const status=document.querySelectorAll("[data-push-status]");
  status.forEach((el)=>{
    el.textContent=on?"Уведомления включены на этом устройстве.":"Уведомления выключены на этом устройстве. Выход из аккаунта на этом устройстве также отключает их здесь.";
  });
}
async function togglePush(){
  const body=document.body;
  const uid=body?body.getAttribute("data-uid"):"";
  const cid=body?body.getAttribute("data-cid"):"";
  const allowedRaw=body?body.getAttribute("data-allowed"):"";
  if(!uid)return;
  if(!("PushManager" in window)){
    const h=document.querySelector("[data-ios-hint]");
    if(h){h.textContent="На iPhone/iPad уведомления приходят только из значка на экране «Домой» (Поделиться → На экран «Домой»), а не из Safari.";h.style.display="block";}
    return;
  }
  if(isIosNotInstalled()){
    const h=document.querySelector("[data-ios-hint]");
    if(h){showIosHint(h);}
    return;
  }
  let perm="default";
  try{perm=await Notification.requestPermission();}catch(_){perm=Notification.permission;}
  if(perm!=="granted"){
    const st=document.querySelector("[data-push-status]");
    if(st){st.textContent="Уведомления заблокированы в браузере. Разрешите их в настройках сайта, затем попробуйте снова.";}
    return;
  }
  let keyResp;
  try{
    const r=await fetch("/push/vapid-key",{credentials:"include"});
    if(!r.ok)throw new Error("key");
    keyResp=await r.json();
  }catch(_){
    const st=document.querySelector("[data-push-status]");
    if(st){st.textContent="Не удалось включить уведомления. Попробуйте позже.";}
    return;
  }
  try{
    const reg=await navigator.serviceWorker.ready;
    let sub=null;
    try{sub=await reg.pushManager.getSubscription();}catch(_){}
    if(sub){
      try{await sub.unsubscribe();}catch(_){}
      try{await fetch("/push/unsubscribe",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfFromCookie()},body:JSON.stringify({endpoint:sub.endpoint})});}catch(_){}
      try{localStorage.removeItem("push_uid");localStorage.removeItem("push_cids");localStorage.removeItem("vapid_key_fp");}catch(_){}
      updateBell(false);
      return;
    }
    const fresh=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:urlBase64ToUint8Array(keyResp.key)});
    const fj=fresh.toJSON();
    let cidsVal="all";
    if(cid){
      cidsVal=[Number(cid)];
    }
    try{
      const stored=localStorage.getItem("push_cids");
      if(cid&&stored&&stored!=="all"){
        try{
          const arr=JSON.parse(stored);
          if(Array.isArray(arr)){
            const set=new Set(arr.map(Number));
            const bell=document.querySelector("[data-bell]");
            const state=bell?bell.getAttribute("data-state"):"off";
            if(state==="off"){
              set.add(Number(cid));
            }
            cidsVal=Array.from(set);
          }
        }catch(_){}
      } else if(!cid){
        cidsVal="all";
      }
    }catch(_){}
    if(allowedRaw&&cid){
      try{
        const allowed=JSON.parse(allowedRaw);
        if(Array.isArray(allowed)&&cidsVal==="all"){
          cidsVal="all";
        }
      }catch(_){}
    }
    const r=await fetch("/push/subscribe",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfFromCookie()},body:JSON.stringify({endpoint:fresh.endpoint,keys:fj.keys,device:{ua:navigator.userAgent},cids:cidsVal})});
    if(!r.ok)throw new Error("sub");
    try{localStorage.setItem("push_uid",String(uid));localStorage.setItem("push_cids",typeof cidsVal==="string"?cidsVal:JSON.stringify(cidsVal));localStorage.setItem("vapid_key_fp",keyResp.fp);}catch(_){}
    updateBell(true);
  }catch(_){
    const st=document.querySelector("[data-push-status]");
    if(st){st.textContent="Не удалось включить уведомления. Попробуйте позже.";}
  }
}
(function(){
  if("serviceWorker" in navigator){
    try{navigator.serviceWorker.register("/sw.js");}catch(_){}
  }
  document.addEventListener("DOMContentLoaded",()=>{
    const bells=document.querySelectorAll("[data-bell]");
    bells.forEach((b)=>{b.addEventListener("click",togglePush);});
    if(isIosNotInstalled()){
      const h=document.querySelector("[data-ios-hint]");
      if(h)showIosHint(h);
    }
    healSubscription();
    let deferredPrompt=null;
    window.addEventListener("beforeinstallprompt",(e)=>{
      e.preventDefault();
      deferredPrompt=e;
      try{
        if(localStorage.getItem("pwa_install_dismissed")==="1")return;
      }catch(_){}
      const btn=document.querySelector("[data-install]");
      if(btn){
        btn.style.display="block";
        btn.addEventListener("click",async()=>{
          if(deferredPrompt){
            try{deferredPrompt.prompt();await deferredPrompt.userChoice;}catch(_){}
            deferredPrompt=null;
          }
          btn.style.display="none";
        },{once:true});
      }
    });
    window.addEventListener("appinstalled",()=>{
      const btn=document.querySelector("[data-install]");
      if(btn)btn.style.display="none";
    });
    const dismiss=document.querySelector("[data-install-dismiss]");
    if(dismiss){
      dismiss.addEventListener("click",()=>{
        try{localStorage.setItem("pwa_install_dismissed","1");}catch(_){}
        const btn=document.querySelector("[data-install]");
        if(btn)btn.style.display="none";
      });
    }
  });
})();
