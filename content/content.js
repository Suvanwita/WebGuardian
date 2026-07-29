// WebGuardian Content Script
console.log('WebGuardian content script initialized.');

function runPhishingScan(){
console.log('Running placeholder phishing scan...');
// Placeholder logic
}

function runLoginScan(){
console.log('Running placeholder login scan...');
// Placeholder logic
}

function runTrackerScan(){
console.log('Running placeholder tracker scan...');
// Placeholder logic
}

function initScans(){
runPhishingScan();
runLoginScan();
runTrackerScan();
}

// Set up communication pipeline with background.js
function reportToBackground(action,data){
chrome.runtime.sendMessage({action:action,data:data},(response)=>{
if(chrome.runtime.lastError){
console.warn('WebGuardian background communication failed:',chrome.runtime.lastError.message);
}else{
console.log('WebGuardian background response:',response);
}
});
}

// Observe DOM changes or wait for load
if(document.readyState==='complete'||document.readyState==='interactive'){
initScans();
}else{
document.addEventListener('DOMContentLoaded',initScans);
}

// MutationObserver for significant DOM changes (e.g. injected scripts, new forms)
const observer=new MutationObserver((mutations)=>{
let shouldScan=false;
for(let i=0;i<mutations.length;i++){
const mutation=mutations[i];
if(mutation.addedNodes&&mutation.addedNodes.length>0){
shouldScan=true;
break;
}
}
if(shouldScan){
initScans();
}
});

observer.observe(document.body||document.documentElement,{
childList:true,
subtree:true
});
