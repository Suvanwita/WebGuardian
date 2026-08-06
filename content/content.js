// WebGuardian Content Script
console.log('WebGuardian content script initialized.');

let lastReportedScore = -1;

async function runPhishingScan(){
  if (window.phishingScanner) {
    return await window.phishingScanner.scan();
  }
  console.warn('WebGuardian: phishingScanner not loaded.');
  return { penaltyScore: 0, matchedKeywords: [] };
}

function runLoginScan(){
  if (window.loginDetector) {
    return window.loginDetector.scan();
  }
  console.warn('WebGuardian: loginDetector not loaded.');
  return { penaltyScore: 0, flaggedForms: [] };
}

async function runTrackerScan(){
  if (window.trackerDetector) {
    return await window.trackerDetector.scan();
  }
  console.warn('WebGuardian: trackerDetector not loaded.');
  return { penaltyScore: 0, detectedTrackers: [] };
}

async function initScans(){
  try {
    const phishingResult = await runPhishingScan();
    const loginResult = runLoginScan();
    const trackerResult = await runTrackerScan();

    const totalContentPenalty = phishingResult.penaltyScore + loginResult.penaltyScore + trackerResult.penaltyScore;

    if (totalContentPenalty !== lastReportedScore) {
      lastReportedScore = totalContentPenalty;
      chrome.runtime.sendMessage({
        action: 'contentScanResult',
        phishingScan: {
          score: phishingResult.penaltyScore,
          matchedKeywords: phishingResult.matchedKeywords
        },
        loginScan: {
          score: loginResult.penaltyScore,
          flaggedForms: loginResult.flaggedForms
        },
        trackerScan: {
          score: trackerResult.penaltyScore,
          detectedTrackers: trackerResult.detectedTrackers
        }
      }, (response) => {
        if (chrome.runtime.lastError) {
          console.warn('WebGuardian background communication failed:', chrome.runtime.lastError.message);
        } else {
          console.log('WebGuardian background response:', response);
        }
      });
    }
  } catch (error) {
    console.error('WebGuardian: Error running content scans:', error);
  }
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
