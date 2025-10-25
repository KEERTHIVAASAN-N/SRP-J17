
document.addEventListener('DOMContentLoaded', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) return;
  const result = await chrome.storage.session.get([`analysis_${tab.id}`]);
  const analysis = result[`analysis_${tab.id}`];
  const container = document.getElementById('main');
  const loading = document.getElementById('loading');
  loading.style.display = 'none';
  if(!analysis){ document.getElementById('error').style.display='block'; return; }
  container.style.display='block';
  container.innerHTML = `
    <div class="security-score ${analysis.level}">
      <div class="score-circle"><div class="score-value">${analysis.score}</div></div>
      <div class="score-info"><h2>${analysis.level.toUpperCase()}</h2><p>${analysis.reasons[0]||''}</p></div>
    </div>
    <div class="ml-detection">
      <h3>Machine Learning Detection</h3>
      ${analysis.mlUsed?`<div class="ml-status"><span class="ml-badge active">Active</span><span class="ml-confidence">${(analysis.mlConfidence*100||0).toFixed(1)}%</span></div><div class="ml-bar"><div class="ml-bar-fill ${analysis.mlConfidence>=0.75?'high':analysis.mlConfidence>=0.4?'medium':'low'}" style="width:${(analysis.mlConfidence*100||0)}%"></div></div>`:`<div class="ml-status"><span class="ml-badge">Inactive</span><span class="ml-confidence">Not used</span></div>`}
    </div>
    <div class="threat-details"><h3>Details</h3><ul>${(analysis.reasons||[]).map(r=>`<li>${r}</li>`).join('')}</ul></div>
    <div class="actions"><button id="trust" class="action-btn primary">✓ Trust This Site</button><button id="reload" class="action-btn secondary">🔄 Re-Analyze</button></div>
  `;
  document.getElementById('trust').onclick = async ()=>{ await chrome.runtime.sendMessage({type:'WHITELIST_SITE', url: analysis.url}); window.close(); };
  document.getElementById('reload').onclick = ()=>{ chrome.tabs.reload(tab.id); window.close(); };
});
