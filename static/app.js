/* PhishGuard UI Frontend Scripts */

function showTab(tabName) {
  document.querySelectorAll('.tab-panel').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));

  const targetPanel = document.getElementById('tab-' + tabName);
  if (targetPanel) {
    targetPanel.classList.add('active');
  }
  if (event && event.target) {
    event.target.classList.add('active');
  }
}

function showInvTab(tabName) {
  document.querySelectorAll('.inv-tab-panel').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.inv-tab-btn').forEach(el => el.classList.remove('active'));

  const targetPanel = document.getElementById('inv-tab-' + tabName);
  if (targetPanel) {
    targetPanel.classList.add('active');
  }
  if (event && event.target) {
    event.target.classList.add('active');
  }
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    alert("Copied to clipboard: " + text);
  }).catch(err => {
    console.error("Copy failed: ", err);
  });
}
