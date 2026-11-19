// PacketScope Global JavaScript Utilities

document.addEventListener('DOMContentLoaded', () => {
  // Initialize tooltips
  const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
  tooltipTriggerList.map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

  // Poll global capture status for navbar pill
  checkGlobalCaptureStatus();
  setInterval(checkGlobalCaptureStatus, 3000);
});

async function checkGlobalCaptureStatus() {
  try {
    const res = await fetch('/api/capture/status');
    const data = await res.json();
    
    const dot = document.getElementById('navPulseDot');
    const text = document.getElementById('navStatusText');
    
    if (!dot || !text) return;

    if (data.is_running) {
      dot.className = 'pulse-dot online';
      text.className = 'font-mono text-green';
      text.textContent = `Capturing (${data.packet_count} pkts)`;
    } else {
      dot.className = 'pulse-dot offline';
      text.className = 'font-mono text-muted';
      text.textContent = 'Engine: Idle';
    }
  } catch (err) {
    // Silent fail if server unreachable
  }
}

function showAlert(message, type = 'info') {
  const container = document.getElementById('alertContainer');
  if (!container) return;

  const alertDiv = document.createElement('div');
  const alertClass = type === 'error' ? 'alert-danger' : (type === 'success' ? 'alert-success' : 'alert-info');
  const icon = type === 'error' ? 'bi-exclamation-octagon-fill' : (type === 'success' ? 'bi-check-circle-fill' : 'bi-info-circle-fill');

  alertDiv.className = `alert ${alertClass} alert-dismissible fade show border-0 shadow d-flex align-items-center gap-2`;
  alertDiv.innerHTML = `
    <i class="bi ${icon} fs-5"></i>
    <div class="flex-grow-1">${message}</div>
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
  `;

  container.innerHTML = '';
  container.appendChild(alertDiv);
  container.style.display = 'block';

  setTimeout(() => {
    alertDiv.classList.remove('show');
    setTimeout(() => { container.style.display = 'none'; }, 300);
  }, 5000);
}

function formatBytes(bytes, decimals = 2) {
  if (!+bytes) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function copyToClipboard(text, btnElement) {
  navigator.clipboard.writeText(text).then(() => {
    if (btnElement) {
      const original = btnElement.innerHTML;
      btnElement.innerHTML = '<i class="bi bi-check2"></i> Copied!';
      btnElement.classList.add('btn-success');
      setTimeout(() => {
        btnElement.innerHTML = original;
        btnElement.classList.remove('btn-success');
      }, 1500);
    }
  }).catch(err => {
    console.error('Failed to copy', err);
  });
}
