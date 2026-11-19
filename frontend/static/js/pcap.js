// PACKETSCOPE PCAP Upload & Processing Handler

document.addEventListener('DOMContentLoaded', () => {
  const dropZone = document.getElementById('dropZone');
  if (!dropZone) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('dragover');
    }, false);
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    handleFileSelect(files);
  });
});

function handleFileSelect(files) {
  if (!files || files.length === 0) return;
  const file = files[0];

  const ext = file.name.split('.').pop().toLowerCase();
  if (!['pcap', 'pcapng', 'cap'].includes(ext)) {
    showAlert('Invalid file type. Please upload a .pcap, .pcapng, or .cap file.', 'error');
    return;
  }

  if (file.size > 50 * 1024 * 1024) {
    showAlert('File exceeds maximum allowable size of 50MB.', 'error');
    return;
  }

  uploadPcapFile(file);
}

function uploadPcapFile(file) {
  const formData = new FormData();
  formData.append('file', file);

  const progContainer = document.getElementById('uploadProgressContainer');
  const progBar = document.getElementById('uploadProgressBar');
  const progLabel = document.getElementById('uploadPercent');
  const progName = document.getElementById('uploadFileName');

  progContainer.style.display = 'block';
  progName.textContent = `Uploading & parsing: ${file.name}`;
  progBar.style.width = '20%';
  progLabel.textContent = '20%';

  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/pcap/upload', true);

  xhr.upload.onprogress = (e) => {
    if (e.lengthComputable) {
      const pct = Math.round((e.loaded / e.total) * 90);
      progBar.style.width = `${pct}%`;
      progLabel.textContent = `${pct}%`;
    }
  };

  xhr.onload = () => {
    progBar.style.width = '100%';
    progLabel.textContent = '100%';

    try {
      const data = JSON.parse(xhr.responseText);
      if (data.success) {
        showAlert(`Successfully parsed ${data.filename} (${data.total_packets} packets)`, 'success');
        displayPcapResults(data);
      } else {
        showAlert(`Parsing failed: ${data.error}`, 'error');
      }
    } catch (e) {
      showAlert('Error parsing backend response', 'error');
    }
    setTimeout(() => { progContainer.style.display = 'none'; }, 1000);
  };

  xhr.onerror = () => {
    showAlert('Network error while uploading PCAP file', 'error');
    progContainer.style.display = 'none';
  };

  xhr.send(formData);
}

async function loadSample(filename, btn) {
  const original = btn.innerHTML;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Loading...';
  btn.disabled = true;

  try {
    const res = await fetch('/api/pcap/load-sample', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: filename })
    });
    const data = await res.json();
    if (data.success) {
      showAlert(`Loaded sample capture ${filename}`, 'success');
      displayPcapResults(data);
    } else {
      showAlert(`Error: ${data.error}`, 'error');
    }
  } catch (err) {
    showAlert('Error communicating with sample loader', 'error');
  } finally {
    btn.innerHTML = original;
    btn.disabled = false;
  }
}

function displayPcapResults(data) {
  const card = document.getElementById('pcapResultCard');
  card.style.display = 'block';

  document.getElementById('resFilename').textContent = data.filename;
  document.getElementById('resSummaryText').textContent = `Imported to Session #${data.session_id} &bull; ${data.total_packets} packets processed`;

  const stats = data.statistics || {};
  document.getElementById('resTotalPkts').textContent = (stats.total_packets || data.total_packets).toLocaleString();
  document.getElementById('resTotalVolume').textContent = formatBytes(stats.total_bytes || 0);
  document.getElementById('resDuration').textContent = `${stats.duration_seconds || 0.0}s`;
  document.getElementById('resAvgSize').textContent = `${stats.avg_packet_size || 0} B`;

  document.getElementById('btnOpenDashboard').href = `/dashboard?session_id=${data.session_id}`;
  document.getElementById('btnOpenInspector').href = `/inspector?session_id=${data.session_id}`;

  const tbody = document.getElementById('resPacketPreviewBody');
  tbody.innerHTML = '';

  const pkts = data.packets_preview || [];
  pkts.slice(0, 10).forEach(p => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="text-muted font-mono">${p.packet_number}</td>
      <td class="text-cyan font-mono">${p.ip_src || 'N/A'}</td>
      <td class="text-white font-mono">${p.ip_dst || 'N/A'}</td>
      <td><span class="badge-proto badge-${(p.protocol || 'other').toLowerCase()}">${p.protocol}</span></td>
      <td class="text-muted font-mono">${p.packet_len} B</td>
      <td class="text-truncate text-secondary" style="max-width: 250px;">${escapeHtml(p.info || '')}</td>
    `;
    tbody.appendChild(tr);
  });

  // Smooth scroll down to results
  card.scrollIntoView({ behavior: 'smooth' });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
