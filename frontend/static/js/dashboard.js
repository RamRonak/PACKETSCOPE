// PACKETSCOPE Dashboard Engine & Real-Time Analytics

let isCapturing = false;
let currentSessionId = INITIAL_SESSION_ID;
let pollTimer = null;
let durationTimer = null;
let captureStartTime = null;
let packetIndex = 0;
let packetDataStore = [];

// Chart.js instances
let protocolChartInstance = null;
let timelineChartInstance = null;
let topSrcChartInstance = null;
let topDstChartInstance = null;
let sizeDistChartInstance = null;

document.addEventListener('DOMContentLoaded', () => {
  initCharts();

  if (INITIAL_SESSION_ID) {
    loadHistoricalSession(INITIAL_SESSION_ID);
  } else {
    // Check if sniffer is already capturing
    checkActiveCaptureState();
  }
});

/* Chart.js Initialization */
function initCharts() {
  const chartTextColor = '#94a3b8';
  const chartGridColor = 'rgba(255, 255, 255, 0.05)';

  // 1. Protocol Distribution (Doughnut)
  const ctxProto = document.getElementById('protocolChart').getContext('2d');
  protocolChartInstance = new Chart(ctxProto, {
    type: 'doughnut',
    data: {
      labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'Other'],
      datasets: [{
        data: [0, 0, 0, 0, 0, 0],
        backgroundColor: [
          '#38bdf8', '#c084fc', '#fbbf24', '#2dd4bf', '#34d399', '#94a3b8'
        ],
        borderWidth: 1,
        borderColor: '#0b1120'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: { color: chartTextColor, font: { family: 'JetBrains Mono', size: 11 } }
        }
      },
      cutout: '65%'
    }
  });

  // 2. Timeline (Line)
  const ctxTime = document.getElementById('timelineChart').getContext('2d');
  timelineChartInstance = new Chart(ctxTime, {
    type: 'line',
    data: {
      labels: ['0s'],
      datasets: [{
        label: 'Packets',
        data: [0],
        borderColor: '#00f0ff',
        backgroundColor: 'rgba(0, 240, 255, 0.12)',
        fill: true,
        tension: 0.35,
        pointRadius: 2,
        pointBackgroundColor: '#00f0ff'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: chartGridColor }, ticks: { color: chartTextColor, font: { family: 'JetBrains Mono', size: 10 } } },
        y: { grid: { color: chartGridColor }, ticks: { color: chartTextColor, font: { family: 'JetBrains Mono', size: 10 }, precision: 0 } }
      }
    }
  });

  // 3. Top Source Endpoints (Horizontal Bar)
  const ctxSrc = document.getElementById('topSrcChart').getContext('2d');
  topSrcChartInstance = new Chart(ctxSrc, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Packets',
        data: [],
        backgroundColor: 'rgba(56, 189, 248, 0.75)',
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: chartGridColor }, ticks: { color: chartTextColor, font: { size: 9 }, precision: 0 } },
        y: { grid: { display: false }, ticks: { color: chartTextColor, font: { family: 'JetBrains Mono', size: 9 } } }
      }
    }
  });

  // 4. Top Destination Endpoints (Horizontal Bar)
  const ctxDst = document.getElementById('topDstChart').getContext('2d');
  topDstChartInstance = new Chart(ctxDst, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Packets',
        data: [],
        backgroundColor: 'rgba(168, 85, 247, 0.75)',
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: chartGridColor }, ticks: { color: chartTextColor, font: { size: 9 }, precision: 0 } },
        y: { grid: { display: false }, ticks: { color: chartTextColor, font: { family: 'JetBrains Mono', size: 9 } } }
      }
    }
  });

  // 5. Packet Size Distribution (Bar)
  const ctxSize = document.getElementById('sizeDistChart').getContext('2d');
  sizeDistChartInstance = new Chart(ctxSize, {
    type: 'bar',
    data: {
      labels: ['<64B', '64-128B', '129-512B', '513-1024B', '1025-1518B', '>1518B'],
      datasets: [{
        label: 'Count',
        data: [0, 0, 0, 0, 0, 0],
        backgroundColor: 'rgba(16, 185, 129, 0.75)',
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { color: chartTextColor, font: { family: 'JetBrains Mono', size: 9 } } },
        y: { grid: { color: chartGridColor }, ticks: { color: chartTextColor, font: { size: 9 }, precision: 0 } }
      }
    }
  });
}

/* Check active capture state */
async function checkActiveCaptureState() {
  try {
    const res = await fetch('/api/capture/status');
    const data = await res.json();
    if (data.is_running) {
      currentSessionId = data.session_id;
      setCaptureUIState(true);
      startLivePolling();
    }
  } catch (err) {
    console.error(err);
  }
}

/* Start Live Capture */
async function startCapture() {
  const iface = document.getElementById('interfaceSelect').value;
  const filter = document.getElementById('filterSelect').value;
  const label = document.getElementById('sessionNameInput').value;

  try {
    const res = await fetch('/api/capture/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: iface, filter: filter, session_name: label })
    });
    const data = await res.json();
    if (data.success) {
      currentSessionId = data.session_id;
      packetIndex = 0;
      packetDataStore = [];
      document.getElementById('packetTableBody').innerHTML = '';
      setCaptureUIState(true);
      showAlert(`Live capture initiated on interface ${iface} [${data.mode}]`, 'success');
      startLivePolling();
    } else {
      showAlert(`Capture start failed: ${data.message || data.error}`, 'error');
    }
  } catch (err) {
    showAlert('Error communicating with backend capture service', 'error');
  }
}

/* Stop Live Capture */
async function stopCapture() {
  try {
    const res = await fetch('/api/capture/stop', { method: 'POST' });
    const data = await res.json();
    setCaptureUIState(false);
    stopLivePolling();
    showAlert(`Capture stopped. Saved ${data.packet_count} packets to session #${data.session_id}`, 'info');
  } catch (err) {
    showAlert('Failed to cleanly stop capture', 'error');
  }
}

/* UI State Toggle */
function setCaptureUIState(running) {
  isCapturing = running;
  document.getElementById('startBtn').disabled = running;
  document.getElementById('stopBtn').disabled = !running;
  document.getElementById('interfaceSelect').disabled = running;
  document.getElementById('filterSelect').disabled = running;

  const dot = document.getElementById('dashPulseDot');
  const txt = document.getElementById('dashStatusText');

  if (running) {
    dot.className = 'pulse-dot online';
    txt.className = 'fw-bold font-mono small text-green';
    txt.textContent = 'Status: Live Capturing';
    captureStartTime = Date.now();
    startDurationTimer();
    document.getElementById('btnExportCsv').disabled = false;
    document.getElementById('btnExportPdf').disabled = false;
  } else {
    dot.className = 'pulse-dot offline';
    txt.className = 'fw-bold font-mono small text-muted';
    txt.textContent = 'Status: Stopped';
    stopDurationTimer();
  }
}

function startDurationTimer() {
  stopDurationTimer();
  durationTimer = setInterval(() => {
    if (!captureStartTime) return;
    const diffSec = Math.floor((Date.now() - captureStartTime) / 1000);
    const hrs = String(Math.floor(diffSec / 3600)).padStart(2, '0');
    const mins = String(Math.floor((diffSec % 3600) / 60)).padStart(2, '0');
    const secs = String(diffSec % 60).padStart(2, '0');
    document.getElementById('dashDuration').textContent = `${hrs}:${mins}:${secs}`;
  }, 1000);
}

function stopDurationTimer() {
  if (durationTimer) clearInterval(durationTimer);
}

/* Live Polling Loop */
function startLivePolling() {
  stopLivePolling();
  pollTimer = setInterval(pollLiveData, 800);
}

function stopLivePolling() {
  if (pollTimer) clearInterval(pollTimer);
}

async function pollLiveData() {
  try {
    const res = await fetch(`/api/capture/live?since=${packetIndex}`);
    const data = await res.json();

    if (!data.status.is_running && isCapturing) {
      setCaptureUIState(false);
      stopLivePolling();
    }

    if (data.packets && data.packets.length > 0) {
      packetIndex = data.next_index;
      packetDataStore.push(...data.packets);
      appendPacketsToTable(data.packets);
    }

    if (data.statistics) {
      updateDashboardStats(data.statistics);
    }
  } catch (err) {
    console.error('Error polling live data:', err);
  }
}

/* Load Historical Session */
async function loadHistoricalSession(sessionId) {
  try {
    const res = await fetch(`/api/sessions/${sessionId}`);
    const resData = await res.json();
    if (!resData.success) {
      showAlert('Session not found', 'error');
      return;
    }

    const { session, statistics, packets } = resData.data;
    currentSessionId = sessionId;
    packetDataStore = packets;

    document.getElementById('sessionNameInput').value = session.name;
    document.getElementById('dashStatusText').textContent = `Loaded Session #${sessionId} (${session.status})`;
    document.getElementById('dashDuration').textContent = `${statistics.duration_seconds}s`;
    document.getElementById('btnExportCsv').disabled = false;
    document.getElementById('btnExportPdf').disabled = false;

    // Populate Table
    document.getElementById('packetTableBody').innerHTML = '';
    appendPacketsToTable(packets);

    // Update Stats & Charts
    updateDashboardStats(statistics);

    showAlert(`Session #${sessionId} loaded (${statistics.total_packets} packets)`, 'info');
  } catch (err) {
    console.error(err);
  }
}

/* Update Dashboard Stats & Charts */
function updateDashboardStats(stats) {
  document.getElementById('statTotalPackets').textContent = stats.total_packets.toLocaleString();
  document.getElementById('statTotalBytes').textContent = formatBytes(stats.total_bytes);
  document.getElementById('tablePacketCount').textContent = `${stats.total_packets.toLocaleString()} Packets`;
  document.getElementById('dashRate').textContent = `${stats.packet_rate} pkts/s`;

  const counts = stats.protocol_counts || {};
  const tot = stats.total_packets || 1;

  const tcp = counts['TCP'] || 0;
  const udp = counts['UDP'] || 0;
  const icmp = counts['ICMP'] || 0;
  const dns = counts['DNS'] || 0;
  const http = counts['HTTP'] || 0;
  const other = tot - (tcp + udp + icmp + dns + http);

  document.getElementById('statTcp').textContent = tcp.toLocaleString();
  document.getElementById('statTcpPct').textContent = `${((tcp / tot) * 100).toFixed(1)}% of total`;

  document.getElementById('statUdp').textContent = udp.toLocaleString();
  document.getElementById('statUdpPct').textContent = `${((udp / tot) * 100).toFixed(1)}% of total`;

  document.getElementById('statIcmp').textContent = icmp.toLocaleString();
  document.getElementById('statIcmpPct').textContent = `${((icmp / tot) * 100).toFixed(1)}% of total`;

  document.getElementById('statDns').textContent = dns.toLocaleString();
  document.getElementById('statDnsPct').textContent = `${((dns / tot) * 100).toFixed(1)}% of total`;

  document.getElementById('statHttpOther').textContent = `${http} / ${Math.max(0, other)}`;
  document.getElementById('statAvgSize').textContent = `Avg: ${stats.avg_packet_size} B`;

  // Update Protocol Chart
  if (stats.protocol_chart && stats.protocol_chart.labels.length > 0) {
    protocolChartInstance.data.labels = stats.protocol_chart.labels;
    protocolChartInstance.data.datasets[0].data = stats.protocol_chart.data;
    protocolChartInstance.update('none');
  }

  // Update Timeline Chart
  if (stats.timeline_chart && stats.timeline_chart.labels.length > 0) {
    timelineChartInstance.data.labels = stats.timeline_chart.labels;
    timelineChartInstance.data.datasets[0].data = stats.timeline_chart.data;
    timelineChartInstance.update('none');
  }

  // Update Top Sources
  if (stats.top_sources) {
    topSrcChartInstance.data.labels = stats.top_sources.map(s => s.ip);
    topSrcChartInstance.data.datasets[0].data = stats.top_sources.map(s => s.count);
    topSrcChartInstance.update('none');
  }

  // Update Top Destinations
  if (stats.top_destinations) {
    topDstChartInstance.data.labels = stats.top_destinations.map(d => d.ip);
    topDstChartInstance.data.datasets[0].data = stats.top_destinations.map(d => d.count);
    topDstChartInstance.update('none');
  }

  // Update Size Distribution
  if (stats.size_distribution) {
    sizeDistChartInstance.data.labels = stats.size_distribution.labels;
    sizeDistChartInstance.data.datasets[0].data = stats.size_distribution.data;
    sizeDistChartInstance.update('none');
  }
}

/* Append Packets to Stream Table */
function appendPacketsToTable(packets) {
  const tbody = document.getElementById('packetTableBody');
  const autoScroll = document.getElementById('autoScrollCheck').checked;
  const container = document.getElementById('tableContainer');

  const fragment = document.createDocumentFragment();

  packets.forEach(p => {
    const tr = document.createElement('tr');
    tr.id = `pkt-row-${p.packet_number}`;
    tr.onclick = () => showPacketModal(p);

    const proto = p.protocol || 'OTHER';
    let badgeClass = 'badge-other';
    if (proto.includes('TCP')) badgeClass = 'badge-tcp';
    else if (proto.includes('UDP')) badgeClass = 'badge-udp';
    else if (proto.includes('ICMP')) badgeClass = 'badge-icmp';
    else if (proto.includes('DNS')) badgeClass = 'badge-dns';
    else if (proto.includes('HTTP')) badgeClass = 'badge-http';
    else if (proto.includes('ARP')) badgeClass = 'badge-arp';

    const shortTime = (p.formatted_time || '').split(' ')[1] || p.formatted_time || '00:00:00';

    tr.innerHTML = `
      <td class="font-mono text-muted">${p.packet_number}</td>
      <td class="font-mono small text-secondary">${shortTime}</td>
      <td class="font-mono text-cyan">${p.ip_src || 'N/A'}</td>
      <td class="font-mono text-white">${p.ip_dst || 'N/A'}</td>
      <td><span class="badge-proto ${badgeClass}">${proto}</span></td>
      <td class="font-mono small text-muted">${p.src_port || '-'}</td>
      <td class="font-mono small text-muted">${p.dst_port || '-'}</td>
      <td class="font-mono small text-muted">${p.packet_len} B</td>
      <td class="small text-truncate" style="max-width: 280px;" title="${escapeHtml(p.info || '')}">${escapeHtml(p.info || '')}</td>
      <td class="text-end">
        <button class="btn btn-sm btn-cyber-outline py-0 px-2" style="font-size: 0.75rem;" onclick="event.stopPropagation(); showPacketModal(${JSON.stringify(p).replace(/"/g, '&quot;')})">
          Inspect
        </button>
      </td>
    `;
    fragment.appendChild(tr);
  });

  tbody.appendChild(fragment);

  if (autoScroll) {
    container.scrollTop = container.scrollHeight;
  }
}

/* Quick Packet Modal Preview */
function showPacketModal(packet) {
  const modalTitle = document.getElementById('modalTitle');
  const modalBody = document.getElementById('modalBody');
  const modalInspectBtn = document.getElementById('modalInspectBtn');

  modalTitle.textContent = `Packet #${packet.packet_number} - ${packet.protocol} Dissection`;
  modalInspectBtn.href = `/inspector?session_id=${currentSessionId || 1}&packet=${packet.packet_number}`;

  let layersHtml = '';
  if (packet.layer_details) {
    for (const [layerName, fields] of Object.entries(packet.layer_details)) {
      layersHtml += `
        <div class="mb-3">
          <h6 class="text-cyan font-mono border-bottom border-secondary-subtle pb-1 mb-2">
            <i class="bi bi-chevron-right small"></i> ${layerName} Layer
          </h6>
          <div class="row g-2 small font-mono">
            ${Object.entries(fields).map(([k, v]) => `
              <div class="col-sm-6 text-muted">${k}: <span class="text-white">${escapeHtml(String(v))}</span></div>
            `).join('')}
          </div>
        </div>
      `;
    }
  }

  modalBody.innerHTML = `
    <div class="row g-2 mb-3">
      <div class="col-sm-4"><span class="text-muted small">Source:</span> <span class="font-mono text-cyan">${packet.ip_src}:${packet.src_port || ''}</span></div>
      <div class="col-sm-4"><span class="text-muted small">Destination:</span> <span class="font-mono text-white">${packet.ip_dst}:${packet.dst_port || ''}</span></div>
      <div class="col-sm-4"><span class="text-muted small">Length:</span> <span class="font-mono text-amber">${packet.packet_len} Bytes</span></div>
    </div>
    
    ${layersHtml}

    ${packet.hex_dump ? `
      <div class="mt-3">
        <h6 class="text-cyan font-mono mb-2"><i class="bi bi-binary"></i> Safe Hexadecimal & ASCII Dump</h6>
        <div class="hex-dump-container">${escapeHtml(packet.hex_dump)}</div>
      </div>
    ` : ''}
  `;

  const modal = new bootstrap.Modal(document.getElementById('packetDetailModal'));
  modal.show();
}

function filterLiveTable() {
  const query = document.getElementById('searchTableInput').value.toLowerCase();
  const rows = document.querySelectorAll('#packetTableBody tr');
  rows.forEach(r => {
    const text = r.textContent.toLowerCase();
    r.style.display = text.includes(query) ? '' : 'none';
  });
}

function exportCurrentSession(type) {
  if (!currentSessionId) {
    showAlert('No active or loaded session to export', 'error');
    return;
  }
  window.location.href = `/api/export/${type}/${currentSessionId}`;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
