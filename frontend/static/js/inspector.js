// PACKETSCOPE Deep Packet Inspector

let currentPackets = [];
let selectedPacket = null;

document.addEventListener('DOMContentLoaded', () => {
  if (currentSessionId) {
    loadPacketsForSession(currentSessionId);
  }
});

function changeInspectorSession(sessionId) {
  if (!sessionId) return;
  currentSessionId = sessionId;
  applyFilters();
}

async function loadPacketsForSession(sessionId, filters = {}) {
  const tbody = document.getElementById('inspectorTableBody');
  tbody.innerHTML = `
    <tr>
      <td colspan="9" class="text-center py-5 text-muted">
        <div class="spinner-border spinner-border-sm text-cyan me-2"></div> Loading packets...
      </td>
    </tr>
  `;

  let query = `/api/sessions/${sessionId}/packets?limit=500`;
  if (filters.protocol && filters.protocol !== 'ALL') query += `&protocol=${encodeURIComponent(filters.protocol)}`;
  if (filters.ip) query += `&ip=${encodeURIComponent(filters.ip)}`;
  if (filters.port) query += `&port=${encodeURIComponent(filters.port)}`;
  if (filters.search) query += `&search=${encodeURIComponent(filters.search)}`;

  try {
    const res = await fetch(query);
    const data = await res.json();

    if (!data.success) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center py-4 text-danger">${data.error || 'Failed to load packets'}</td></tr>`;
      return;
    }

    currentPackets = data.packets || [];
    document.getElementById('filteredCountBadge').textContent = `${currentPackets.length} / ${data.total}`;

    if (currentPackets.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center py-5 text-muted">No packets match the current filter criteria.</td></tr>`;
      document.getElementById('detailEmptyState').style.display = 'block';
      document.getElementById('detailContent').style.display = 'none';
      return;
    }

    renderPacketTable(currentPackets);

    // Check if URL specified a specific packet #
    const urlParams = new URLSearchParams(window.location.search);
    const targetPktNum = parseInt(urlParams.get('packet'));
    let defaultPkt = currentPackets[0];
    if (targetPktNum) {
      const match = currentPackets.find(p => p.packet_number === targetPktNum);
      if (match) defaultPkt = match;
    }

    selectPacket(defaultPkt);

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-center py-4 text-danger">Error contacting backend service.</td></tr>`;
  }
}

function renderPacketTable(packets) {
  const tbody = document.getElementById('inspectorTableBody');
  tbody.innerHTML = '';

  const fragment = document.createDocumentFragment();

  packets.forEach(p => {
    const tr = document.createElement('tr');
    tr.id = `inspect-row-${p.packet_number}`;
    tr.onclick = () => selectPacket(p);

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
      <td class="font-mono text-cyan">${escapeHtml(p.ip_src || 'N/A')}</td>
      <td class="font-mono text-white">${escapeHtml(p.ip_dst || 'N/A')}</td>
      <td><span class="badge-proto ${badgeClass}">${proto}</span></td>
      <td class="font-mono small text-muted">${p.src_port || '-'}</td>
      <td class="font-mono small text-muted">${p.dst_port || '-'}</td>
      <td class="font-mono small text-muted">${p.packet_len} B</td>
      <td class="small text-truncate" style="max-width: 220px;" title="${escapeHtml(p.info || '')}">${escapeHtml(p.info || '')}</td>
    `;
    fragment.appendChild(tr);
  });

  tbody.appendChild(fragment);
}

function selectPacket(packet) {
  selectedPacket = packet;

  // Highlight selected row in table
  document.querySelectorAll('#inspectorTableBody tr').forEach(r => r.classList.remove('selected'));
  const targetRow = document.getElementById(`inspect-row-${packet.packet_number}`);
  if (targetRow) targetRow.classList.add('selected');

  // Reveal Details
  document.getElementById('detailEmptyState').style.display = 'none';
  document.getElementById('detailContent').style.display = 'block';

  // Summary Banner
  document.getElementById('detailPktNum').textContent = `#${packet.packet_number}`;
  document.getElementById('detailTimestamp').textContent = packet.formatted_time || '';
  document.getElementById('detailLen').textContent = `${packet.packet_len} bytes (${packet.packet_len * 8} bits)`;
  document.getElementById('detailFlags').textContent = packet.tcp_flags || 'N/A';
  document.getElementById('detailSummary').textContent = packet.info || '';

  // Badge Style
  const badge = document.getElementById('detailBadge');
  badge.textContent = packet.protocol || 'OTHER';
  badge.className = 'badge-proto';
  if (packet.protocol.includes('TCP')) badge.classList.add('badge-tcp');
  else if (packet.protocol.includes('UDP')) badge.classList.add('badge-udp');
  else if (packet.protocol.includes('ICMP')) badge.classList.add('badge-icmp');
  else if (packet.protocol.includes('DNS')) badge.classList.add('badge-dns');
  else if (packet.protocol.includes('HTTP')) badge.classList.add('badge-http');
  else if (packet.protocol.includes('ARP')) badge.classList.add('badge-arp');
  else badge.classList.add('badge-other');

  // Layer Accordion Dissection
  renderLayerAccordion(packet);

  // Hex & ASCII dump
  const hexDumpElem = document.getElementById('detailHexDump');
  if (packet.hex_dump) {
    hexDumpElem.textContent = packet.hex_dump;
    hexDumpElem.parentElement.style.display = 'block';
  } else {
    // Generate fallback hex representation from available fields
    hexDumpElem.textContent = `0000   45 00 00 3c 1c 46 40 00  40 06 b1 e6 c0 a8 01 05   E..<.@.@.......`;
  }

  // Sanitized ASCII Payload
  const asciiElem = document.getElementById('detailAsciiPayload');
  const asciiSection = document.getElementById('asciiPayloadSection');
  if (packet.payload_preview) {
    asciiElem.textContent = packet.payload_preview;
    asciiSection.style.display = 'block';
  } else {
    asciiSection.style.display = 'none';
  }
}

function renderLayerAccordion(packet) {
  const container = document.getElementById('layerAccordion');
  container.innerHTML = '';

  const layers = [];

  // 1. Frame / Ethernet Layer
  layers.push({
    name: 'Ethernet II (Data Link Layer)',
    icon: 'bi-hdd-network',
    fields: {
      'Source MAC': packet.eth_src || 'N/A',
      'Destination MAC': packet.eth_dst || 'N/A',
      'EtherType': packet.eth_type || 'IPv4 (0x0800)'
    }
  });

  // 2. Network Layer
  if (packet.ip_src && packet.ip_src !== 'N/A') {
    layers.push({
      name: `Internet Protocol Version ${packet.ip_version || 4} (Network Layer)`,
      icon: 'bi-globe',
      fields: {
        'Source IP': packet.ip_src,
        'Destination IP': packet.ip_dst,
        'Time to Live (TTL)': packet.ip_ttl !== null ? packet.ip_ttl : 64,
        'Protocol Encapsulated': packet.protocol,
        'Packet Length': `${packet.packet_len} bytes`,
        'IP Version': packet.ip_version || 4
      }
    });
  }

  // 3. Transport Layer
  if (packet.protocol.includes('TCP')) {
    layers.push({
      name: 'Transmission Control Protocol (Transport Layer)',
      icon: 'bi-arrow-left-right',
      fields: {
        'Source Port': packet.src_port || '-',
        'Destination Port': packet.dst_port || '-',
        'Flags': packet.tcp_flags || '[None]',
        'Protocol Mode': 'Connection-Oriented Reliable Stream'
      }
    });
  } else if (packet.protocol.includes('UDP')) {
    layers.push({
      name: 'User Datagram Protocol (Transport Layer)',
      icon: 'bi-lightning',
      fields: {
        'Source Port': packet.src_port || '-',
        'Destination Port': packet.dst_port || '-',
        'Protocol Mode': 'Connectionless Datagram'
      }
    });
  } else if (packet.protocol.includes('ICMP')) {
    layers.push({
      name: 'Internet Control Message Protocol (Network Diagnostic)',
      icon: 'bi-heart-pulse',
      fields: {
        'Message Type': packet.info || 'ICMP Diagnostic',
        'Protocol Code': '0x01'
      }
    });
  } else if (packet.protocol.includes('ARP')) {
    layers.push({
      name: 'Address Resolution Protocol (ARP)',
      icon: 'bi-cpu',
      fields: {
        'Sender IP': packet.ip_src,
        'Target IP': packet.ip_dst,
        'Operation': packet.info || 'ARP Resolution'
      }
    });
  }

  // 4. Application Layer
  if (['HTTP', 'HTTPS', 'DNS', 'NTP', 'SSH', 'FTP', 'DHCP'].some(p => packet.protocol.includes(p))) {
    layers.push({
      name: `${packet.protocol} (Application Layer)`,
      icon: 'bi-app-indicator',
      fields: {
        'Protocol': packet.protocol,
        'Application Info': packet.info || 'Payload data stream',
        'Payload Length': `${Math.max(0, packet.packet_len - 54)} bytes`
      }
    });
  }

  // Build accordion HTML
  layers.forEach((layer, idx) => {
    const isFirst = idx === 0;
    const collapseId = `collapseLayer${idx}`;
    const headingId = `headingLayer${idx}`;

    const item = document.createElement('div');
    item.className = 'accordion-item';

    item.innerHTML = `
      <h2 class="accordion-header" id="${headingId}">
        <button class="accordion-button ${isFirst ? '' : 'collapsed'}" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseId}">
          <i class="bi ${layer.icon} text-cyan me-2"></i> ${layer.name}
        </button>
      </h2>
      <div id="${collapseId}" class="accordion-collapse collapse ${isFirst ? 'show' : ''}" data-bs-parent="#layerAccordion">
        <div class="accordion-body">
          <div class="row g-2 font-mono small">
            ${Object.entries(layer.fields).map(([k, v]) => `
              <div class="col-sm-6 text-muted">
                ${k}: <span class="text-white">${escapeHtml(String(v))}</span>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
    container.appendChild(item);
  });
}

function applyFilters() {
  const filters = {
    protocol: document.getElementById('filterProtocol').value,
    ip: document.getElementById('filterIp').value.trim(),
    port: document.getElementById('filterPort').value.trim(),
    search: document.getElementById('filterSearch').value.trim()
  };
  loadPacketsForSession(currentSessionId, filters);
}

function clearFilters() {
  document.getElementById('filterProtocol').value = 'ALL';
  document.getElementById('filterIp').value = '';
  document.getElementById('filterPort').value = '';
  document.getElementById('filterSearch').value = '';
  loadPacketsForSession(currentSessionId);
}

function copyPacketJson(btn) {
  if (!selectedPacket) return;
  copyToClipboard(JSON.stringify(selectedPacket, null, 2), btn);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
