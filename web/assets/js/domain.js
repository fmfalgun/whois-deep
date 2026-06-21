(function () {
  function param(name) {
    return new URLSearchParams(window.location.search).get(name);
  }

  function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val != null ? String(val) : '—';
  }

  function addInfraRow(grid, key, val) {
    if (!grid) return;
    var row = document.createElement('div');
    row.className = 'infra-row';
    var isEmpty = val == null || val === '' || val === 'N/A';
    row.innerHTML =
      '<span class="infra-key">' + key + '</span>' +
      '<span class="infra-val' + (isEmpty ? ' empty' : '') + '">' +
      (isEmpty ? 'n/a' : val) + '</span>';
    grid.appendChild(row);
  }

  function addPivot(list, cmd, comment) {
    if (!list) return;
    var item = document.createElement('div');
    item.className = 'pivot-item';
    item.innerHTML = '<span class="pivot-cmd">' + cmd + '</span>' +
      (comment ? '  <span class="pivot-comment"># ' + comment + '</span>' : '');
    list.appendChild(item);
  }

  document.addEventListener('DOMContentLoaded', function () {
    var domain = param('d');
    if (!domain) {
      window.location.href = 'rir-board.html';
      return;
    }

    fetch('data/domains/' + domain + '.json')
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) {
        // Header
        setText('domain-name-display', d.domain);
        var contribEl = document.getElementById('contributor-meta');
        if (contribEl && d.display_name) {
          contribEl.textContent = d.display_name + (d.display_loc ? ' · ' + d.display_loc : '');
        }

        // Stat badges
        setText('val-ip',      d.resolved_ip || '—');
        var ip = d.ip_whois || {};
        var cidr = ip.cidr || {};
        setText('val-asn',     ip.asn ? 'AS' + ip.asn : '—');
        setText('val-rir',     ip.rir || '—');
        setText('val-country', ip.country || '—');

        // queried-at
        setText('queried-at', (d.queried_at || '').slice(0, 10));

        // IP WHOIS grid
        var ipGrid = document.getElementById('ip-whois-grid');
        if (ip.available) {
          addInfraRow(ipGrid, 'Net Name',     ip.net_name);
          addInfraRow(ipGrid, 'Org',          ip.org_name);
          addInfraRow(ipGrid, 'IP Block',     ip.inetnum);
          addInfraRow(ipGrid, 'CIDR',         cidr.cidr_notation);
          addInfraRow(ipGrid, 'Block Size',   cidr.size ? cidr.size + ' IPs' : null);
          addInfraRow(ipGrid, 'Block Type',   ip.block_context);
          addInfraRow(ipGrid, 'Hosting',      ip.hosting_hint);
          addInfraRow(ipGrid, 'Abuse Email',  ip.abuse_email);
        } else {
          if (ipGrid) ipGrid.innerHTML = '<span class="empty">' + (ip.reason || 'no data') + '</span>';
        }

        // Registrar WHOIS grid
        var regGrid = document.getElementById('registrar-grid');
        var reg = d.registrar_whois || {};
        if (reg.available) {
          addInfraRow(regGrid, 'Server',          reg.server);
          var contacts = reg.contacts || {};
          var registrant = contacts.registrant || {};
          addInfraRow(regGrid, 'Registrant Name', registrant.name);
          addInfraRow(regGrid, 'Registrant Org',  registrant.org);
          addInfraRow(regGrid, 'Registrant Email',registrant.email);
          var billing = contacts.billing || {};
          addInfraRow(regGrid, 'Billing Name',    billing.name);
          addInfraRow(regGrid, 'Billing Email',   billing.email);
          addInfraRow(regGrid, 'Reseller',        reg.reseller);
        } else {
          if (regGrid) regGrid.innerHTML = '<span class="empty">' + (reg.reason || 'no data') + '</span>';
        }

        // Pivots
        var pivotList = document.getElementById('pivot-list');
        var resolvedIP = d.resolved_ip;
        if (resolvedIP) {
          addPivot(pivotList, 'nmap -sV -sC ' + resolvedIP, 'service scan');
          addPivot(pivotList, 'curl -I https://' + d.domain, 'header grab');
        }
        if (ip.asn) {
          addPivot(pivotList, '# https://bgp.he.net/AS' + ip.asn, 'ASN detail');
          addPivot(pivotList, '# Shodan: asn:AS' + ip.asn, 'all hosts in ASN');
        }
        if (cidr.cidr_notation) {
          addPivot(pivotList, 'nmap -sn ' + cidr.cidr_notation, 'ping sweep block');
        }
        if (billing && billing.email) {
          addPivot(pivotList, '# billing email: ' + billing.email, 'not in registry WHOIS');
        }
        if (!pivotList || !pivotList.children.length) {
          if (pivotList) pivotList.innerHTML = '<span class="empty">no pivots available</span>';
        }
      })
      .catch(function (err) {
        var box = document.getElementById('error-box');
        var msg = document.getElementById('error-message');
        if (box) box.style.display = 'block';
        if (msg) msg.textContent = 'Failed to load data for "' + domain + '": ' + err.message;
      });
  });
})();
