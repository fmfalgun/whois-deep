(function () {
  var DATA_URL = 'data/index.json';

  function sortAlpha(a, b) {
    return a.domain.localeCompare(b.domain);
  }

  function renderCard(entry) {
    var card = document.createElement('div');
    card.className = 'domain-card';
    card.setAttribute('data-domain', entry.domain);

    // Build RIR badge class — e.g. "rir-ARIN", fallback "rir-UNKNOWN"
    var rir = (entry.rir || 'UNKNOWN').toUpperCase();
    var validRIRs = ['ARIN','RIPE','APNIC','LACNIC','AFRINIC'];
    var ririClass = validRIRs.includes(rir) ? 'rir-' + rir : 'rir-UNKNOWN';

    var asn = entry.asn ? 'AS' + entry.asn : '—';
    var org = entry.org || '—';
    var country = entry.country || '—';
    var netblock = entry.netblock || '—';

    card.innerHTML =
      '<div class="card-header-row">' +
        '<span class="card-domain">' + entry.domain + '</span>' +
        '<span class="card-date">' + (entry.last_refreshed || entry.queried_at || '').slice(0, 10) + '</span>' +
      '</div>' +
      '<div class="card-org">' + org + '</div>' +
      '<div class="card-stats">' +
        '<span class="card-stat">' + asn + '</span>' +
        '<span class="card-stat">' + country + '</span>' +
        '<span class="rir-badge ' + ririClass + '">' + rir + '</span>' +
        '<span class="card-netblock">' + netblock + '</span>' +
      '</div>' +
      '<div class="card-contributor">' +
        '<span class="card-name">' + (entry.display_name || '') + '</span>' +
        '<span>' + (entry.display_loc || '') + '</span>' +
      '</div>';

    card.addEventListener('click', function () {
      window.location.href = 'domain.html?d=' + encodeURIComponent(entry.domain);
    });
    return card;
  }

  function render(domains) {
    var list = document.getElementById('domain-list');
    if (!list) return;
    list.innerHTML = '';
    if (!domains.length) {
      list.innerHTML = '<p class="empty">No results.</p>';
      return;
    }
    domains.forEach(function (entry) {
      list.appendChild(renderCard(entry));
    });
  }

  function applySearch(allDomains) {
    var input = document.getElementById('search-input');
    if (!input) return;
    input.addEventListener('input', function () {
      var q = input.value.trim().toLowerCase();
      var filtered = !q ? allDomains : allDomains.filter(function (e) {
        return e.domain.toLowerCase().includes(q) ||
               (e.org || '').toLowerCase().includes(q) ||
               (e.country || '').toLowerCase().includes(q);
      });
      render(filtered);
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    fetch(DATA_URL)
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (data) {
        var domains = (data.domains || []).slice().sort(sortAlpha);

        // stats line
        var statsEl = document.getElementById('rb-stats');
        if (statsEl) {
          var uniqueASNs = new Set(domains.map(function(d){return d.asn;}).filter(Boolean)).size;
          statsEl.textContent = domains.length + ' domain' + (domains.length !== 1 ? 's' : '') +
            ' · ' + uniqueASNs + ' unique ASN' + (uniqueASNs !== 1 ? 's' : '');
        }

        render(domains);
        applySearch(domains);
      })
      .catch(function (err) {
        var list = document.getElementById('domain-list');
        if (list) list.innerHTML = '<p class="empty">Failed to load data: ' + err.message + '</p>';
      });
  });
})();
