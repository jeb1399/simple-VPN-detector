(function () {
  var overlayId = 'vpn-detect-overlay';
  var interval = 30000;
  var countdownId = 'vpn-detect-popup-countdown';
  var timer = null;
  var countdownTimer = null;
  var lastCountdown = 0;

  function fetchIPInfo() {
    return fetch('https://ipapi.co/json/')
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!data) return null;
        return {
          ip: data.ip || '',
          country: data.country_name || '',
          countryCode: data.country || '',
          region: data.region || '',
          city: data.city || '',
          org: data.org || '',
          asn: data.asn || '',
          timezone: data.timezone || '',
          security: data.security || {},
          version: data.version || '',
          postal: data.postal || '',
          latitude: data.latitude || '',
          longitude: data.longitude || ''
        };
      })
      .catch(() => null);
  }

  function getLocaleCountry() {
    try {
      let l = Intl.DateTimeFormat().resolvedOptions().locale,
        m = l.match(/[-_]([A-Z]{2})$/);
      return m ? m[1] : '';
    } catch { return ''; }
  }

  function getTimezone() {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; }
    catch { return ''; }
  }

  function getLanguages() {
    return navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || ''];
  }

  function getWebRTCLocalIPs(cb) {
    var ips = [],
      P = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
    if (!P) { cb([]); return }
    var pc = new P({ iceServers: [] });
    pc.createDataChannel('');
    pc.createOffer().then(function (o) { pc.setLocalDescription(o); }).catch(function () { });
    pc.onicecandidate = function (e) {
      if (!e || !e.candidate) { pc.close(); cb(ips); return }
      var s = e.candidate.candidate,
        m = /([0-9]{1,3}(\.[0-9]{1,3}){3})/.exec(s);
      if (m) { var ip = m[1]; if (ips.indexOf(ip) === -1) ips.push(ip) }
    };
    setTimeout(function () { pc.close(); cb(ips); }, 800);
  }

  function getScreenRes() { return window.screen.width + 'x' + window.screen.height; }

  function getFingerprint() {
    return [
      navigator.userAgent,
      getLanguages().join(','),
      getScreenRes(),
      navigator.platform,
      navigator.hardwareConcurrency || '',
      navigator.deviceMemory || '',
      navigator.vendor || ''
    ].join('||');
  }

  function normalizeCountry(k) {
    if (!k) return '';
    var m = {
      'US': 'United States', 'GB': 'United Kingdom', 'DE': 'Germany', 'FR': 'France', 'CA': 'Canada',
      'AU': 'Australia', 'RU': 'Russia', 'CN': 'China', 'JP': 'Japan', 'IN': 'India', 'BR': 'Brazil',
      'MX': 'Mexico', 'IT': 'Italy', 'ES': 'Spain', 'NL': 'Netherlands'
    };
    return k.length === 2 && m[k.toUpperCase()] ? m[k.toUpperCase()] : k;
  }

  function detectIncognito(cb) {
    var fs = window.RequestFileSystem || window.webkitRequestFileSystem;
    if (!fs) {
      var db;
      try {
        db = window.indexedDB.open('test');
        db.onerror = function () { cb(true); };
        db.onsuccess = function () { cb(false); };
      } catch { cb(false); }
      return;
    }
    fs(window.TEMPORARY, 100, function () { cb(false); }, function () { cb(true); });
  }

  function isTorExit(ip) {
    var torCIDRs = [
      '185.220.100.0/22', '199.249.230.0/23', '51.68.204.0/24', '116.202.120.0/24'
    ];
    function ip2int(ip) {
      return ip.split('.').reduce(function (acc, oct) { return acc * 256 + parseInt(oct, 10); }, 0);
    }
    function inRange(ip, range) {
      var parts = range.split('/');
      var subnet = parts[0], bits = parseInt(parts[1], 10);
      var mask = ~(Math.pow(2, 32 - bits) - 1);
      return (ip2int(ip) & mask) === (ip2int(subnet) & mask);
    }
    try {
      return torCIDRs.some(function (cidr) { return inRange(ip, cidr); });
    } catch { return false; }
  }

  function isDatacenterASN(asn) {
    return /(google|amazon|aws|digitalocean|ovh|microsoft|azure|linode|vultr|datacenter|colo|cloud|hosting)/i.test(asn || '');
  }

  function isDatacenterOrg(org) {
    return /(google|amazon|aws|digitalocean|ovh|microsoft|azure|linode|vultr|datacenter|colo|cloud|hosting)/i.test(org || '');
  }

  function isSuspiciousTimezone(tz) {
    return /(Etc\/UTC|Etc\/GMT|Africa\/Abidjan|Pacific\/Midway|Pacific\/Pago_Pago)/i.test(tz || '');
  }

  function isSuspiciousLanguage(langs) {
    if (!langs || !langs.length) return false;
    return langs.some(function (l) { return /^en-GB|^en-US|^ru|^zh|^ja|^ar/.test(l); }) && langs.length > 3;
  }

  function scoreVPN(dc, dt, dl, df, ip, wi, incog) {
    var sc = 0, rs = [], st = [], ic = normalizeCountry(dc), ipc = ip ? ip.country : '', tz = ip ? ip.timezone : '', cc = ip ? ip.countryCode : '', org = ip ? ip.org : '', asn = ip ? ip.asn : '', sec = ip && ip.security ? ip.security : {}, v = 'VPN not detected', reliable = true;

    if (!ip) { st.push({ l: 'IP Lookup', r: 'fail', d: 'No IP data' }); reliable = false; }
    else { st.push({ l: 'IP Lookup', r: 'pass', d: 'IP data found' }); }

    if (ip && isTorExit(ip.ip)) { sc += 10; rs.push('Tor exit node detected'); st.push({ l: 'Tor Exit', r: 'fail', d: ip.ip }); reliable = false; }
    else { st.push({ l: 'Tor Exit', r: 'pass', d: (ip ? ip.ip : '') }); }

    if (ip && isDatacenterASN(asn)) { sc += 4; rs.push('Datacenter ASN'); st.push({ l: 'ASN', r: 'fail', d: asn }); }
    else if (ip && asn) { st.push({ l: 'ASN', r: 'pass', d: asn }); }

    if (ip && isDatacenterOrg(org)) { sc += 4; rs.push('Datacenter Org'); st.push({ l: 'Org', r: 'fail', d: org }); }
    else if (ip && org) { st.push({ l: 'Org', r: 'pass', d: org }); }

    if (ip && sec && typeof sec.vpn !== 'undefined') {
      if (sec.vpn) { sc += 7; rs.push('VPN IP'); st.push({ l: 'VPN Flag', r: 'fail', d: 'VPN detected' }); }
      else { st.push({ l: 'VPN Flag', r: 'pass', d: 'No VPN' }); }
    } else { st.push({ l: 'VPN Flag', r: 'neutral', d: 'Unknown' }); reliable = false; }

    if (ic) st.push({ l: 'Locale Country', r: 'pass', d: ic }); else st.push({ l: 'Locale Country', r: 'neutral', d: 'None' });
    if (ic && ipc) {
      if (ic.toLowerCase() !== ipc.toLowerCase()) {
        sc += 2; rs.push('Country mismatch'); st.push({ l: 'Country', r: 'fail', d: ic + ' ≠ ' + ipc });
      } else { st.push({ l: 'Country', r: 'pass', d: ic + ' = ' + ipc }); }
    } else { st.push({ l: 'Country', r: 'neutral', d: 'No match' }); }

    if (dt && tz) {
      if (dt !== tz) { sc += 2; rs.push('Timezone mismatch'); st.push({ l: 'Timezone', r: 'fail', d: dt + ' ≠ ' + tz }); }
      else { st.push({ l: 'Timezone', r: 'pass', d: dt + ' = ' + tz }); }
    } else { st.push({ l: 'Timezone', r: 'neutral', d: 'Unknown' }); }

    if (dl.length && cc) {
      var ll = '';
      switch (cc.toUpperCase()) {
        case 'US': case 'GB': ll = 'en'; break;
        case 'FR': ll = 'fr'; break;
        case 'DE': ll = 'de'; break;
        case 'ES': ll = 'es'; break;
        case 'JP': ll = 'ja'; break;
        case 'CN': ll = 'zh'; break;
        case 'RU': ll = 'ru'; break;
        case 'BR': ll = 'pt'; break;
        default: ll = '';
      }
      if (ll && !dl.some(function (l) { return l.toLowerCase().startsWith(ll); })) {
        sc += 1; rs.push('Lang≠Country'); st.push({ l: 'Lang', r: 'fail', d: dl.join(',') + ' ≠ ' + ll });
      } else { st.push({ l: 'Lang', r: 'pass', d: 'OK' }); }
    } else { st.push({ l: 'Lang', r: 'neutral', d: 'Unknown' }); }

    if (isSuspiciousTimezone(tz)) { sc += 1; rs.push('Suspicious TZ'); st.push({ l: 'Suspicious TZ', r: 'fail', d: tz }); }

    if (isSuspiciousLanguage(dl)) { sc += 1; rs.push('Suspicious Langs'); st.push({ l: 'Suspicious Langs', r: 'fail', d: dl.join(',') }); }

    if (wi && wi.length > 0) {
      var leak = wi.some(function (ipx) { return ipx !== (ip.ip || '') && !ipx.startsWith('192.168') && !ipx.startsWith('10.') && !ipx.startsWith('172.'); });
      if (leak) { sc += 2; rs.push('WebRTC leak'); st.push({ l: 'WebRTC', r: 'fail', d: wi.join(',') }); }
      else { st.push({ l: 'WebRTC', r: 'pass', d: 'No leak' }); }
    } else { st.push({ l: 'WebRTC', r: 'neutral', d: 'None' }); }

    var sf = localStorage.getItem('vpn_fp');
    if (sf && sf !== df) { sc += 1; rs.push('Fingerprint change'); st.push({ l: 'Fingerprint', r: 'fail', d: 'Changed' }); }
    else { st.push({ l: 'Fingerprint', r: 'pass', d: 'No change' }); }
    localStorage.setItem('vpn_fp', df);

    if (incog === true) { sc += 1; rs.push('Incognito'); st.push({ l: 'Incognito', r: 'fail', d: 'Incognito mode' }); }
    else if (incog === false) { st.push({ l: 'Incognito', r: 'pass', d: 'Normal' }); }
    else { st.push({ l: 'Incognito', r: 'neutral', d: 'Unknown' }); }

    if (!reliable && sc === 0) { v = 'Unreliable detection'; }
    else if (sc >= 6) { v = 'VPN detected'; }
    else if (sc >= 4) { v = 'VPN likely'; }
    else { v = 'VPN not detected'; }
    return { v: v, sc: sc, rs: rs, st: st, reliable: reliable };
  }

  function showPopup(html, countdown) {
    var o = document.getElementById(overlayId);
    if (!o) {
      o = document.createElement('div');
      o.id = overlayId;
      o.style.position = 'fixed';
      o.style.top = '0';
      o.style.left = '0';
      o.style.width = '100vw';
      o.style.height = '100vh';
      o.style.background = 'rgba(0,0,0,0.65)';
      o.style.zIndex = '999999';
      o.style.display = 'flex';
      o.style.alignItems = 'center';
      o.style.justifyContent = 'center';
      document.body.appendChild(o);
    }
    o.innerHTML = '<div style="background:#fff;border-radius:10px;max-width:420px;width:90%;padding:28px 24px 34px 24px;box-shadow:0 6px 28px rgba(0,0,0,0.22);font-family:sans-serif;color:#222;text-align:left;position:relative;">' +
      html +
      '<div id="' + countdownId + '" style="position:absolute;right:18px;bottom:10px;font-size:1em;color:#666;background:rgba(0,0,0,0.07);padding:4px 12px;border-radius:6px;font-family:monospace;"></div>' +
      '</div>';
    updatePopupCountdown(countdown);
  }

  function updatePopupCountdown(seconds) {
    var el = document.getElementById(countdownId);
    if (!el) return;
    el.textContent = 'Next check in ' + seconds + 's';
  }

  function removePopup() {
    var o = document.getElementById(overlayId);
    if (o) o.parentNode.removeChild(o);
  }

  function defaultPopup() {
    return (
      '<h1 style="margin:0 0 8px 0;font-size:2em;color:#c00;">VPN or Proxy Detected</h1>' +
      '<p style="font-size:1.1em;">Your connection appears to be using a VPN or proxy service. To protect your account and our community, we do not allow VPN/proxy access.</p>' +
      '<h4><b>What do do.</b></h4>' +
      '<ul style="font-size:1em;margin-bottom:1em;">' +
      '<li>Please disable your VPN/proxy and reload the page.</li>' +
      '<li>If you believe this is a mistake, please contact support for help.</li>' +
      '</ul>' +
      '<h4><b>Why we check?</b></h4>' +
      '<ul style="font-size:1em;margin-bottom:1em;">' +
      '<li>Accessing from a blocked region may violate local laws and site rules.</li>' +
      '</ul>' +
      '<p style="font-size:0.97em;color:#666;">Site owners: customize this message by setting <b>window.vpndetector.changePopup.innerHTML</b> before this script loads.</p>' +
      '<h6 style="margin-top:1.2em;font-size:0.88em;"><a href="https://github.com/jeb1399/simple-VPN-detector/" target="_blank" style="color:#0077cc;">VPN Detector</a> | <a href="https://github.com/jeb1399/simple-VPN-detector/blob/main/README.md" style="color:#0077cc;">Instructions</a></h6>'
    );
  }

  function render(r, countdown) {
    if ((r.v === 'VPN detected' || r.v === 'VPN likely' || r.v === 'Unreliable detection')) {
      console.log('%c[VPN DETECTOR] ' + r.v + ':', 'color:#c00;font-weight:bold', r);
      if (window.vpndetector && window.vpndetector.changePopup && window.vpndetector.changePopup.innerHTML) {
        showPopup(window.vpndetector.changePopup.innerHTML, countdown);
      } else {
        showPopup(defaultPopup(), countdown);
      }
    } else {
      removePopup();
      console.log('%c[VPN DETECTOR] No VPN detected.', 'color:#090;font-weight:bold');
    }
  }

  window.vpndetector = window.vpndetector || {};
  window.vpndetector.changePopup = window.vpndetector.changePopup || { innerHTML: '' };

  function run(countdown) {
    var dc = getLocaleCountry(), dt = getTimezone(), dl = getLanguages(), df = getFingerprint();
    detectIncognito(function (incog) {
      fetchIPInfo().then(function (ip) {
        getWebRTCLocalIPs(function (wi) {
          var r = scoreVPN(dc, dt, dl, df, ip, wi, incog);
          render(r, countdown);
        });
      });
    });
  }

  function startCountdown() {
    var remaining = interval / 1000;
    if (countdownTimer) clearInterval(countdownTimer);
    function tick() {
      if (document.getElementById(countdownId)) updatePopupCountdown(remaining);
      remaining--;
      if (remaining < 0) {
        clearInterval(countdownTimer);
      }
    }
    tick();
    countdownTimer = setInterval(tick, 1000);
  }

  function mainLoop() {
    run(interval / 1000);
    startCountdown();
    timer = setInterval(function () {
      run(interval / 1000);
      startCountdown();
    }, interval);
  }

  mainLoop();
})();
