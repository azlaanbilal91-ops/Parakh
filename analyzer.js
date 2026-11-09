'use strict';

// Scoring logic. Takes the parsed link plus whatever the network lookups found (ext)
// and returns the JSON the frontend renders. No network access in this file.

const BRANDS = {
  paypal: ['paypal.com'], google: ['google.com', 'google.com.pk'], facebook: ['facebook.com', 'fb.com'],
  instagram: ['instagram.com'], whatsapp: ['whatsapp.com', 'whatsapp.net'], amazon: ['amazon.com'],
  apple: ['apple.com', 'icloud.com'], microsoft: ['microsoft.com', 'live.com', 'office.com'],
  netflix: ['netflix.com'], binance: ['binance.com'], easypaisa: ['easypaisa.com.pk'],
  jazzcash: ['jazzcash.com.pk'], hbl: ['hbl.com'], meezan: ['meezanbank.com'], ubl: ['ubldigital.com', 'ubl.com.pk'],
  daraz: ['daraz.pk'], nadra: ['nadra.gov.pk'], fbr: ['fbr.gov.pk'], sadapay: ['sadapay.pk'],
  nayapay: ['nayapay.com'], alfalah: ['bankalfalah.com'], telenor: ['telenor.com.pk']
};
const RISKY_TLD = ['xyz', 'top', 'click', 'buzz', 'icu', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'loan', 'cam', 'rest', 'monster', 'support', 'zip', 'mov', 'cyou', 'sbs'];
const KEYWORDS = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'wallet', 'claim', 'prize', 'bonus', 'giveaway', 'free', 'gift', 'support', 'confirm', 'offer', 'reward', 'recover', 'unlock', 'billing', 'payment'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'rb.gy', 'is.gd', 'shorturl.at', 'goo.gl', 'ow.ly'];
const SLD = ['com', 'co', 'org', 'net', 'gov', 'edu', 'ac'];
const THREAT_NAMES = {
  SOCIAL_ENGINEERING: 'dhoka (phishing)',
  MALWARE: 'malware',
  UNWANTED_SOFTWARE: 'nuqsan dene wala software',
  POTENTIALLY_HARMFUL_APPLICATION: 'nuqsan dene wali app'
};

function regDomain(host) {
  const l = host.split('.');
  if (l.length <= 2) return host;
  const tld = l[l.length - 1];
  const sld = l[l.length - 2];
  if (tld.length === 2 && SLD.indexOf(sld) > -1) return l.slice(-3).join('.');
  return l.slice(-2).join('.');
}

function parseInput(raw) {
  const s = String(raw || '').trim();
  if (!s || s.length > 2048) return null;
  const hadScheme = /^[a-z][a-z0-9+.\-]*:\/\//i.test(s);
  let u;
  try { u = new URL(hadScheme ? s : 'https://' + s); } catch (e) { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.charAt(0) === '[';
  if (!isIP && host.indexOf('.') < 0) return null;
  return { raw: s, u: u, host: host, hadScheme: hadScheme, isIP: isIP };
}

function analyze(p, ext) {
  ext = ext || {};
  const host = p.host;
  const u = p.u;
  const reg = p.isIP ? host : regDomain(host);
  const sub = p.isIP ? '' : host.slice(0, host.length - reg.length);
  const subLabels = sub ? sub.replace(/\.$/, '').split('.').length : 0;
  const tld = host.split('.').pop();
  const tokens = host.split(/[.\-]/);
  const checks = [];
  let penalty = 0;
  let forceBad = false;
  const add = function (title, status, detail, pen) {
    checks.push({ title: title, status: status, detail: detail });
    if (pen) penalty += pen;
  };

  // Brand match (computed first, other checks depend on it)
  let legit = null;
  let fake = null;
  let b;
  for (b in BRANDS) {
    if (BRANDS[b].indexOf(reg) > -1) { legit = b; break; }
  }
  if (!legit && !p.isIP) {
    outer:
    for (b in BRANDS) {
      for (let i = 0; i < tokens.length; i++) {
        if (tokens[i] === b || (b.length >= 5 && tokens[i].indexOf(b) > -1)) { fake = b; break outer; }
      }
    }
  }

  // 1. Khatarnak sites ki list (Google Safe Browsing, URLhaus)
  const rep = ext.reputation || { checked: [], threats: [] };
  if (rep.threats.length) {
    const names = rep.threats.map(function (t) { return THREAT_NAMES[t] || t; });
    add('Khatarnak sites ki list', 'bad', 'Yeh site ' + names.join(', ') + ' ki wajah se list mein darj hai (' + rep.checked.join(', ') + ').', 100);
    forceBad = true;
  } else if (rep.checked.length) {
    add('Khatarnak sites ki list', 'ok', 'Dekhi gayi: ' + rep.checked.join(', ') + '. Koi khatarnak entry nahi mili. Naye jaali pages shamil hone mein waqt lagta hai.', 0);
  } else {
    add('Khatarnak sites ki list', 'na', 'Is server par yeh check band hai (API key nahi lagi), is liye score ki hadd kam rakhi gayi hai.', 0);
  }

  // 2. Domain ki umar (RDAP)
  const ageKnown = !!(ext.age && typeof ext.age.days === 'number');
  if (ageKnown) {
    const d = ext.age.days;
    const when = d < 60 ? d + ' din' : d < 730 ? Math.floor(d / 30) + ' mahine' : Math.floor(d / 365) + ' saal';
    if (d < 30) add('Domain ki umar', 'bad', 'Yeh domain sirf ' + when + ' pehle bana hai (' + ext.age.registered + '). Jaali sites aksar bilkul naye domain par hoti hain.', 35);
    else if (d < 180) add('Domain ki umar', 'warn', 'Domain sirf ' + when + ' purana hai (' + ext.age.registered + ').', 20);
    else if (d < 365) add('Domain ki umar', 'warn', 'Domain ' + when + ' purana hai (' + ext.age.registered + '), abhi naya sa hai.', 8);
    else add('Domain ki umar', 'ok', 'Domain ' + when + ' purana hai (' + ext.age.registered + ').', 0);
  } else {
    add('Domain ki umar', 'na', p.isIP ? 'IP address ki umar nahi hoti.' : 'Maloom nahi ho saki. Kuch extensions (jaise .pk) ka registration data public nahi hota.', 0);
  }

  // 3. DNS
  if (ext.dns) {
    if (!ext.dns.resolves && ext.dns.definitive) add('Server maujood hai', 'bad', 'Is naam ka koi server nahi mila. Site band ho chuki hai ya naam ghalat hai.', 20);
    else if (ext.dns.resolves && ext.dns.private) add('Server maujood hai', 'bad', 'Yeh naam kisi private network ke pate ki taraf jata hai, asli website ki taraf nahi.', 30);
    else if (ext.dns.resolves) add('Server maujood hai', 'ok', 'Naam ek asli server se juda hai.', 0);
  }

  // 4. SSL certificate
  if (ext.ssl) {
    if (ext.ssl.connected && ext.ssl.ok) {
      add('SSL certificate', 'ok', 'Certificate sahi hai' + (ext.ssl.issuer ? ' (' + ext.ssl.issuer + ')' : '') + ', ' + ext.ssl.daysLeft + ' din baqi.', 0);
      if (typeof ext.ssl.ageDays === 'number' && ext.ssl.ageDays < 14) {
        add('Certificate naya hai', 'warn', 'Certificate sirf ' + ext.ssl.ageDays + ' din pehle bana hai.', 5);
      }
    } else if (ext.ssl.connected) {
      add('SSL certificate', 'bad', 'Certificate mein masla hai (' + (ext.ssl.error || 'na-maloom') + '). Browser is par warning dega.', 25);
    } else {
      add('SSL certificate', 'warn', 'Port 443 par HTTPS jawab nahi mila.', 10);
    }
  }

  // 5. Link http ya https
  if (!p.hadScheme) add('Link ka protocol', 'na', 'Aap ne http ya https nahi likha, is liye yeh check chhor diya gaya.', 0);
  else if (u.protocol === 'https:') add('Link ka protocol', 'ok', 'Link HTTPS use karta hai. Yeh akela kaafi nahi, jaali sites bhi HTTPS lagati hain.', 0);
  else add('Link ka protocol', 'bad', 'Link sirf http hai. Jo bhi likhein ge woh raaste mein parha ja sakta hai.', 25);

  // 6. Brand ki nakal
  if (legit) add('Mashhoor brand ki nakal', 'ok', 'Yeh ' + legit + ' ka apna domain (' + reg + ') hai.', 0);
  else if (fake) add('Mashhoor brand ki nakal', 'bad', 'Naam mein "' + fake + '" hai, magar domain ' + reg + ' us brand ka nahi. Jaali sites aksar yehi tareeqa use karti hain.', 35);
  else add('Mashhoor brand ki nakal', 'ok', 'Naam kisi jaane pehchane brand ki naqal nahi lagta.', 0);

  // 7. IP
  if (p.isIP) add('Website ka naam', 'bad', 'Link mein naam ki jagah sirf IP address hai. Asli bank ya shop aisa nahi karte.', 30);
  else add('Website ka naam', 'ok', 'Link mein naam likha hua hai, IP number nahi.', 0);

  // 8. Extension
  if (p.isIP) add('Domain ka extension', 'na', 'IP address mein extension nahi hota.', 0);
  else if (RISKY_TLD.indexOf(tld) > -1) add('Domain ka extension (.' + tld + ')', 'warn', 'Yeh extension sasta hai aur jaali sites mein zyada dekha jata hai. Is se akele kuch sabit nahi hota.', 12);
  else add('Domain ka extension (.' + tld + ')', 'ok', 'Yeh aam tor par use hone wala extension hai.', 0);

  // 9. Shak wale alfaaz
  const hits = [];
  if (!legit && !p.isIP) {
    KEYWORDS.forEach(function (k) {
      for (let t = 0; t < tokens.length; t++) {
        if (tokens[t] === k || (k.length >= 5 && tokens[t].indexOf(k) > -1)) { hits.push(k); break; }
      }
    });
  }
  if (hits.length >= 2) add('Shak wale alfaaz', 'bad', 'Naam mein ' + hits.join(', ') + ' jaise alfaaz hain. Yeh log in karwane ya inaam ka lalach dene ke liye lagaye jate hain.', 18);
  else if (hits.length === 1) add('Shak wale alfaaz', 'warn', 'Naam mein "' + hits[0] + '" hai. Aksar jaali pages yeh lafz lagate hain.', 8);
  else add('Shak wale alfaaz', 'ok', 'Naam mein log in, inaam ya verify jaise alfaaz nahi mile.', 0);

  // 10. Naam ki banawat
  const rl = p.isIP ? '' : reg.split('.')[0];
  const hy = (rl.match(/-/g) || []).length;
  const dg = (rl.match(/\d/g) || []).length;
  if (hy >= 2) add('Naam ki banawat', 'warn', 'Domain mein ' + hy + ' hyphen (-) hain. Asli brands ke naam aam tor par seedhay hotay hain.', 10);
  else if (dg >= 4) add('Naam ki banawat', 'warn', 'Domain mein bohat se number hain, yeh aksar auto-generated sites mein hota hai.', 6);
  else add('Naam ki banawat', p.isIP ? 'na' : 'ok', p.isIP ? 'IP address par lagu nahi.' : 'Naam saaf aur chhota hai.', 0);

  // 11. Subdomains
  if (subLabels >= 4) add('Subdomains', 'bad', 'Naam se pehle ' + subLabels + ' hisse hain. Asli naam aksar in ke peechay chhupaya jata hai.', 15);
  else if (subLabels === 3) add('Subdomains', 'warn', 'Naam se pehle 3 hisse hain, ghaur se parhein ke asli domain kaunsa hai.', 10);
  else add('Subdomains', 'ok', subLabels ? 'Subdomain maujood hai, magar aam hadd mein.' : 'Koi subdomain nahi.', 0);

  // 12. Milte julte huroof
  if (host.indexOf('xn--') > -1) add('Milte julte huroof', 'bad', 'Domain mein khaas (Unicode) huroof hain jo angrezi ke huroof jaise dikhte hain.', 25);
  else add('Milte julte huroof', 'ok', 'Domain mein sirf aam huroof hain.', 0);

  // 13. Link ki shakal
  const problems = [];
  let pen = 0;
  if (SHORTENERS.indexOf(reg) > -1) { problems.push('yeh chhota kiya hua link hai, asli manzil chhupi hui hai'); pen += 15; }
  if (u.username || u.password) { problems.push('link mein @ ya password wala hissa hai jo asli host chhupata hai'); pen += 25; }
  if (u.port && u.port !== '80' && u.port !== '443') { problems.push('ajeeb port (' + u.port + ') istemal hua hai'); pen += 8; }
  if (p.raw.length > 90) { problems.push('link bohat lamba hai'); pen += 6; }
  if (problems.length) {
    const text = problems.join('; ');
    add('Link ki shakal', pen >= 15 ? 'bad' : 'warn', text.charAt(0).toUpperCase() + text.slice(1) + '.', pen);
  } else {
    add('Link ki shakal', 'ok', 'Link chhota aur seedha hai.', 0);
  }

  // Score. Without real data the score is capped, so an unknown site can never look fully safe.
  const coverage = { reputation: rep.checked.length > 0, age: ageKnown, ssl: !!(ext.ssl && ext.ssl.connected) };
  let score = Math.max(0, 100 - penalty);
  let cap = 100;
  if (!legit) {
    if (!coverage.reputation) cap = 70;
    else if (!coverage.age) cap = 85;
  }
  if (score > cap) score = cap;
  if (forceBad) score = Math.min(score, 5);

  const tone = score >= 80 ? 'good' : score >= 50 ? 'warn' : 'bad';
  const flagged = checks.filter(function (c) { return c.status === 'warn' || c.status === 'bad'; }).length;
  let verdict;
  if (forceBad) verdict = 'Khatarnak: dhoke ya malware ki list mein hai';
  else if (tone === 'good') verdict = 'Aam tor par theek lagta hai';
  else if (tone === 'warn' && flagged === 0) verdict = 'Koi nishan nahi mila, magar jaanch mukammal nahi';
  else if (tone === 'warn') verdict = 'Ehtiyat karein';
  else verdict = 'Khatarnak ho sakta hai';

  return { host: host, reg: reg, sub: sub, score: score, tone: tone, verdict: verdict, checks: checks, flagged: flagged, coverage: coverage };
}

module.exports = { parseInput: parseInput, analyze: analyze, regDomain: regDomain };
