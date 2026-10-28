'use strict';
/* Análise Estatística – BR (PWA). Mesmo formato de dados do app Windows:
   'AEBR1' | u32 LE tamanho cabeçalho | cabeçalho JSON {expiry} | salt(16) | nonce(12) | AES-256-GCM(zlib(JSON))
   chave = PBKDF2-SHA256(senha, salt, 300000); AAD = 'AEBR1' + cabeçalho. */
const KDF_ITER = 300000, MAX_TRIES = 5, LOCK_MIN = 15, MAX_OFFLINE_DAYS = 7;
const $ = id => document.getElementById(id);
const enc = new TextEncoder(), dec = new TextDecoder();
const COLS = ['Q10', 'Q15', 'Q20', 'Q30', 'Q40', 'Q50', 'Média', 'Ocorrências'];
const REG = { BR: ['Brasil', 'var(--br)'], RJ: ['RJ', 'var(--rj)'], SP: ['SP', 'var(--sp)'], SC: ['SC', 'var(--sc)'], PR: ['PR', 'var(--pr)'] };
const ROWS = [...['2023', '2024', '2025', '2026'].map(y => ['BR', y]),
  ...['RJ', 'SP', 'SC', 'PR'].flatMap(u => ['2024', '2025', '2026'].map(y => [u, y]))];
let DB = null, KEY = null, EXPIRY = null, IDX = null;

// ---------------------------------------------------------------- utilidades
const money = v => v == null ? 'ND' : 'US$ ' + v.toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const fmtNcm = n => { const s = String(n).padStart(8, '0'); return `${s.slice(0, 4)}.${s.slice(4, 6)}.${s.slice(6)}`; };
const strip = s => (s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const iso = d => d.toISOString().slice(0, 10);
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
function store(k, v) { try { v === null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch (e) { } }
function load(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }

// ---------------------------------------------------------------- dados
async function fetchBlob() {
  const r = await fetch('dados.bin', { cache: 'no-cache' });
  if (!r.ok) throw new Error('dados');
  return new Uint8Array(await r.arrayBuffer());
}
function header(b) {
  if (dec.decode(b.slice(0, 5)) !== 'AEBR1') throw new Error('formato');
  const n = new DataView(b.buffer, b.byteOffset + 5, 4).getUint32(0, true);
  return { n, hdr: b.slice(9, 9 + n), meta: JSON.parse(dec.decode(b.slice(9, 9 + n))) };
}
async function unpack(b, pw) {
  const { n, hdr, meta } = header(b); const p = 9 + n;
  const salt = b.slice(p, p + 16), nonce = b.slice(p + 16, p + 28), ct = b.slice(p + 28);
  const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const raw = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: KDF_ITER }, base, 256);
  const aes = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  const aad = new Uint8Array(5 + hdr.length); aad.set(enc.encode('AEBR1')); aad.set(hdr, 5);
  let plain;
  try { plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, aes, ct); }
  catch (e) { throw new Error('senha'); }
  const stream = new Blob([plain]).stream().pipeThrough(new DecompressionStream('deflate'));
  const json = await new Response(stream).text();
  const hmac = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return { data: JSON.parse(json), key: hmac, expiry: meta.expiry };
}

// ---------------------------------------------------------------- validade (mesma regra do app Windows)
async function onlineDate() {
  try {
    const r = await fetch(location.pathname + '?t=' + Date.now(), { method: 'HEAD', cache: 'no-store' });
    const d = r.headers.get('Date'); if (d) return new Date(d);
  } catch (e) { }
  return null;
}
async function sign(body) { return hex(await crypto.subtle.sign('HMAC', KEY, enc.encode(body))); }
async function loadState() {
  const s = load('aebr_estado'); if (!s) return {};
  const i = s.lastIndexOf('|'); const body = s.slice(0, i);
  return (await sign(body)) === s.slice(i + 1) ? JSON.parse(body) : {};
}
async function saveState(st) { const body = JSON.stringify(st); store('aebr_estado', body + '|' + await sign(body)); }
async function checkValidity() {
  const exp = new Date(EXPIRY + 'T23:59:59-03:00');
  const st = await loadState();
  if (st.expired) return 'Licença expirada.';
  const net = await onlineDate(), local = new Date();
  let today;
  if (net) { today = net; st.last_online = iso(net); }
  else {
    if (st.last_seen && local < new Date(new Date(st.last_seen).getTime() - 864e5)) return 'Relógio do aparelho inconsistente. Corrija a data ou conecte-se à internet.';
    if (!st.last_online || (local - new Date(st.last_online)) / 864e5 > MAX_OFFLINE_DAYS) return 'É necessária conexão com a internet para validar a licença.';
    today = local;
  }
  st.last_seen = iso(st.last_seen && new Date(st.last_seen) > today ? new Date(st.last_seen) : today);
  if (today > exp) { st.expired = true; await saveState(st); return 'Licença expirada.'; }
  await saveState(st); return null;
}

// ---------------------------------------------------------------- consultas (mesma lógica do app Windows)
const stats = (src, y, n) => ((DB.stats[src] || {})[y] || {})[String(n)] || null;
const q = (src, y, n, i) => { const v = stats(src, y, n); return v && v[i] != null ? v[i] : null; };
function exists(n) {
  const k = String(n);
  return k in DB.desc || k in DB.aliq || Object.values(DB.stats).some(s => Object.values(s).some(y => k in y));
}
function referencias(n) {
  const src = [['BR', '2024'], ['BR', '2025'], ['BR', '2026'], ['SP', '2024'], ['SP', '2025'], ['SP', '2026']];
  const q30 = src.map(([s, y]) => q(s, y, n, 3)).filter(v => v != null);
  const q15 = src.map(([s, y]) => q(s, y, n, 1)).filter(v => v != null);
  return [(q30.length ? Math.max(...q30) : 0) * 1.01188888888888, (q15.length ? Math.max(...q15) : 0) * 1.05];
}
function evolucao(n, src) {
  const a = q(src, '2024', n, 3), b = q(src, '2026', n, 3);
  if (!a || b == null) return '';
  const r = b / a - 1;
  return (r > 0 ? '+ ' + (Math.round(r * 10000) / 100) : String(Math.round(r * 1000) / 10)).replace('.', ',') + '%';
}
function search(text) {
  const t = strip(text).split(/\s+/).filter(Boolean);
  const dig = text.replace(/\D/g, ''), onlyDig = dig && dig.length === text.replace(/[.\s]/g, '').length;
  const out = [];
  for (const [k, low] of IDX) {
    if ((onlyDig && String(k).padStart(8, '0').startsWith(dig)) || (!onlyDig && t.every(w => low.includes(w)))) {
      out.push(k); if (out.length >= 200) break;
    }
  }
  return out;
}

// ---------------------------------------------------------------- interface
function chart(series) {
  const W = 400, H = 250, L = 42, R = 14, T = 28, B = 40;
  const vals = series.flatMap(s => s.ys).filter(v => v != null);
  if (!vals.length) return '<p class="foot">Sem dados de SP/RJ para esta NCM</p>';
  const top = Math.max(...vals) * 1.2 || 1;
  const x = i => L + (W - L - R) * (i + 0.5) / 3, y = v => T + (H - T - B) * (1 - v / top);
  let g = '';
  for (let k = 0; k <= 4; k++) {
    const yy = T + (H - T - B) * k / 4;
    g += `<line x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}" stroke="var(--line)" ${k < 4 ? 'stroke-dasharray="4 4"' : ''}/>` +
      `<text x="${L - 6}" y="${yy + 4}" font-size="12" fill="var(--muted)" text-anchor="end">${(top * (1 - k / 4)).toFixed(2).replace('.', ',')}</text>`;
  }
  ['2024', '2025', '2026'].forEach((yr, i) => g += `<text x="${x(i)}" y="${H - B + 18}" font-size="13" fill="var(--muted)" text-anchor="middle">${yr}</text>`);
  for (const s of series) {
    const pts = s.ys.map((v, i) => [i, v]).filter(p => p[1] != null);
    if (pts.length > 1) g += `<polyline fill="none" stroke="${s.color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" points="${pts.map(([i, v]) => `${x(i)},${y(v)}`).join(' ')}"/>`;
  }
  for (const s of series) s.ys.forEach((v, i) => {
    if (v == null) return;
    const others = series.filter(o => o !== s).map(o => o.ys[i]).filter(o => o != null);
    const up = !others.length || v >= Math.max(...others);
    const lbl = v.toFixed(2).replace('.', ','), w = lbl.length * 8.5 + 14, yy = y(v) + (up ? -28 : 10);
    g += `<circle cx="${x(i)}" cy="${y(v)}" r="5" fill="${s.color}" stroke="#fff" stroke-width="2"/>` +
      `<rect x="${x(i) - w / 2}" y="${yy}" width="${w}" height="20" rx="10" fill="${s.color}"/>` +
      `<text x="${x(i)}" y="${yy + 14.5}" font-size="13" font-weight="700" fill="#fff" text-anchor="middle">${lbl}</text>`;
  });
  let lx = L;
  for (const s of series) { g += `<circle cx="${lx + 5}" cy="${H - 8}" r="5" fill="${s.color}"/><text x="${lx + 14}" y="${H - 4}" font-size="13" fill="var(--ink)">${s.name}</text>`; lx += 60; }
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Evolução Q30">${g}</svg>`;
}
function consultar() {
  const d = $('ncm').value.replace(/\D/g, '');
  const n = d.length === 8 ? parseInt(d, 10) : null;
  if (n == null || !exists(n)) { alert('NCM não cadastrada ou inexistente.'); return; }
  $('ncm').value = fmtNcm(n); $('results').style.display = 'none'; $('ncm').blur();
  const desc = DB.desc[String(n)];
  if (desc) {
    const lines = desc.split('\n');
    $('desc').innerHTML = lines.slice(0, -1).map(esc).join('<br>') + '<br><b>' + esc(lines[lines.length - 1]) + '</b>';
  } else $('desc').textContent = 'Descrição não encontrada na Tabela NCM (código possivelmente alterado/extinto).';
  const [r1, r2] = referencias(n); $('r1').textContent = money(r1); $('r2').textContent = money(r2);
  const al = DB.aliq[String(n)] || ['ND', 'ND', 'ND', 'ND'];
  $('aliq').innerHTML = ['II', 'IPI', 'PIS', 'COFINS'].map((t, i) =>
    `<div class="chip"><span>${t}</span><strong>${al[i] == null || al[i] === 'ND' ? 'ND' : String(al[i]).replace('.', ',')}</strong></div>`).join('');
  $('tb').innerHTML = ROWS.map(([src, y]) => {
    const v = stats(src, y, n), [nm, col] = REG[src];
    const cells = COLS.map((c, j) => {
      if (!v) return '<td class="nd">—</td>';
      if (v[j] == null) return '<td class="nd">ND</td>';
      return `<td>${j === 7 ? v[j] : money(v[j])}</td>`;
    }).join('');
    return `<tr class="${src === 'BR' && y === '2026' ? 'hl ' : ''}${y === '2026' ? 'y26' : ''}"><td><span class="pill" style="background:${col}">${nm}</span>${y}</td>${cells}</tr>`;
  }).join('');
  for (const s of ['BR', 'SP']) {
    const e = evolucao(n, s), el = $('ev' + s);
    el.textContent = e || '—'; el.style.color = e.startsWith('+') ? 'var(--green)' : (e ? 'var(--red)' : 'var(--muted)');
  }
  $('chart').innerHTML = chart([{ name: 'SP', color: '#1d4ed8', ys: ['2024', '2025', '2026'].map(y => q('SP', y, n, 3)) },
  { name: 'RJ', color: '#0f766e', ys: ['2024', '2025', '2026'].map(y => q('RJ', y, n, 3)) }]);
}
function buscar() {
  const t = $('q').value.trim(), ul = $('results');
  if (t.length < 3) { ul.style.display = 'none'; return; }
  const ks = search(t);
  ul.innerHTML = ks.map(k => `<li data-k="${k}"><b>${fmtNcm(k)}</b>${esc((DB.desc[String(k)] || '').split('\n').pop().split(':').slice(1).join(':').trim())}</li>`).join('');
  ul.style.display = ks.length ? 'block' : 'none';
}

// ---------------------------------------------------------------- login
async function entrar() {
  const lock = parseInt(load('aebr_lock') || '0', 10);
  if (Date.now() < lock) { $('msg').textContent = `Muitas tentativas. Aguarde ${Math.ceil((lock - Date.now()) / 60000)} min.`; return; }
  $('busy').classList.remove('hidden');
  try {
    const blob = await fetchBlob();
    const { data, key, expiry } = await unpack(blob, $('pw').value);
    DB = data; KEY = key; EXPIRY = expiry;
    const err = await checkValidity();
    if (err) { DB = null; $('msg').textContent = err; return; }
    store('aebr_tries', null);
    IDX = Object.entries(DB.desc).map(([k, v]) => [parseInt(k, 10), strip(v)]).sort((a, b) => a[0] - b[0]);
    $('fonte').textContent = DB.fonte || '';
    $('login').classList.add('hidden'); $('app').classList.remove('hidden'); $('pw').value = '';
    setInterval(async () => { if (new Date() > new Date(EXPIRY + 'T23:59:59-03:00')) location.reload(); }, 3600e3);
  } catch (e) {
    if (e.message === 'senha') {
      const t = parseInt(load('aebr_tries') || '0', 10) + 1;
      if (t >= MAX_TRIES) { store('aebr_lock', String(Date.now() + LOCK_MIN * 60000)); store('aebr_tries', null); $('msg').textContent = `Senha incorreta. Acesso bloqueado por ${LOCK_MIN} min.`; }
      else { store('aebr_tries', String(t)); $('msg').textContent = `Senha incorreta · ${MAX_TRIES - t} tentativa(s) restante(s)`; }
      $('pw').value = '';
    } else $('msg').textContent = navigator.onLine ? 'Não foi possível abrir os dados.' : 'Sem conexão e sem cópia local dos dados. Conecte-se à internet.';
  } finally { $('busy').classList.add('hidden'); }
}

$('enter').onclick = entrar;
$('pw').addEventListener('keydown', e => { if (e.key === 'Enter') entrar(); });
$('go').onclick = consultar;
$('ncm').addEventListener('keydown', e => { if (e.key === 'Enter') consultar(); });
$('q').addEventListener('input', buscar);
$('results').addEventListener('click', e => { const li = e.target.closest('li'); if (li) { $('ncm').value = fmtNcm(li.dataset.k); $('q').value = ''; consultar(); } });
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => { });
