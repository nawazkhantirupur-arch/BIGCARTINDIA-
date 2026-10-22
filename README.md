 

Server · JS
/**
 * BCI Express backend — real shared data + auth + wallet + payments.
 *
 * Every vendor and the admin now read/write through this server instead
 * of the browser's own local storage, so everyone sees the same couriers,
 * invoices, and wallet balances no matter which computer they're on.
 *
 * Deploy this once (Render/Railway/Fly.io/a VPS — see README.md), set the
 * environment variables it asks for, then paste its URL into the app.
 */
 
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const Razorpay = require('razorpay');
 
const { db, uid } = require('./db');
const { signToken, hashPassword, checkPassword, requireAuth, requireAdmin } = require('./auth');
const { round2, computeInvoice, sanitizeBreakdownForVendor, sanitizeOverheadsForVendor } = require('./calc');
const { isPincode, stateForPincode } = require('./pincode');
 
const PORT = process.env.PORT || 3000;
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(function(s){ return s.trim(); }).filter(Boolean);
 
const razorpay = (RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET)
  ? new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET })
  : null;
 
const app = express();
app.use(express.json());
app.use(cors({
  origin: function(origin, callback){
    if(!origin || ALLOWED_ORIGINS.length===0 || ALLOWED_ORIGINS.indexOf(origin)!==-1) callback(null, true);
    else callback(new Error('Origin not allowed: ' + origin));
  }
}));
 
// basic per-IP rate limit
const hits = {};
app.use(function(req, res, next){
  const ip = req.ip;
  const now = Date.now();
  hits[ip] = (hits[ip] || []).filter(function(t){ return now - t < 60000; });
  hits[ip].push(now);
  if(hits[ip].length > 120) return res.status(429).json({ error: 'Too many requests, slow down.' });
  next();
});
 
function nowISO(){ return new Date().toISOString(); }
 
function publicUser(row){
  return {
    id: row.id, name: row.name, username: row.username, role: row.role,
    vendorName: row.vendor_name, walletBalance: row.wallet_balance, createdAt: row.created_at
  };
}
function courierRowToObj(row, forVendor){
  const overheads = JSON.parse(row.overheads_json);
  return {
    id: row.id, name: row.name,
    zones: JSON.parse(row.zones_json),
    matrix: JSON.parse(row.matrix_json),
    cities: JSON.parse(row.cities_json),
    stateZoneMap: JSON.parse(row.state_zone_json || '{}'),
    overheads: forVendor ? sanitizeOverheadsForVendor(overheads) : overheads
  };
}
function invoiceRowToObj(row, forVendor){
  const breakdown = JSON.parse(row.breakdown_json);
  return {
    id: row.id, invoiceNo: row.invoice_no, type: row.type,
    vendorId: row.vendor_id, vendorName: row.vendor_name,
    courierId: row.courier_id, courierName: row.courier_name,
    date: row.date, consignee: row.consignee,
    sourceCity: row.source_city, sourceZone: row.source_zone,
    destCity: row.dest_city, destZone: row.dest_zone,
    actualWt: row.actual_wt, dims: JSON.parse(row.dims_json || 'null'),
    isODA: !!row.is_oda, isAppointment: !!row.is_appointment,
    carrierRisk: !!row.carrier_risk, declaredValue: row.declared_value,
    codAmount: row.cod_amount, topay: !!row.topay,
    breakdown: forVendor ? sanitizeBreakdownForVendor(breakdown) : breakdown,
    total: row.total, status: row.status, paymentMode: row.payment_mode
  };
}
function findCityInCourier(courierObj, name){
  if(!name) return null;
  const n = String(name).trim().toLowerCase();
  return courierObj.cities.find(function(c){ return c.city.toLowerCase()===n; }) || null;
}
 
/**
 * Resolves a vendor's typed pickup/destination into a {city, zone} pair.
 * Priority: (1) exact named city in this courier's mapping — the most
 * trustworthy since it was explicitly configured; (2) an exact PIN match
 * already present in that mapping; (3) for any other valid 6-digit PIN,
 * derive the state from well-known postal-circle ranges and look up that
 * courier's state → zone fallback. Returns null if nothing matches.
 */
function resolveLocation(courierObj, raw){
  const trimmed = String(raw||'').trim();
  if(!trimmed) return null;
 
  const cityMatch = findCityInCourier(courierObj, trimmed);
  if(cityMatch) return { city: cityMatch.city, zone: cityMatch.zone, matchType: 'city' };
 
  if(isPincode(trimmed)){
    const pinMatch = courierObj.cities.find(function(c){ return c.pin === trimmed; });
    if(pinMatch) return { city: pinMatch.city, zone: pinMatch.zone, matchType: 'city' };
 
    const state = stateForPincode(trimmed);
    const zone = state ? courierObj.stateZoneMap[state] : null;
    if(state && zone){
      return { city: trimmed + ' (' + state + ')', zone: zone, matchType: 'pincode', state: state };
    }
  }
  return null;
}
 
function addNotification(forRole, title, message, meta){
  db.prepare(`INSERT INTO notifications (id, for_role, title, message, invoice_id, vendor_id, read, created_at)
              VALUES (?,?,?,?,?,?,0,?)`)
    .run(uid('ntf'), forRole, title, message, (meta && meta.invoiceId) || null, (meta && meta.vendorId) || null, nowISO());
}
 
app.get('/health', function(req, res){ res.json({ ok: true }); });
 
/* ============================= AUTH ============================= */
 
app.post('/auth/signup', function(req, res){
  const name = String(req.body.name || '').trim();
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const requestedRole = req.body.role === 'admin' ? 'admin' : 'vendor';
  const vendorName = String(req.body.vendorName || '').trim();
 
  if(!name) return res.status(400).json({ error: 'Enter your full name.' });
  if(!/^[a-z0-9._]{3,24}$/.test(username)) return res.status(400).json({ error: 'Username should be 3-24 characters: letters, numbers, dots.' });
  if(password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
 
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if(existing) return res.status(400).json({ error: 'That username is already taken.' });
 
  const adminExists = db.prepare("SELECT COUNT(*) as n FROM users WHERE role='admin'").get().n > 0;
  let role = requestedRole;
  if(role === 'admin' && adminExists) return res.status(400).json({ error: 'An administrator already exists for this workspace — choose Vendor.' });
  if(role === 'vendor' && !vendorName) return res.status(400).json({ error: 'Enter a company / vendor name.' });
 
  const user = {
    id: uid('u'), name: name, username: username, password_hash: hashPassword(password),
    role: role, vendor_name: role==='vendor' ? vendorName : null, wallet_balance: 0, created_at: nowISO()
  };
  db.prepare(`INSERT INTO users (id, name, username, password_hash, role, vendor_name, wallet_balance, created_at)
              VALUES (@id,@name,@username,@password_hash,@role,@vendor_name,@wallet_balance,@created_at)`).run(user);
 
  const token = signToken(user);
  res.json({ token: token, user: publicUser({ ...user, vendor_name: user.vendor_name }) });
});
 
app.post('/auth/login', function(req, res){
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if(!row || !checkPassword(password, row.password_hash)){
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }
  const token = signToken(row);
  res.json({ token: token, user: publicUser(row) });
});
 
app.get('/auth/me', requireAuth, function(req, res){
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if(!row) return res.status(404).json({ error: 'Account not found.' });
  res.json({ user: publicUser(row) });
});
 
/* ============================= COURIERS ============================= */
 
app.get('/couriers', requireAuth, function(req, res){
  const rows = db.prepare('SELECT * FROM couriers ORDER BY created_at ASC').all();
  const forVendor = req.userRole !== 'admin';
  res.json({ couriers: rows.map(function(r){ return courierRowToObj(r, forVendor); }) });
});
 
app.post('/couriers', requireAuth, requireAdmin, function(req, res){
  const name = String(req.body.name || '').trim();
  if(!name) return res.status(400).json({ error: 'Enter a courier name.' });
  const template = db.prepare('SELECT zones_json, matrix_json, overheads_json, state_zone_json FROM couriers LIMIT 1').get();
  const zones = template ? template.zones_json : '["N1","N2","E","NE","W1","W2","S1","S2","Central"]';
  const matrix = template ? template.matrix_json : '{}';
  const overheads = template ? template.overheads_json : '{}';
  const stateZones = template ? template.state_zone_json : '{}';
  const row = {
    id: uid('c'), name: name, zones_json: zones, matrix_json: matrix,
    cities_json: '[]', overheads_json: overheads, state_zone_json: stateZones, created_at: nowISO()
  };
  db.prepare(`INSERT INTO couriers (id,name,zones_json,matrix_json,cities_json,overheads_json,state_zone_json,created_at)
              VALUES (@id,@name,@zones_json,@matrix_json,@cities_json,@overheads_json,@state_zone_json,@created_at)`).run(row);
  res.json({ courier: courierRowToObj(row, false) });
});
 
app.delete('/couriers/:id', requireAuth, requireAdmin, function(req, res){
  const used = db.prepare('SELECT COUNT(*) as n FROM invoices WHERE courier_id = ?').get(req.params.id).n;
  if(used > 0) return res.status(400).json({ error: 'Cannot remove — invoices reference this courier.' });
  db.prepare('DELETE FROM couriers WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});
 
app.put('/couriers/:id/zones', requireAuth, requireAdmin, function(req, res){
  const zones = req.body.zones;
  const matrix = req.body.matrix;
  if(!Array.isArray(zones) || typeof matrix !== 'object') return res.status(400).json({ error: 'Invalid zone data.' });
  const result = db.prepare('UPDATE couriers SET zones_json = ?, matrix_json = ? WHERE id = ?')
    .run(JSON.stringify(zones), JSON.stringify(matrix), req.params.id);
  if(result.changes === 0) return res.status(404).json({ error: 'Courier not found.' });
  res.json({ ok: true });
});
 
app.put('/couriers/:id/rates', requireAuth, requireAdmin, function(req, res){
  const row = db.prepare('SELECT overheads_json FROM couriers WHERE id = ?').get(req.params.id);
  if(!row) return res.status(404).json({ error: 'Courier not found.' });
  const overheads = Object.assign(JSON.parse(row.overheads_json), req.body.overheads || {});
  db.prepare('UPDATE couriers SET overheads_json = ? WHERE id = ?').run(JSON.stringify(overheads), req.params.id);
  res.json({ ok: true });
});
 
app.put('/couriers/:id/state-zones', requireAuth, requireAdmin, function(req, res){
  const row = db.prepare('SELECT state_zone_json FROM couriers WHERE id = ?').get(req.params.id);
  if(!row) return res.status(404).json({ error: 'Courier not found.' });
  const map = req.body.stateZoneMap;
  if(typeof map !== 'object' || !map) return res.status(400).json({ error: 'Invalid state-zone map.' });
  db.prepare('UPDATE couriers SET state_zone_json = ? WHERE id = ?').run(JSON.stringify(map), req.params.id);
  res.json({ ok: true });
});
 
app.post('/couriers/:id/cities', requireAuth, requireAdmin, function(req, res){
  const row = db.prepare('SELECT cities_json FROM couriers WHERE id = ?').get(req.params.id);
  if(!row) return res.status(404).json({ error: 'Courier not found.' });
  const city = String(req.body.city || '').trim();
  if(!city) return res.status(400).json({ error: 'Enter a city name.' });
  const cities = JSON.parse(row.cities_json);
  cities.push({ city: city, state: String(req.body.state||'').trim(), pin: String(req.body.pin||'').trim(), zone: req.body.zone });
  db.prepare('UPDATE couriers SET cities_json = ? WHERE id = ?').run(JSON.stringify(cities), req.params.id);
  res.json({ ok: true, cities: cities });
});
 
app.put('/couriers/:id/cities/:idx', requireAuth, requireAdmin, function(req, res){
  const row = db.prepare('SELECT cities_json FROM couriers WHERE id = ?').get(req.params.id);
  if(!row) return res.status(404).json({ error: 'Courier not found.' });
  const cities = JSON.parse(row.cities_json);
  const idx = parseInt(req.params.idx, 10);
  if(!cities[idx]) return res.status(404).json({ error: 'City not found.' });
  if(req.body.zone) cities[idx].zone = req.body.zone;
  db.prepare('UPDATE couriers SET cities_json = ? WHERE id = ?').run(JSON.stringify(cities), req.params.id);
  res.json({ ok: true });
});
 
app.delete('/couriers/:id/cities/:idx', requireAuth, requireAdmin, function(req, res){
  const row = db.prepare('SELECT cities_json FROM couriers WHERE id = ?').get(req.params.id);
  if(!row) return res.status(404).json({ error: 'Courier not found.' });
  const cities = JSON.parse(row.cities_json);
  const idx = parseInt(req.params.idx, 10);
  if(!cities[idx]) return res.status(404).json({ error: 'City not found.' });
  cities.splice(idx, 1);
  db.prepare('UPDATE couriers SET cities_json = ? WHERE id = ?').run(JSON.stringify(cities), req.params.id);
  res.json({ ok: true });
});
 
/* ============================= VENDORS (admin) ============================= */
 
app.post('/vendors/:id/reset-password', requireAuth, requireAdmin, function(req, res){
  const pw = String((req.body && req.body.password) || '');
  if(pw.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const r = db.prepare("UPDATE users SET password_hash=? WHERE id=? AND role='vendor'").run(hashPassword(pw), req.params.id);
  if(!r.changes) return res.status(404).json({ error: 'Vendor not found.' });
  res.json({ ok: true });
});
 
app.get('/vendors', requireAuth, requireAdmin, function(req, res){
  const vendors = db.prepare("SELECT * FROM users WHERE role='vendor' ORDER BY created_at ASC").all();
  const out = vendors.map(function(v){
    const agg = db.prepare('SELECT COUNT(*) as n, COALESCE(SUM(total),0) as total FROM invoices WHERE vendor_id = ?').get(v.id);
    const u = publicUser(v);
    u.invoiceCount = agg.n;
    u.invoiceTotal = agg.total;
    return u;
  });
  res.json({ vendors: out });
});
 
/* ============================= INVOICES ============================= */
 
app.get('/invoices', requireAuth, function(req, res){
  const forVendor = req.userRole !== 'admin';
  let sql = 'SELECT * FROM invoices WHERE 1=1';
  const args = [];
  if(forVendor){ sql += ' AND vendor_id = ?'; args.push(req.userId); }
  else {
    if(req.query.vendorId){ sql += ' AND vendor_id = ?'; args.push(req.query.vendorId); }
    if(req.query.courierId){ sql += ' AND courier_id = ?'; args.push(req.query.courierId); }
    if(req.query.type){ sql += ' AND type = ?'; args.push(req.query.type); }
    if(req.query.status){ sql += ' AND status = ?'; args.push(req.query.status); }
  }
  sql += ' ORDER BY created_at ASC';
  const rows = db.prepare(sql).all(...args);
  res.json({ invoices: rows.map(function(r){ return invoiceRowToObj(r, forVendor); }) });
});
 
app.get('/invoices/:id', requireAuth, function(req, res){
  const row = db.prepare('SELECT * FROM invoices WHERE id = ?').get(req.params.id);
  if(!row) return res.status(404).json({ error: 'Invoice not found.' });
  if(req.userRole !== 'admin' && row.vendor_id !== req.userId) return res.status(403).json({ error: 'Not your invoice.' });
  res.json({ invoice: invoiceRowToObj(row, req.userRole !== 'admin') });
});
 
app.post('/invoices/preview', requireAuth, function(req, res){
  if(req.userRole !== 'vendor') return res.status(403).json({ error: 'Vendor accounts only.' });
  const b = req.body;
  const courierRow = db.prepare('SELECT * FROM couriers WHERE id = ?').get(b.courierId);
  if(!courierRow) return res.status(400).json({ error: 'Select a valid courier.' });
  const courier = courierRowToObj(courierRow, false);
 
  const src = resolveLocation(courier, b.sourceCityName);
  const dst = resolveLocation(courier, b.destCityName);
  if(!src || !dst) return res.status(400).json({ error: 'Pickup and destination must be known cities — check City mapping.' });
  const actualWt = Number(b.actualWt);
  if(!actualWt || actualWt <= 0) return res.status(400).json({ error: 'Enter the shipment weight.' });
 
  const type = b.type === 'B2C' ? 'B2C' : 'B2B';
  const codAmount = type === 'B2C' ? Number(b.codAmount || 0) : 0;
  const topay = type === 'B2C' ? !!b.topay : false;
 
  const calc = computeInvoice(courier, {
    sourceZone: src.zone, destZone: dst.zone, actualWt: actualWt,
    dims: b.dims || null, isODA: !!b.isODA, isAppointment: !!b.isAppointment,
    carrierRisk: !!b.carrierRisk, declaredValue: Number(b.declaredValue || 0),
    codAmount: codAmount, topay: topay
  });
 
  res.json({ sourceZone: src.zone, destZone: dst.zone, sourceMatch: src.matchType, destMatch: dst.matchType, breakdown: sanitizeBreakdownForVendor(calc) });
});
 
app.post('/invoices', requireAuth, function(req, res){
  if(req.userRole !== 'vendor') return res.status(403).json({ error: 'Only vendor accounts can book shipments.' });
  const b = req.body;
  const courierRow = db.prepare('SELECT * FROM couriers WHERE id = ?').get(b.courierId);
  if(!courierRow) return res.status(400).json({ error: 'Select a valid courier.' });
  const courier = courierRowToObj(courierRow, false); // full overheads for authoritative calc
 
  const src = resolveLocation(courier, b.sourceCityName);
  const dst = resolveLocation(courier, b.destCityName);
  if(!src || !dst) return res.status(400).json({ error: 'Pickup and destination must be known cities — check City mapping.' });
  const actualWt = Number(b.actualWt);
  if(!actualWt || actualWt <= 0) return res.status(400).json({ error: 'Enter the shipment weight.' });
 
  const type = b.type === 'B2C' ? 'B2C' : 'B2B';
  const codAmount = type === 'B2C' ? Number(b.codAmount || 0) : 0;
  const topay = type === 'B2C' ? !!b.topay : false;
 
  const calc = computeInvoice(courier, {
    sourceZone: src.zone, destZone: dst.zone, actualWt: actualWt,
    dims: b.dims || null, isODA: !!b.isODA, isAppointment: !!b.isAppointment,
    carrierRisk: !!b.carrierRisk, declaredValue: Number(b.declaredValue || 0),
    codAmount: codAmount, topay: topay
  });
 
  const vendorRow = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if(calc.total > vendorRow.wallet_balance + 0.001){
    return res.status(400).json({
      error: 'Insufficient wallet balance — short by ' + round2(calc.total - vendorRow.wallet_balance) + '.',
      shortfall: round2(calc.total - vendorRow.wallet_balance)
    });
  }
 
  const year = new Date().getFullYear();
  const seq = db.prepare('SELECT COUNT(*) as n FROM invoices').get().n + 1;
  const invoiceNo = (type==='B2B'?'BCI-B2B-':'BCI-B2C-') + year + '-' + String(seq).padStart(5,'0');
  const invId = uid('inv');
  const newBalance = round2(vendorRow.wallet_balance - calc.total);
 
  const tx = db.transaction(function(){
    db.prepare('UPDATE users SET wallet_balance = ? WHERE id = ?').run(newBalance, req.userId);
    db.prepare(`INSERT INTO wallet_tx (id, vendor_id, type, amount, balance_after, note, invoice_id, created_at)
                VALUES (?,?,?,?,?,?,?,?)`)
      .run(uid('wtx'), req.userId, 'debit', -calc.total, newBalance, 'Freight — '+invoiceNo, invId, nowISO());
    db.prepare(`INSERT INTO invoices (id, invoice_no, type, vendor_id, vendor_name, courier_id, courier_name,
                date, consignee, source_city, source_zone, dest_city, dest_zone, actual_wt, dims_json,
                is_oda, is_appointment, carrier_risk, declared_value, cod_amount, topay, breakdown_json,
                total, status, payment_mode, created_at)
                VALUES (@id,@invoice_no,@type,@vendor_id,@vendor_name,@courier_id,@courier_name,@date,
                @consignee,@source_city,@source_zone,@dest_city,@dest_zone,@actual_wt,@dims_json,
                @is_oda,@is_appointment,@carrier_risk,@declared_value,@cod_amount,@topay,@breakdown_json,
                @total,@status,@payment_mode,@created_at)`)
      .run({
        id: invId, invoice_no: invoiceNo, type: type, vendor_id: req.userId, vendor_name: vendorRow.vendor_name || vendorRow.name,
        courier_id: courier.id, courier_name: courier.name, date: nowISO(), consignee: b.consignee || '',
        source_city: src.city, source_zone: src.zone, dest_city: dst.city, dest_zone: dst.zone,
        actual_wt: actualWt, dims_json: JSON.stringify(b.dims || null),
        is_oda: b.isODA?1:0, is_appointment: b.isAppointment?1:0, carrier_risk: b.carrierRisk?1:0,
        declared_value: Number(b.declaredValue||0), cod_amount: codAmount, topay: topay?1:0,
        breakdown_json: JSON.stringify(calc), total: calc.total, status: 'Paid', payment_mode: 'Wallet',
        created_at: nowISO()
      });
    addNotification('admin', 'New shipment booked',
      (vendorRow.vendor_name||vendorRow.name)+' booked '+invoiceNo+' ('+type+', '+src.city+' \u2192 '+dst.city+') \u2014 \u20b9'+calc.total+' billed to wallet',
      { invoiceId: invId, vendorId: req.userId });
  });
  tx();
 
  const savedRow = db.prepare('SELECT * FROM invoices WHERE id = ?').get(invId);
  res.json({ invoice: invoiceRowToObj(savedRow, true), walletBalance: newBalance });
});
 
app.delete('/invoices/:id', requireAuth, requireAdmin, function(req, res){
  const row = db.prepare('SELECT * FROM invoices WHERE id = ?').get(req.params.id);
  if(!row) return res.status(404).json({ error: 'Invoice not found.' });
 
  const tx = db.transaction(function(){
    if(row.payment_mode === 'Wallet'){
      const vendor = db.prepare('SELECT wallet_balance FROM users WHERE id = ?').get(row.vendor_id);
      if(vendor){
        const newBalance = round2(vendor.wallet_balance + row.total);
        db.prepare('UPDATE users SET wallet_balance = ? WHERE id = ?').run(newBalance, row.vendor_id);
        db.prepare(`INSERT INTO wallet_tx (id, vendor_id, type, amount, balance_after, note, invoice_id, created_at)
                    VALUES (?,?,?,?,?,?,?,?)`)
          .run(uid('wtx'), row.vendor_id, 'refund', row.total, newBalance, 'Refund for deleted invoice '+row.invoice_no, row.id, nowISO());
      }
    }
    db.prepare('DELETE FROM invoices WHERE id = ?').run(req.params.id);
  });
  tx();
  res.json({ ok: true });
});
 
/* ============================= WALLET ============================= */
 
app.get('/wallet/me', requireAuth, function(req, res){
  if(req.userRole !== 'vendor') return res.status(403).json({ error: 'Vendor accounts only.' });
  const user = db.prepare('SELECT wallet_balance FROM users WHERE id = ?').get(req.userId);
  const tx = db.prepare('SELECT * FROM wallet_tx WHERE vendor_id = ? ORDER BY created_at ASC').all(req.userId);
  res.json({ balance: user.wallet_balance, transactions: tx.map(walletTxToObj) });
});
 
app.get('/wallet/vendor/:vendorId', requireAuth, requireAdmin, function(req, res){
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.vendorId);
  if(!user) return res.status(404).json({ error: 'Vendor not found.' });
  const tx = db.prepare('SELECT * FROM wallet_tx WHERE vendor_id = ? ORDER BY created_at ASC').all(req.params.vendorId);
  res.json({ vendor: publicUser(user), transactions: tx.map(walletTxToObj) });
});
 
function walletTxToObj(t){
  return { id: t.id, vendorId: t.vendor_id, type: t.type, amount: t.amount, balanceAfter: t.balance_after, note: t.note, invoiceId: t.invoice_id, date: t.created_at };
}
 
app.post('/wallet/adjust', requireAuth, requireAdmin, function(req, res){
  const vendorId = req.body.vendorId;
  const amount = Number(req.body.amount);
  const direction = req.body.direction === 'debit' ? 'debit' : 'credit';
  const note = String(req.body.note || '').trim() || (direction==='credit' ? 'Manual credit by admin' : 'Manual debit by admin');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(vendorId);
  if(!user) return res.status(404).json({ error: 'Vendor not found.' });
  if(!amount || amount <= 0) return res.status(400).json({ error: 'Enter a valid amount.' });
  if(direction === 'debit' && amount > user.wallet_balance + 0.001){
    return res.status(400).json({ error: 'Cannot debit more than the current balance.' });
  }
  const delta = direction === 'credit' ? amount : -amount;
  const newBalance = round2(user.wallet_balance + delta);
  const tx = db.transaction(function(){
    db.prepare('UPDATE users SET wallet_balance = ? WHERE id = ?').run(newBalance, vendorId);
    db.prepare(`INSERT INTO wallet_tx (id, vendor_id, type, amount, balance_after, note, invoice_id, created_at)
                VALUES (?,?,?,?,?,?,NULL,?)`)
      .run(uid('wtx'), vendorId, direction==='credit'?'adjust-credit':'adjust-debit', delta, newBalance, note, nowISO());
  });
  tx();
  res.json({ ok: true, balance: newBalance });
});
 
/* ============================= RECHARGE REQUESTS ============================= */
 
app.post('/recharge-requests', requireAuth, function(req, res){
  if(req.userRole !== 'vendor') return res.status(403).json({ error: 'Vendor accounts only.' });
  const amount = Number(req.body.amount);
  const method = String(req.body.method || 'UPI');
  const ref = String(req.body.ref || '').trim();
  const note = String(req.body.note || '').trim();
  if(!amount || amount <= 0) return res.status(400).json({ error: 'Enter the amount you paid.' });
  if(!ref) return res.status(400).json({ error: 'Enter the payment reference / UTR / transaction ID.' });
 
  const vendor = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  const id = uid('rr');
  db.prepare(`INSERT INTO recharge_requests (id, vendor_id, vendor_name, amount, method, ref, note, status, requested_at)
              VALUES (?,?,?,?,?,?,?, 'Pending', ?)`)
    .run(id, req.userId, vendor.vendor_name || vendor.name, amount, method, ref, note, nowISO());
  addNotification('admin', 'Recharge request submitted',
    (vendor.vendor_name||vendor.name)+' requested a recharge of \u20b9'+amount+' via '+method+' (ref '+ref+')',
    { vendorId: req.userId });
  res.json({ ok: true });
});
 
app.get('/recharge-requests', requireAuth, function(req, res){
  const forVendor = req.userRole !== 'admin';
  const rows = forVendor
    ? db.prepare('SELECT * FROM recharge_requests WHERE vendor_id = ? ORDER BY requested_at ASC').all(req.userId)
    : db.prepare('SELECT * FROM recharge_requests ORDER BY requested_at ASC').all();
  res.json({ requests: rows.map(rrToObj) });
});
 
function rrToObj(r){
  return { id: r.id, vendorId: r.vendor_id, vendorName: r.vendor_name, amount: r.amount, method: r.method, ref: r.ref, note: r.note, status: r.status, requestedAt: r.requested_at, decidedAt: r.decided_at, decisionNote: r.decision_note };
}
 
app.post('/recharge-requests/:id/approve', requireAuth, requireAdmin, function(req, res){
  const r = db.prepare('SELECT * FROM recharge_requests WHERE id = ?').get(req.params.id);
  if(!r || r.status !== 'Pending') return res.status(400).json({ error: 'Request not pending.' });
  const vendor = db.prepare('SELECT wallet_balance FROM users WHERE id = ?').get(r.vendor_id);
  const newBalance = round2(vendor.wallet_balance + r.amount);
  const tx = db.transaction(function(){
    db.prepare('UPDATE users SET wallet_balance = ? WHERE id = ?').run(newBalance, r.vendor_id);
    db.prepare(`INSERT INTO wallet_tx (id, vendor_id, type, amount, balance_after, note, invoice_id, created_at)
                VALUES (?,?,?,?,?,?,NULL,?)`)
      .run(uid('wtx'), r.vendor_id, 'recharge', r.amount, newBalance, 'Approved \u00b7 '+r.method+' ref '+r.ref, nowISO());
    db.prepare("UPDATE recharge_requests SET status='Approved', decided_at=? WHERE id=?").run(nowISO(), r.id);
  });
  tx();
  res.json({ ok: true, balance: newBalance });
});
 
app.post('/recharge-requests/:id/reject', requireAuth, requireAdmin, function(req, res){
  const r = db.prepare('SELECT * FROM recharge_requests WHERE id = ?').get(req.params.id);
  if(!r || r.status !== 'Pending') return res.status(400).json({ error: 'Request not pending.' });
  const reason = String(req.body.reason || 'Could not verify this payment');
  db.prepare("UPDATE recharge_requests SET status='Rejected', decided_at=?, decision_note=? WHERE id=?").run(nowISO(), reason, r.id);
  res.json({ ok: true });
});
 
/* ============================= NOTIFICATIONS (admin) ============================= */
 
app.get('/notifications', requireAuth, requireAdmin, function(req, res){
  const rows = db.prepare("SELECT * FROM notifications WHERE for_role='admin' ORDER BY created_at ASC").all();
  res.json({ notifications: rows.map(function(n){
    return { id:n.id, title:n.title, message:n.message, invoiceId:n.invoice_id, vendorId:n.vendor_id, read: !!n.read, createdAt: n.created_at };
  })});
});
 
app.post('/notifications/:id/read', requireAuth, requireAdmin, function(req, res){
  db.prepare('UPDATE notifications SET read = 1 WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});
 
app.post('/notifications/read-all', requireAuth, requireAdmin, function(req, res){
  db.prepare("UPDATE notifications SET read = 1 WHERE for_role='admin'").run();
  res.json({ ok: true });
});
 
/* ============================= PAYMENTS (Razorpay) ============================= */
 
app.get('/payments/status', requireAuth, function(req, res){
  res.json({ enabled: !!razorpay });
});
 
app.post('/payments/create-order', requireAuth, async function(req, res){
  if(req.userRole !== 'vendor') return res.status(403).json({ error: 'Vendor accounts only.' });
  if(!razorpay) return res.status(500).json({ error: 'Payment gateway is not configured on this server.' });
  try{
    const amount = Number(req.body.amount);
    if(!amount || amount <= 0 || amount > 500000) return res.status(400).json({ error: 'Enter an amount between \u20b91 and \u20b95,00,000.' });
    const order = await razorpay.orders.create({ amount: Math.round(amount*100), currency: 'INR', receipt: 'wallet_'+Date.now() });
    db.prepare('INSERT INTO razorpay_orders (order_id, vendor_id, amount, status, created_at) VALUES (?,?,?,?,?)')
      .run(order.id, req.userId, amount, 'created', nowISO());
    res.json({ orderId: order.id, keyId: RAZORPAY_KEY_ID });
  }catch(err){
    console.error('create-order error:', err);
    res.status(500).json({ error: 'Could not create order.' });
  }
});
 
app.post('/payments/verify-payment', requireAuth, function(req, res){
  if(req.userRole !== 'vendor') return res.status(403).json({ error: 'Vendor accounts only.' });
  const orderId = req.body.razorpay_order_id;
  const paymentId = req.body.razorpay_payment_id;
  const signature = req.body.razorpay_signature;
  if(!orderId || !paymentId || !signature) return res.status(400).json({ valid:false, error: 'Missing verification fields.' });
 
  const orderRow = db.prepare('SELECT * FROM razorpay_orders WHERE order_id = ?').get(orderId);
  if(!orderRow || orderRow.vendor_id !== req.userId) return res.status(403).json({ valid:false, error: 'Order does not belong to this account.' });
  if(orderRow.status === 'verified') return res.status(400).json({ valid:false, error: 'This payment was already credited.' });
 
  const expected = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET).update(orderId+'|'+paymentId).digest('hex');
  if(expected !== signature) return res.json({ valid: false });
 
  const vendor = db.prepare('SELECT wallet_balance FROM users WHERE id = ?').get(req.userId);
  const newBalance = round2(vendor.wallet_balance + orderRow.amount);
  const tx = db.transaction(function(){
    db.prepare('UPDATE users SET wallet_balance = ? WHERE id = ?').run(newBalance, req.userId);
    db.prepare(`INSERT INTO wallet_tx (id, vendor_id, type, amount, balance_after, note, invoice_id, created_at)
                VALUES (?,?,?,?,?,?,NULL,?)`)
      .run(uid('wtx'), req.userId, 'recharge', orderRow.amount, newBalance, 'Razorpay (verified) \u00b7 '+paymentId, nowISO());
    db.prepare("UPDATE razorpay_orders SET status='verified' WHERE order_id=?").run(orderId);
  });
  tx();
  res.json({ valid: true, balance: newBalance });
});
 
// Emergency reset: set RESET_ALL_PASSWORDS_TO (min 6 chars) as an env var, deploy once,
// every account (admin + vendors) gets that password. REMOVE the variable afterwards.
if(process.env.RESET_ALL_PASSWORDS_TO){
  const np = String(process.env.RESET_ALL_PASSWORDS_TO);
  if(np.length >= 6){
    const n = db.prepare('UPDATE users SET password_hash=?').run(hashPassword(np)).changes;
    console.log('RESET_ALL_PASSWORDS_TO applied to ' + n + ' account(s). Remove this env var now.');
  }else console.log('RESET_ALL_PASSWORDS_TO ignored: must be at least 6 characters.');
}
 
app.listen(PORT, function(){
  console.log('BCI Express backend listening on port ' + PORT);
});
 
Claude finished the response
