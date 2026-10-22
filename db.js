/**
 * db.js — SQLite setup, schema, and first-run seed data.
 *
 * Uses better-sqlite3: synchronous calls, which keeps read-modify-write
 * sequences (like "check wallet balance, then debit it") naturally free
 * of race conditions within a single request — Node handles one request's
 * synchronous code to completion before starting the next.
 */

const path = require('path');
const Database = require('better-sqlite3');
const fs = require('fs');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.sqlite');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','vendor')),
  vendor_name TEXT,
  wallet_balance REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS couriers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  zones_json TEXT NOT NULL,
  matrix_json TEXT NOT NULL,
  cities_json TEXT NOT NULL,
  overheads_json TEXT NOT NULL,
  state_zone_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invoices (
  id TEXT PRIMARY KEY,
  invoice_no TEXT NOT NULL,
  type TEXT NOT NULL,
  vendor_id TEXT NOT NULL,
  vendor_name TEXT NOT NULL,
  courier_id TEXT NOT NULL,
  courier_name TEXT NOT NULL,
  date TEXT NOT NULL,
  consignee TEXT,
  source_city TEXT, source_zone TEXT,
  dest_city TEXT, dest_zone TEXT,
  actual_wt REAL,
  dims_json TEXT,
  is_oda INTEGER, is_appointment INTEGER,
  carrier_risk INTEGER, declared_value REAL,
  cod_amount REAL, topay INTEGER,
  breakdown_json TEXT NOT NULL,
  total REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'Paid',
  payment_mode TEXT DEFAULT 'Wallet',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS wallet_tx (
  id TEXT PRIMARY KEY,
  vendor_id TEXT NOT NULL,
  type TEXT NOT NULL,
  amount REAL NOT NULL,
  balance_after REAL NOT NULL,
  note TEXT,
  invoice_id TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recharge_requests (
  id TEXT PRIMARY KEY,
  vendor_id TEXT NOT NULL,
  vendor_name TEXT NOT NULL,
  amount REAL NOT NULL,
  method TEXT,
  ref TEXT,
  note TEXT,
  status TEXT NOT NULL DEFAULT 'Pending',
  requested_at TEXT NOT NULL,
  decided_at TEXT,
  decision_note TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  for_role TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  invoice_id TEXT,
  vendor_id TEXT,
  read INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS razorpay_orders (
  order_id TEXT PRIMARY KEY,
  vendor_id TEXT NOT NULL,
  amount REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'created',
  created_at TEXT NOT NULL
);
`);

// Defensive migration for databases created before state_zone_json existed.
try{
  db.exec("ALTER TABLE couriers ADD COLUMN state_zone_json TEXT NOT NULL DEFAULT '{}'");
}catch(e){ /* column already exists — fine */ }

const DELHIVERY_OVERHEADS = {
  docketCharge:150, fscPercent:20, rovPercent:0.1, rovMin:150,
  volumetricDivisor:4500, handlingPerKg:3, handlingThresholdKg:400, handlingMin:0,
  odaPerKg:4, odaMin:750, demurragePerKg:1, demurrageMin:100, freeStorageDays:4,
  appointmentPerKg:4, appointmentMin:750, minChargeableWt:20, minChargeableAmt:350,
  gstPercent:18, topayChargePerLR:100, cashHandlingPercent:2, cashHandlingMin:300,
  marginPercent:0, marginFlat:0, riskType:'Owner'
};

function uid(prefix){ return prefix + '_' + Math.random().toString(36).slice(2,9) + Date.now().toString(36).slice(-4); }

function seedIfEmpty(){
  const row = db.prepare('SELECT COUNT(*) as n FROM couriers').get();
  if(row.n > 0) return;

  const seedPath = path.join(__dirname, 'seed-data.json');
  const seed = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
  const stateZonesPath = path.join(__dirname, 'state_zones.json');
  const stateZones = JSON.parse(fs.readFileSync(stateZonesPath, 'utf8'));

  const insertCourier = db.prepare(`
    INSERT INTO couriers (id, name, zones_json, matrix_json, cities_json, overheads_json, state_zone_json, created_at)
    VALUES (@id, @name, @zones_json, @matrix_json, @cities_json, @overheads_json, @state_zone_json, @created_at)
  `);

  function courierRow(id, name, cityRows, stateZoneMap){
    const cities = cityRows.map(function(c){ return { city:c[0], state:c[1], pin:c[2], zone:c[3] }; });
    return {
      id: id, name: name,
      zones_json: JSON.stringify(seed.zones),
      matrix_json: JSON.stringify(seed.matrix),
      cities_json: JSON.stringify(cities),
      overheads_json: JSON.stringify(DELHIVERY_OVERHEADS),
      state_zone_json: JSON.stringify(stateZoneMap),
      created_at: new Date().toISOString()
    };
  }

  const tx = db.transaction(function(){
    insertCourier.run(courierRow('c_delhivery', 'Delhivery', seed.delhivery_cities, stateZones.delhivery));
    insertCourier.run(courierRow('c_bci', 'BCI Express', seed.bci_cities, stateZones.bci));
  });
  tx();

  console.log('Seeded default couriers (Delhivery, BCI Express) with the standard 9-zone rate grid and all-India PIN code fallback.');
}

seedIfEmpty();

module.exports = { db, uid };
