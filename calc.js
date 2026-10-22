function round2(n){ return Math.round((n + Number.EPSILON) * 100) / 100; }

/**
 * Computes the full freight breakdown for a shipment, including the
 * vendor's hidden margin. This is the ONLY place this math should run —
 * keeping it server-side means a vendor can never see or tamper with it
 * from the browser.
 */
function computeInvoice(courier, p){
  const oh = courier.overheads;
  const matrix = courier.matrix;
  const rate = (matrix[p.sourceZone] && matrix[p.sourceZone][p.destZone] != null)
    ? matrix[p.sourceZone][p.destZone] : null;

  let volWt = 0;
  if(p.dims && p.dims.l && p.dims.w && p.dims.h){
    volWt = (p.dims.l * p.dims.w * p.dims.h) / (oh.volumetricDivisor || 4500);
  }
  const chargeableRaw = Math.max(p.actualWt || 0, volWt);
  const chargeableWt = Math.max(chargeableRaw, oh.minChargeableWt || 0);

  let baseFreight = rate != null ? chargeableWt * rate : 0;
  baseFreight = Math.max(baseFreight, oh.minChargeableAmt || 0);

  const docket = oh.docketCharge || 0;
  const fsc = baseFreight * (oh.fscPercent || 0) / 100;
  const handling = chargeableWt >= (oh.handlingThresholdKg != null ? oh.handlingThresholdKg : Infinity)
    ? Math.max(chargeableWt * (oh.handlingPerKg||0), oh.handlingMin||0) : 0;
  const oda = p.isODA ? Math.max(chargeableWt * (oh.odaPerKg||0), oh.odaMin||0) : 0;
  const appointment = p.isAppointment ? Math.max(chargeableWt * (oh.appointmentPerKg||0), oh.appointmentMin||0) : 0;
  const rov = (p.carrierRisk && p.declaredValue > 0) ? Math.max(p.declaredValue * (oh.rovPercent||0)/100, oh.rovMin||0) : 0;
  const cashHandling = (p.codAmount > 0) ? Math.max(p.codAmount * (oh.cashHandlingPercent||0)/100, oh.cashHandlingMin||0) : 0;
  const topay = p.topay ? (oh.topayChargePerLR||0) : 0;

  const costSubtotal = baseFreight + docket + fsc + handling + oda + appointment + rov + cashHandling + topay;
  const margin = round2(costSubtotal * (oh.marginPercent||0) / 100 + (oh.marginFlat||0));
  const subtotal = costSubtotal + margin;
  const gst = subtotal * (oh.gstPercent||0) / 100;
  const total = round2(subtotal + gst);

  return {
    rate: rate, volWt: volWt, chargeableWt: chargeableWt, baseFreight: round2(baseFreight),
    docket: docket, fsc: round2(fsc), handling: round2(handling), oda: round2(oda),
    appointment: round2(appointment), rov: round2(rov), cashHandling: round2(cashHandling),
    topay: topay, margin: margin, subtotal: round2(subtotal), gst: round2(gst), total: total
  };
}

/**
 * Strips the margin out of a breakdown for vendor eyes — folds it
 * invisibly into baseFreight so the vendor's own numbers still add up,
 * without the word "margin" or its value ever reaching their browser.
 */
function sanitizeBreakdownForVendor(calc){
  const copy = Object.assign({}, calc);
  copy.baseFreight = round2(copy.baseFreight + (copy.margin || 0));
  delete copy.margin;
  return copy;
}

function sanitizeOverheadsForVendor(overheads){
  const copy = Object.assign({}, overheads);
  delete copy.marginPercent;
  delete copy.marginFlat;
  return copy;
}

module.exports = { round2, computeInvoice, sanitizeBreakdownForVendor, sanitizeOverheadsForVendor };
