/**
 * pincode.js — resolves any 6-digit Indian PIN code to its state/UT using
 * well-known India Post postal-circle prefix ranges.
 *
 * This is a PROVISIONAL, best-effort mapping, not an official live PIN
 * database. It's reliable for the vast majority of India, but a few
 * corridors carved from older states without full PIN renumbering —
 * Uttarakhand/Uttar Pradesh, Jharkhand/Bihar, Chhattisgarh/Madhya Pradesh,
 * Telangana/Andhra Pradesh — have historically interleaved ranges that
 * can't be perfectly separated by prefix alone. The well-documented
 * sub-blocks are carved out below where known.
 *
 * For anything business-critical, add the exact city + PIN + zone under
 * that courier's City Mapping — an exact match there always wins over
 * this fallback.
 */

const PIN_RANGES = [[110,110,"Delhi"],[121,136,"Haryana"],[140,146,"Punjab"],[147,149,"Punjab"],[150,159,"Punjab"],[160,160,"Chandigarh"],[161,165,"Punjab"],[171,177,"Himachal Pradesh"],[180,194,"Jammu & Kashmir"],[201,207,"Uttar Pradesh"],[208,210,"Uttar Pradesh"],[211,231,"Uttar Pradesh"],[242,243,"Uttar Pradesh"],[244,244,"Uttarakhand"],[245,245,"Uttar Pradesh"],[246,249,"Uttarakhand"],[250,261,"Uttar Pradesh"],[262,263,"Uttarakhand"],[264,270,"Uttar Pradesh"],[271,285,"Uttar Pradesh"],[301,326,"Rajasthan"],[327,345,"Rajasthan"],[360,396,"Gujarat"],[400,402,"Maharashtra"],[403,403,"Goa"],[404,445,"Maharashtra"],[450,458,"Madhya Pradesh"],[460,488,"Madhya Pradesh"],[490,497,"Chhattisgarh"],[500,509,"Telangana"],[515,535,"Andhra Pradesh"],[560,591,"Karnataka"],[600,604,"Tamil Nadu"],[605,605,"Puducherry"],[606,608,"Tamil Nadu"],[609,609,"Puducherry"],[610,643,"Tamil Nadu"],[670,682,"Kerala"],[683,695,"Kerala"],[700,736,"West Bengal"],[737,737,"Sikkim"],[738,743,"West Bengal"],[744,744,"Andaman & Nicobar Islands"],[751,770,"Odisha"],[781,788,"Assam"],[790,792,"Arunachal Pradesh"],[793,794,"Meghalaya"],[795,795,"Manipur"],[796,796,"Mizoram"],[797,798,"Nagaland"],[799,799,"Tripura"],[800,812,"Bihar"],[813,828,"Jharkhand"],[829,835,"Jharkhand"],[841,855,"Bihar"]];

function isPincode(str){
  return /^\d{6}$/.test(String(str||'').trim());
}

function stateForPincode(pin){
  const p3 = parseInt(String(pin).trim().slice(0,3), 10);
  if(isNaN(p3)) return null;
  for(let i=0;i<PIN_RANGES.length;i++){
    if(p3 >= PIN_RANGES[i][0] && p3 <= PIN_RANGES[i][1]) return PIN_RANGES[i][2];
  }
  return null;
}

module.exports = { isPincode, stateForPincode, PIN_RANGES };
