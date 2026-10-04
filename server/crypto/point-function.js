function assertBitArray(values, name) {
  if (!Array.isArray(values) && !(values instanceof Uint8Array)) throw new TypeError(`${name} must be an array of bits`);
  let invalid = 0;
  for (const value of values) invalid |= Number(value !== 0) & Number(value !== 1);
  if (invalid !== 0) throw new TypeError(`${name} must be an array of bits`);
}

function assertAndCallback(andShares) {
  if (typeof andShares !== 'function') throw new TypeError('andShares callback is required');
}

export async function evaluateSharedRead(databaseShare, pointShare, andShares) {
  assertAndCallback(andShares);
  assertBitArray(databaseShare, 'databaseShare');
  assertBitArray(pointShare, 'pointShare');
  if (pointShare.length < databaseShare.length) throw new RangeError('Point-function domain is smaller than the database');
  // Entries in the padded power-of-two domain have no backing database cell.
  const databaseDomainShare = pointShare.slice(0, databaseShare.length);
  const products = await andShares(databaseDomainShare, Array.from(databaseShare));
  assertBitArray(products, 'read product share');
  if (products.length !== databaseShare.length) throw new RangeError('Read product share has incorrect length');
  return products.reduce((value, bit) => value ^ bit, 0);
}

export async function evaluateSharedReplace(databaseShare, pointShare, valueShare, andShares) {
  assertAndCallback(andShares);
  assertBitArray(databaseShare, 'databaseShare');
  assertBitArray(pointShare, 'pointShare');
  if (pointShare.length < databaseShare.length) throw new RangeError('Point-function domain is smaller than the database');
  if (valueShare !== 0 && valueShare !== 1) throw new TypeError('valueShare must be a bit');

  // D'[i] = D[i] XOR q[i] AND (D[i] XOR value), where q is the
  // secret-shared point function. This replaces one addressed bit while
  // preserving XOR sharing and without opening q or the address.
  const databaseDomainShare = pointShare.slice(0, databaseShare.length);
  const deltaShare = Array.from(databaseShare, bit => bit ^ valueShare);
  const selectedDelta = await andShares(databaseDomainShare, deltaShare);
  assertBitArray(selectedDelta, 'update product share');
  if (selectedDelta.length !== databaseShare.length) throw new RangeError('Update product share has incorrect length');
  return databaseShare.map((bit, index) => bit ^ selectedDelta[index]);
}


