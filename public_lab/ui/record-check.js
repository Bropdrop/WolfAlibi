/* A narrow browser check of the signed record and its content bindings.
   The Python verifiers also check the original authorization chain. */
(() => {
  'use strict';
  const encoder = new TextEncoder();

  function requireMatch(condition, message) {
    if (!condition) throw new Error(message);
  }

  // The published vectors contain printable ASCII, JSON containers and safe
  // integers. Stay inside that domain when matching alibi.canon() byte-for-byte.
  function canonical(value) {
    if (value === null || typeof value === 'boolean' || Number.isSafeInteger(value)) return JSON.stringify(value);
    if (typeof value === 'string' && /^[\x20-\x7e]*$/.test(value)) return JSON.stringify(value);
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    if (typeof value === 'object' && value !== null) {
      return '{' + Object.keys(value).sort().map(key => canonical(key) + ':' + canonical(value[key])).join(',') + '}';
    }
    throw new Error('Value outside the published vector format.');
  }

  function bytes(hex, length) {
    requireMatch(typeof hex === 'string' && hex.length === length * 2 && /^[0-9a-f]+$/.test(hex), 'Invalid key or signature encoding.');
    return Uint8Array.from(hex.match(/../g), pair => parseInt(pair, 16));
  }

  async function digest(value) {
    const data = await crypto.subtle.digest('SHA-256', encoder.encode(canonical(value)));
    return Array.from(new Uint8Array(data), byte => byte.toString(16).padStart(2, '0')).join('');
  }

  async function signature(record, publicKey, domain) {
    const key = await crypto.subtle.importKey('raw', bytes(publicKey, 32), {name: 'Ed25519'}, false, ['verify']);
    const signed = encoder.encode(domain + '\0' + canonical(record.payload));
    requireMatch(await crypto.subtle.verify('Ed25519', key, bytes(record.signature, 64), signed), 'The signature does not match the pinned public key.');
    return record.payload;
  }

  async function paymentOrAdmission(id, evidence, pins, challenge) {
    const record = await signature(evidence.receipt, pins.target_pub, 'quorvane/' + id + '/target-receipt/v1');
    requireMatch(record.type === (id === 'education' ? 'QUORVANE_EDUCATION_TARGET_RECEIPT_V1' : 'QUORVANE_FINANCE_TARGET_RECEIPT_V1'), 'Wrong receipt type.');
    requireMatch(record.target_pub === pins.target_pub && challenge === pins.scope.challenge &&
      record.request_id === pins.scope.request_id && canonical(pins.scope) === canonical(evidence.packet.scope), 'The recorded scope differs from the public expectations.');
    requireMatch(record.scope_sha256 === await digest(pins.scope) && record.packet_sha256 === await digest(evidence.packet), 'The packet differs from the one signed by the target.');
    if (id === 'education') {
      requireMatch(record.response_sha256 === pins.response_sha256 && record.response_sha256 === await digest(evidence.response), 'The fictional response differs from its signed digest.');
    } else {
      requireMatch(record.outcome === 'PENDING_EXTERNAL_SETTLEMENT', 'The signed receipt has an unexpected disposition.');
    }
  }

  window.quorvaneCheckRecord = async (id, envelopeText, pinsText, challengeText) => {
    if (!globalThis.crypto?.subtle) return {outcome: 'UNSUPPORTED', detail: 'Web Crypto is unavailable. Use the local Python verifier.'};
    try {
      const evidence = JSON.parse(envelopeText).evidence;
      const pins = JSON.parse(pinsText);
      const challenge = challengeText.trim();
      bytes(challenge, 32);
      if (id === 'history') {
        const record = await signature(evidence.attestation, pins.history_pub, 'quorvane/finance/history/disclosure/v1');
        requireMatch(record.type === 'QUORVANE_HISTORICAL_INTENT_DISCLOSURE_V1' && record.disposition === 'PENDING_EXTERNAL_SETTLEMENT', 'Unexpected disclosure type or disposition.');
        requireMatch(pins.challenge === challenge && record.challenge === challenge && evidence.request.challenge === challenge, 'The inquiry challenge differs from the pinned challenge.');
        requireMatch(record.anchor_sha256 === pins.anchor_sha256 && record.finance_expectations_sha256 === await digest(pins.finance) &&
          record.inquiry_sha256 === await digest(evidence.request) && record.original_receipt_sha256 === await digest(evidence.original.receipt), 'The archive or inquiry differs from the signed disclosure.');
        await paymentOrAdmission('finance', evidence.original, pins.finance, pins.finance.scope.challenge);
      } else {
        requireMatch(id === 'education' || id === 'finance', 'Unknown experiment.');
        await paymentOrAdmission(id, evidence, pins, challenge);
      }
      return {outcome: 'MATCH', detail: 'The signature and record bindings match the supplied public inputs.'};
    } catch (error) {
      if (error.name === 'NotSupportedError') return {outcome: 'UNSUPPORTED', detail: 'Ed25519 is unavailable here. Use the local Python verifier.'};
      return {outcome: 'REJECTED', detail: error.message || 'The signed record check failed.'};
    }
  };
})();
