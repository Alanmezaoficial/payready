// Copyright (c) 2026 Enrique Rocha (@soyenriquerocha)
// SPDX-License-Identifier: MIT
// id: er-fee52fa9
/**
 * Canonical synthetic events, one per provider. Shapes mirror the real payloads closely
 * enough that the signed-string templates exercise every placeholder they use.
 */
module.exports = {
  stripe: {
    payload: { id: 'evt_pagokit_test', object: 'event', type: 'payment_intent.succeeded', created: 1780000000,
      data: { object: { id: 'pi_test_1', amount: 2000, currency: 'usd', status: 'succeeded' } } },
    tamper: (b) => b.replace('"succeeded"', '"requires_payment_method"'),
  },
  mercadopago: {
    payload: { id: 12345, type: 'payment', action: 'payment.updated', data: { id: '99999' } },
    extraHeaders: { 'x-request-id': 'req-pagokit-abc' },
    tamper: (b) => b.replace('"99999"', '"88888"'),
  },
  wompi: {
    payload: { event: 'transaction.updated', timestamp: 1780000000,
      data: { transaction: { id: 'txn_test_1', status: 'APPROVED', amount_in_cents: 5000, reference: 'ref1' } },
      signature: { properties: ['data.transaction.id', 'data.transaction.status', 'data.transaction.amount_in_cents'], checksum: '' } },
    tamper: (b) => b.replace('"APPROVED"', '"DECLINED"'),
  },
  lemonsqueezy: {
    payload: { meta: { event_name: 'order_created', event_id: 'evt_ls_1' },
      data: { type: 'orders', id: '1', attributes: { status: 'paid', total: 2000 } } },
    tamper: (b) => b.replace('"paid"', '"refunded"'),
  },
};
