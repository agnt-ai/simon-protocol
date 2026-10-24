/** Duplicate-key classification from structured metadata and default index names; no adapter support claim. */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { MongoServerError } from 'mongodb';
import { isDuplicate } from '../src/store/db.ts';

const indexError = (index: string) =>
  new MongoServerError({ code: 11000, errmsg: `E11000 duplicate key error collection: core.agents index: ${index}` });

describe('isDuplicate', () => {
  it('prefers structured keyPattern over a conflicting default index name', () => {
    const e = new MongoServerError({ code: 11000, errmsg: 'E11000 index: _id_', keyPattern: { 'keys.key': 1 } });
    assert.equal(isDuplicate(e, 'keys.key'), true);
    assert.equal(isDuplicate(e, '_id'), false);
  });

  it('reads default index names: _id, one field, and every field of a compound index', () => {
    assert.equal(isDuplicate(indexError('_id_'), '_id'), true);
    assert.equal(isDuplicate(indexError('_id_'), 'keys.key'), false);
    assert.equal(isDuplicate(indexError('keys.key_1'), 'keys.key'), true);
    assert.equal(isDuplicate(indexError('keys.key_1'), 'keys'), false);
    for (const field of ['from', 'principal', 'via'])
      assert.equal(isDuplicate(indexError('from_1_principal_-1_via_1'), field), true);
    assert.equal(isDuplicate(indexError('from_1_principal_-1_via_1'), 'to'), false);
  });

  it('is never a duplicate for another error, and any duplicate without a field', () => {
    assert.equal(isDuplicate(new MongoServerError({ code: 2, errmsg: 'index: _id_' }), '_id'), false);
    assert.equal(isDuplicate(indexError('custom_name')), true);
    assert.equal(isDuplicate(indexError('custom_name'), 'custom'), false);
  });
});
