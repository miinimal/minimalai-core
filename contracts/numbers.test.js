// City numbers (B10c): NFT collection + items that resolve "N.minimalcult.ton" to the item owner, delegated by the City Hall.
// Run: node numbers.test.js — also measures what a mint costs (sandbox fees, printed with the date).
const fs = require('fs');
const assert = require('assert');
const crypto = require('crypto');
const { compileFunc } = require('@ton-community/func-js');
const { Blockchain } = require('@ton/sandbox');
const { beginCell, Cell, Dictionary, contractAddress, toNano, fromNano, Address } = require('@ton/core');

const sha = (s) => BigInt('0x' + crypto.createHash('sha256').update(s).digest('hex'));
const CAT_WALLET = sha('wallet'), CAT_NEXT = sha('dns_next_resolver');
const OP = { mint: 0x4d494e54, numbers: 0x4e554d42, transfer: 0x5fcc3d14, set: 0x53455421 };
const src = (p) => fs.readFileSync(__dirname + '/contracts/' + p, 'utf8');

async function compile(target, out) {
  const r = await compileFunc({ targets: [target], sources: src });
  if (r.status === 'error') { console.error(target, r.message); process.exit(1); }
  fs.writeFileSync(__dirname + '/contracts/' + out, r.codeBoc + '\n');
  return Cell.fromBase64(r.codeBoc);
}

(async () => {
  const itemCode = await compile('number_item.fc', 'number_item.code.b64');
  const collCode = await compile('number_collection.fc', 'number_collection.code.b64');
  const mayorCode = await compile('mayor.fc', 'mayor.code.b64');

  const bc = await Blockchain.create();
  const mayor = await bc.treasury('mayor'), agent = await bc.treasury('agent'), buyer = await bc.treasury('buyer'), stranger = await bc.treasury('stranger');
  const content = beginCell().storeUint(1, 8).storeBuffer(Buffer.from('https://ai.minimalcult.org/v1/numbers/meta.json')).endCell();
  const collInit = { code: collCode, data: beginCell().storeAddress(mayor.address).storeUint(101, 64).storeRef(itemCode).storeRef(content).endCell() };
  const coll = contractAddress(0, collInit);
  const mayorInit = { code: mayorCode, data: beginCell().storeAddress(mayor.address).storeDict(null).storeMaybeRef(null).endCell() };
  const hall = contractAddress(0, mayorInit);
  await mayor.send({ to: coll, value: toNano('0.1'), init: collInit, body: beginCell().endCell() });
  await mayor.send({ to: hall, value: toNano('0.1'), init: mayorInit, body: beginCell().endCell() });
  const exitAt = (res, addr) => res.transactions.find((t) => t.inMessage?.info?.dest?.equals?.(addr))?.description?.computePhase?.exitCode;
  const itemAddr = async (i) => (await bc.runGetMethod(coll, 'get_nft_address_by_index', [{ type: 'int', value: BigInt(i) }])).stackReader.readAddress();
  const mint = (who, index, owner, value = '0.06') => who.send({ to: coll, value: toNano(value), body: beginCell().storeUint(OP.mint, 32).storeUint(0, 64)
    .storeUint(index, 64).storeCoins(toNano('0.05')).storeRef(beginCell().storeAddress(owner).storeRef(beginCell().storeBuffer(Buffer.from(String(index))).endCell()).endCell()).endCell() });
  const resolveAt = async (addr, name, cat) => {
    const res = await bc.runGetMethod(addr, 'dnsresolve', [{ type: 'slice', cell: beginCell().storeBuffer(Buffer.from(name, 'latin1')).endCell() }, { type: 'int', value: cat }]);
    const s = res.stackReader; return { bits: Number(s.readBigNumber()), cell: s.readCellOpt() };
  };
  // a TEP-81 client: follow dns_next_resolver records until the subdomain is consumed
  const resolve = async (name, cat) => {
    let addr = hall, rest = name;
    for (let hop = 0; hop < 4; hop++) {
      const { bits, cell } = await resolveAt(addr, rest, cat);
      if (bits === 0) return { bits: 0, cell: null, hops: hop };
      const consumed = bits / 8;
      if (consumed >= rest.length) return { bits, cell, hops: hop + 1 };
      let rec = cell;
      if (cat === 0n) { const d = Dictionary.loadDirect(Dictionary.Keys.BigUint(256), Dictionary.Values.Cell(), cell); rec = d.get(CAT_NEXT); assert.ok(rec, 'record set must carry dns_next_resolver'); }
      const s = rec.beginParse(); assert.equal(s.loadUint(16), 0xba93, 'partial result must be dns_next_resolver');
      addr = s.loadAddress(); rest = rest.slice(consumed);
    }
    throw new Error('too many hops');
  };
  let n = 0; const t = async (name, fn) => { await fn(); n++; console.log('ok  ', name); };

  await t('only the mayor mints; item 101 belongs to the agent; index below 1 refused', async () => {
    assert.equal(exitAt(await stranger.send({ to: coll, value: toNano('0.06'), body: beginCell().storeUint(OP.mint, 32).storeUint(0, 64).storeUint(101, 64).storeCoins(toNano('0.05')).storeRef(beginCell().storeAddress(agent.address).storeRef(beginCell().endCell()).endCell()).endCell() }), coll), 401);
    assert.equal(exitAt(await mint(mayor, 0, agent.address), coll), 403);
    const res = await mint(mayor, 101, agent.address);
    assert.equal(exitAt(res, coll), 0);
    const item = await itemAddr(101);
    const d = (await bc.runGetMethod(item, 'get_nft_data', [])).stackReader;
    assert.equal(d.readBigNumber(), -1n); assert.equal(d.readBigNumber(), 101n); assert.ok(d.readAddress().equals(coll)); assert.ok(d.readAddress().equals(agent.address));
    const fees = res.transactions.reduce((a, tx) => a + tx.totalFees.coins, 0n);
    console.log(`     mint cost in the sandbox (fees, all transactions, ${new Date().toISOString().slice(0, 10)}): ${fromNano(fees)} TON + 0.05 TON kept on the item`);
  });

  await t('City Hall delegates numbers: NUMB op by the mayor, then 101.minimalcult.ton resolves through the item to the agent wallet', async () => {
    assert.equal(exitAt(await stranger.send({ to: hall, value: toNano('0.05'), body: beginCell().storeUint(OP.numbers, 32).storeUint(0, 64).storeAddress(coll).storeRef(itemCode).endCell() }), hall), 401);
    assert.equal(exitAt(await mayor.send({ to: hall, value: toNano('0.05'), body: beginCell().storeUint(OP.numbers, 32).storeUint(0, 64).storeAddress(coll).storeRef(itemCode).endCell() }), hall), 0);
    const viaHall = (await bc.runGetMethod(hall, 'get_number_item', [{ type: 'int', value: 101n }])).stackReader.readAddress();
    assert.ok(viaHall.equals(await itemAddr(101)), 'the hall computes the same item address as the collection');
    for (const q of ['\x00101\x00', '101\0']) {
      const r = await resolve(q, CAT_WALLET);
      assert.equal(r.hops, 2, q);
      const s = r.cell.beginParse(); assert.equal(s.loadUint(16), 0x9fd3); assert.ok(s.loadAddress().equals(agent.address));
    }
    const all = await resolve('\x00101\x00', 0n);
    const dict = Dictionary.loadDirect(Dictionary.Keys.BigUint(256), Dictionary.Values.Cell(), all.cell);
    assert.ok(dict.get(CAT_WALLET));
  });

  await t('names still resolve directly; a zero-padded label, an unminted number and a deeper level resolve to nothing', async () => {
    await mayor.send({ to: hall, value: toNano('0.05'), body: beginCell().storeUint(OP.set, 32).storeUint(0, 64).storeUint(0, 32).storeAddress(buyer.address).storeRef(beginCell().storeBuffer(Buffer.from('alice')).endCell()).endCell() });
    const a = await resolve('\0alice\0', CAT_WALLET); assert.equal(a.hops, 1); assert.ok(a.cell.beginParse().skip(16).loadAddress().equals(buyer.address));
    assert.equal((await resolveAt(hall, '\x00' + '0101' + '\x00', CAT_WALLET)).bits, 0);          // only the canonical label is a number
    const un = await resolveAt(hall, '\x00' + '777' + '\x00', CAT_WALLET);                           // the hall points at the (undeployed) item
    assert.equal(un.bits, 32);
    await assert.rejects(resolve('\x00777\x00', CAT_WALLET), /non-active/);                          // the item does not exist: a resolver gets no account
    assert.equal((await resolveAt(hall, '\x00101\x00x\x00', CAT_WALLET)).bits, 0);
  });

  await t('transfer by the owner moves the address; a stranger cannot transfer; the old owner is notified / excess returned', async () => {
    const item = await itemAddr(101);
    const xfer = (who, to) => who.send({ to: item, value: toNano('0.05'), body: beginCell().storeUint(OP.transfer, 32).storeUint(0, 64)
      .storeAddress(to).storeAddress(who.address).storeBit(0).storeCoins(toNano('0.001')).storeBit(0).endCell() });
    assert.equal(exitAt(await xfer(stranger, stranger.address), item), 401);
    assert.equal(exitAt(await xfer(agent, buyer.address), item), 0);
    const r = await resolve('\x00101\x00', CAT_WALLET);
    assert.ok(r.cell.beginParse().skip(16).loadAddress().equals(buyer.address), 'the address follows the NFT');
    assert.equal(exitAt(await xfer(agent, agent.address), item), 401);
  });

  await t('project custody: an item minted to the mayor wallet is handed to the agent later by a normal transfer', async () => {
    await mint(mayor, 102, mayor.address);
    const item = await itemAddr(102);
    assert.ok((await resolve('\x00102\x00', CAT_WALLET)).cell.beginParse().skip(16).loadAddress().equals(mayor.address));
    await mayor.send({ to: item, value: toNano('0.05'), body: beginCell().storeUint(OP.transfer, 32).storeUint(0, 64).storeAddress(agent.address).storeAddress(mayor.address).storeBit(0).storeCoins(0).storeBit(0).endCell() });
    assert.ok((await resolve('\x00102\x00', CAT_WALLET)).cell.beginParse().skip(16).loadAddress().equals(agent.address));
    const cd = (await bc.runGetMethod(coll, 'get_collection_data', [])).stackReader; assert.equal(cd.readBigNumber(), 103n);
  });

  console.log(`NUMBERS OK ${n}/5`);
})().catch((e) => { console.error(e); process.exit(1); });
