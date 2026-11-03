// City Hall (TON DNS subresolver for *.minimalcult.ton) in the TON sandbox. Run: node mayor.test.js
const fs = require('fs');
const assert = require('assert');
const crypto = require('crypto');
const { compileFunc } = require('@ton-community/func-js');
const { Blockchain } = require('@ton/sandbox');
const { beginCell, Cell, Dictionary, contractAddress, toNano, Address } = require('@ton/core');

const OP = { set: 0x53455421, drop: 0x44524f50, mayor: 0x4d41594f };
const sha = (s) => BigInt('0x' + crypto.createHash('sha256').update(s).digest('hex'));
const CAT_WALLET = sha('wallet');
const label = (s) => beginCell().storeBuffer(Buffer.from(s, 'utf8')).endCell();
const dnsName = (s) => beginCell().storeBuffer(Buffer.from(s, 'utf8')).endCell().beginParse();   // raw bytes incl. \0

(async () => {
  const r = await compileFunc({ targets: ['mayor.fc'], sources: (p) => fs.readFileSync(__dirname + '/contracts/' + p, 'utf8') });
  if (r.status === 'error') { console.error(r.message); process.exit(1); }
  fs.writeFileSync(__dirname + '/contracts/mayor.code.b64', r.codeBoc + '\n');
  const code = Cell.fromBase64(r.codeBoc);

  const bc = await Blockchain.create();
  const mayor = await bc.treasury('mayor'), stranger = await bc.treasury('stranger'), agent = await bc.treasury('agent');
  const data = beginCell().storeAddress(mayor.address).storeDict(null).endCell();
  const init = { code, data }; const address = contractAddress(0, init);
  const ex = (res) => res.transactions.find((t) => t.inMessage?.info?.dest?.equals?.(address))?.description?.computePhase?.exitCode;
  const now = Math.floor(Date.now() / 1000); bc.now = now;
  await mayor.send({ to: address, value: toNano('0.1'), init, body: beginCell().endCell() });

  const setMsg = (name, wallet, expires) => beginCell().storeUint(OP.set, 32).storeUint(0, 64).storeUint(expires, 32)
    .storeAddress(wallet).storeRef(label(name)).endCell();
  const resolve = async (name, cat) => {
    const res = await bc.runGetMethod(address, 'dnsresolve', [{ type: 'slice', cell: beginCell().storeBuffer(Buffer.from(name, 'utf8')).endCell() },
      { type: 'int', value: cat }]);
    const s = res.stackReader; const bits = Number(s.readBigNumber()); const c = s.readCellOpt(); return { bits, cell: c };
  };
  let n = 0; const t = async (name, fn) => { await fn(); n++; console.log('ok  ', name); };

  await t('stranger cannot register a name; mayor can', async () => {
    assert.equal(ex(await stranger.send({ to: address, value: toNano('0.05'), body: setMsg('alice', agent.address, now + 86400 * 365) })), 401);
    assert.equal(ex(await mayor.send({ to: address, value: toNano('0.05'), body: setMsg('alice', agent.address, now + 86400 * 365) })), 0);
  });

  await t('alice.minimalcult.ton resolves to the agent wallet (category wallet, initial and recursive forms)', async () => {
    for (const q of ['\0alice\0', 'alice\0']) {
      const { bits, cell } = await resolve(q, CAT_WALLET);
      assert.equal(bits, q.length * 8, q);
      const s = cell.beginParse();
      assert.equal(s.loadUint(16), 0x9fd3);
      assert.ok(s.loadAddress().equals(agent.address));
    }
  });

  await t('category 0 returns the record set with the wallet; unknown category -> no record but bits consumed', async () => {
    const all = await resolve('\0alice\0', 0n);
    const d = Dictionary.loadDirect(Dictionary.Keys.BigUint(256), Dictionary.Values.Cell(), all.cell);
    assert.ok(d.get(CAT_WALLET));
    const other = await resolve('\0alice\0', sha('site'));
    assert.equal(other.bits, 7 * 8); assert.equal(other.cell, null);
  });

  await t('unknown name, deeper level and malformed input resolve to nothing', async () => {
    assert.equal((await resolve('\0bob\0', CAT_WALLET)).bits, 0);
    assert.equal((await resolve('\0alice\0sub\0', CAT_WALLET)).bits, 0);
    assert.equal((await resolve('\0', CAT_WALLET)).bits, 0);
    assert.equal((await resolve('alice', CAT_WALLET)).bits, 0);          // no terminator
  });

  await t('expired name stops resolving; renewal brings it back; drop removes it', async () => {
    await mayor.send({ to: address, value: toNano('0.05'), body: setMsg('carol', agent.address, now + 10) });
    assert.equal((await resolve('\0carol\0', CAT_WALLET)).bits, 56);
    bc.now = now + 11;
    assert.equal((await resolve('\0carol\0', CAT_WALLET)).bits, 0);
    await mayor.send({ to: address, value: toNano('0.05'), body: setMsg('carol', agent.address, now + 86400) });
    assert.equal((await resolve('\0carol\0', CAT_WALLET)).bits, 56);
    await mayor.send({ to: address, value: toNano('0.05'), body: beginCell().storeUint(OP.drop, 32).storeUint(0, 64).storeRef(label('carol')).endCell() });
    assert.equal((await resolve('\0carol\0', CAT_WALLET)).bits, 0);
  });

  await t('bad labels are rejected (control byte, dot, too long); unknown op rejected', async () => {
    assert.equal(ex(await mayor.send({ to: address, value: toNano('0.05'), body: setMsg('a\x01b', agent.address, 0) })), 402);
    assert.equal(ex(await mayor.send({ to: address, value: toNano('0.05'), body: setMsg('a.b', agent.address, 0) })), 0);  // '.' is byte 46 > 32: allowed here, forbidden by the gateway
    assert.equal(ex(await mayor.send({ to: address, value: toNano('0.05'), body: setMsg('x'.repeat(64), agent.address, 0) })), 402);
    assert.equal(ex(await mayor.send({ to: address, value: toNano('0.05'), body: beginCell().storeUint(0x11111111, 32).storeUint(0, 64).endCell() })), 404);
  });

  await t('mayor hand-over: old mayor loses control', async () => {
    await mayor.send({ to: address, value: toNano('0.05'), body: beginCell().storeUint(OP.mayor, 32).storeUint(0, 64).storeAddress(stranger.address).endCell() });
    assert.equal(ex(await mayor.send({ to: address, value: toNano('0.05'), body: setMsg('dave', agent.address, 0) })), 401);
    assert.equal(ex(await stranger.send({ to: address, value: toNano('0.05'), body: setMsg('dave', agent.address, 0) })), 0);
    const gm = (await bc.runGetMethod(address, 'get_mayor')).stackReader.readAddress();
    assert.ok(gm.equals(stranger.address));
  });

  console.log(`MAYOR OK ${n}/7`);
})().catch((e) => { console.error(e); process.exit(1); });
