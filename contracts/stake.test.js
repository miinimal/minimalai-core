// Stake v1 in the TON sandbox: the owner deposits, only the slasher slashes and only to the treasury, withdrawal only after
// the unlock period, relock cancels it; nobody else can move anything. Run: node stake.test.js
const fs = require('fs');
const assert = require('assert');
const { compileFunc } = require('@ton-community/func-js');
const { Blockchain } = require('@ton/sandbox');
const { beginCell, Cell, contractAddress, toNano } = require('@ton/core');
const OP = { unlock: 0x554e4c4b, relock: 0x52454c4b, withdraw: 0x57495448, slash: 0x534c5348 };
const UNLOCK = 7 * 86400;
(async () => {
  const r = await compileFunc({ targets: ['stake.fc'], sources: (p) => fs.readFileSync(__dirname + '/contracts/' + p, 'utf8') });
  if (r.status === 'error') { console.error(r.message); process.exit(1); }
  fs.writeFileSync(__dirname + '/contracts/stake.code.b64', r.codeBoc + '\n');
  const code = Cell.fromBase64(r.codeBoc);
  const bc = await Blockchain.create();
  const w = {}; for (const n of ['owner', 'slasher', 'treasury', 'stranger']) w[n] = await bc.treasury(n);
  const now = Math.floor(Date.now() / 1000); bc.now = now;
  const data = beginCell().storeAddress(w.owner.address).storeAddress(w.slasher.address).storeAddress(w.treasury.address)
    .storeUint(UNLOCK, 32).storeUint(0, 32).storeUint(1, 64).endCell();
  const init = { code, data }; const address = contractAddress(0, init);
  const ex = (res) => res.transactions.find((t) => t.inMessage?.info?.dest?.equals?.(address))?.description?.computePhase?.exitCode;
  const op = (who, o, extra) => who.send({ to: address, value: toNano('0.05'), body: (extra || beginCell().storeUint(o, 32).storeUint(0, 64)).endCell() });
  const bal = async (a) => (await bc.getContract(a)).balance;
  const stake = async () => { const s = (await bc.runGetMethod(address, 'get_stake')).stackReader; s.readAddress(); s.readAddress(); s.readAddress(); s.readBigNumber(); return { unlockAt: Number(s.readBigNumber()), purpose: Number(s.readBigNumber()), balance: s.readBigNumber() }; };
  let n = 0; const t = async (name, fn) => { await fn(); n++; console.log('ok  ', name); };

  await t('owner deposits 2 GRAM; get_stake reads it', async () => {
    assert.equal(ex(await w.owner.send({ to: address, value: toNano('2'), init, body: beginCell().endCell() })), 0);
    const s = await stake(); assert.ok(s.balance > toNano('1.9') && s.unlockAt === 0 && s.purpose === 1);
  });
  await t('nobody but the owner withdraws, and not before unlocking', async () => {
    assert.equal(ex(await op(w.stranger, OP.withdraw)), 401);
    assert.equal(ex(await op(w.slasher, OP.withdraw)), 401);
    assert.equal(ex(await op(w.owner, OP.withdraw)), 403);
  });
  await t('slash: only the slasher, only to the treasury, never above the balance', async () => {
    const body = (amt) => beginCell().storeUint(OP.slash, 32).storeUint(0, 64).storeCoins(toNano(amt)).storeRef(beginCell().storeStringTail('backdoor in PR 12').endCell());
    assert.equal(ex(await op(w.stranger, 0, body('1'))), 402);
    assert.equal(ex(await op(w.owner, 0, body('1'))), 402);
    assert.equal(ex(await op(w.slasher, 0, body('5'))), 405);
    const t0 = await bal(w.treasury.address), s0 = await bal(w.slasher.address);
    assert.equal(ex(await op(w.slasher, 0, body('1'))), 0);
    assert.ok((await bal(w.treasury.address)) - t0 > toNano('0.99'), 'treasury got the slash');
    assert.ok((await bal(w.slasher.address)) <= s0, 'the slasher gained nothing');
  });
  await t('unlock -> wait -> withdraw the rest; relock cancels the clock', async () => {
    assert.equal(ex(await op(w.stranger, OP.unlock)), 401);
    assert.equal(ex(await op(w.owner, OP.unlock)), 0);
    assert.ok((await stake()).unlockAt > now);
    assert.equal(ex(await op(w.owner, OP.relock)), 0);
    assert.equal((await stake()).unlockAt, 0);
    assert.equal(ex(await op(w.owner, OP.unlock)), 0);
    bc.now = now + UNLOCK - 10;
    assert.equal(ex(await op(w.owner, OP.withdraw)), 403);
    bc.now = now + UNLOCK + 1;
    const o0 = await bal(w.owner.address);
    assert.equal(ex(await op(w.owner, OP.withdraw)), 0);
    assert.ok((await bal(w.owner.address)) - o0 > toNano('0.9'));
    assert.notEqual((await bc.getContract(address)).accountState?.type, 'active');
  });
  console.log(`STAKE OK ${n}/4`);
})().catch((e) => { console.error(e); process.exit(1); });
