// Escrow v2 ("the Circle") in the official TON sandbox: honest paths and every fraud path we know.
// Run: node escrow.test.js   (exit 0 = all passed)
const fs = require('fs');
const assert = require('assert');
const { compileFunc } = require('@ton-community/func-js');
const { Blockchain } = require('@ton/sandbox');
const { beginCell, Cell, contractAddress, toNano } = require('@ton/core');

const OP = { accept: 0x41435054, claim: 0x434c414d, defect: 0x44464354, release: 0x52454c53, decline: 0x4445434c, refund: 0x52464e44 };
const DAY = 86400, HOLD = 14 * DAY;
const G = toNano('0.05');   // gas tolerance per message

async function code() {
  const r = await compileFunc({ targets: ['escrow.fc'], sources: (p) => fs.readFileSync(__dirname + '/contracts/' + p, 'utf8') });
  if (r.status === 'error') { console.error(r.message); process.exit(1); }
  fs.writeFileSync(__dirname + '/contracts/escrow.code.b64', r.codeBoc + '\n');
  return Cell.fromBase64(r.codeBoc);
}

async function setup(c, { feeBps = 1500, revBps = 1500, reviewer = true, deadlineIn = 3 * DAY, taskId = 1n } = {}) {
  const bc = await Blockchain.create();
  const w = {};
  for (const n of ['poster', 'worker', 'treasury', 'reviewer', 'stranger', 'project']) w[n] = await bc.treasury(n);
  const now = Math.floor(Date.now() / 1000);
  bc.now = now;
  const terms = beginCell().storeAddress(w.treasury.address).storeUint(feeBps, 16)
    .storeAddress(reviewer ? w.reviewer.address : null).storeUint(revBps, 16)
    .storeUint(now + deadlineIn, 32).storeUint(taskId, 64).storeUint(HOLD, 32).endCell();
  const data = beginCell().storeAddress(w.poster.address).storeAddress(w.worker.address)
    .storeUint(0, 2).storeUint(0, 32).storeUint(0, 32).storeRef(terms).endCell();
  const init = { code: c, data };
  const address = contractAddress(0, init);
  const e = { bc, ...w, address, init, now };
  e.ex = (res) => res.transactions.find((t) => t.inMessage?.info?.dest?.equals?.(address))?.description?.computePhase?.exitCode;
  e.op = async (who, o) => e.ex(await who.send({ to: address, value: G, body: beginCell().storeUint(o, 32).storeUint(0, 64).endCell() }));
  e.bal = async (a) => (await bc.getContract(a)).balance;
  e.closed = async () => (await bc.getContract(address)).accountState?.type !== 'active';
  e.deploy = async (from = w.poster, value = toNano('10')) => e.ex(await from.send({ to: address, value, init, body: beginCell().endCell() }));
  e.snap = async () => { const s = {}; for (const n of ['poster', 'worker', 'treasury', 'reviewer', 'project']) s[n] = await e.bal(w[n].address); return s; };
  e.delta = async (s0) => { const s = await e.snap(); const d = {}; for (const k in s) d[k] = s[k] - s0[k]; return d; };
  return e;
}

const near = (got, want, tol = G) => assert.ok(got >= want - tol && got <= want + tol, `got ${got}, want ~${want}`);

(async () => {
  const c = await code();
  let n = 0;
  const t = async (name, fn) => { await fn(); n++; console.log('ok  ', name); };

  await t('circle: accept pays fee 15% + reviewer 15% + worker 50% of rest; claim after 14 days pays the rest', async () => {
    const e = await setup(c);
    assert.equal(await e.deploy(), 0);
    const amount = (await e.bal(e.address)) - toNano('0.01');
    const s0 = await e.snap();
    assert.equal(await e.op(e.poster, OP.accept), 0);
    const fee = amount * 1500n / 10000n, rev = amount * 1500n / 10000n, first = (amount - fee - rev) / 2n;
    let d = await e.delta(s0);
    near(d.treasury, fee); near(d.reviewer, rev); near(d.worker, first);
    assert.equal(await e.op(e.stranger, OP.claim), 403);              // hold not over
    e.bc.now = e.now + HOLD + 1;
    assert.equal(await e.op(e.stranger, OP.claim), 0);                // anyone can trigger the time release
    d = await e.delta(s0);
    near(d.worker, amount - fee - rev, toNano('0.15'));  // + reserve and leftover gas
    assert.equal(d.project, 0n, 'project wallet is not involved');
    assert.ok(await e.closed());
  });

  await t('no reviewer: reviewer share stays with the worker', async () => {
    const e = await setup(c, { reviewer: false });
    await e.deploy();
    const amount = (await e.bal(e.address)) - toNano('0.01');
    const s0 = await e.snap();
    await e.op(e.poster, OP.accept);
    near((await e.delta(s0)).worker, (amount - amount * 1500n / 10000n) / 2n);
    assert.equal((await e.delta(s0)).reviewer, 0n);
  });

  await t('fraud: only the poster accepts, once; only the poster funds, only while open', async () => {
    const e = await setup(c);
    assert.equal(await e.deploy(e.stranger), 401);
    await e.deploy();
    assert.equal(await e.op(e.stranger, OP.accept), 401);
    assert.equal(await e.op(e.worker, OP.accept), 401);
    assert.equal(await e.op(e.poster, OP.accept), 0);
    assert.equal(await e.op(e.poster, OP.accept), 406);
    assert.equal(e.ex(await e.poster.send({ to: e.address, value: toNano('1'), body: beginCell().endCell() })), 406);
    assert.equal(await e.op(e.poster, 0x12345678), 404);
  });

  await t('defect: poster flags inside hold; reviewer rules for the poster -> remainder back to poster', async () => {
    const e = await setup(c);
    await e.deploy(); await e.op(e.poster, OP.accept);
    assert.equal(await e.op(e.stranger, OP.defect), 401);
    assert.equal(await e.op(e.poster, OP.defect), 0);
    assert.equal(await e.op(e.stranger, OP.claim), 403);              // no time release while disputed
    assert.equal(await e.op(e.poster, OP.refund), 401);               // poster cannot rule for itself
    assert.equal(await e.op(e.worker, OP.release), 401);
    const s0 = await e.snap();
    assert.equal(await e.op(e.reviewer, OP.refund), 0);
    assert.ok((await e.delta(s0)).poster > toNano('3'));
    assert.ok(await e.closed());
  });

  await t('defect: reviewer rules for the worker; or nobody rules in 30 days -> split equally', async () => {
    let e = await setup(c);
    await e.deploy(); await e.op(e.poster, OP.accept); await e.op(e.poster, OP.defect);
    let s0 = await e.snap();
    assert.equal(await e.op(e.reviewer, OP.release), 0);
    assert.ok((await e.delta(s0)).worker > toNano('3'));
    e = await setup(c);
    await e.deploy(); await e.op(e.poster, OP.accept); await e.op(e.poster, OP.defect);
    const rest = (await e.bal(e.address)) - toNano('0.01');
    e.bc.now = e.now + 31 * DAY;
    s0 = await e.snap();
    assert.equal(await e.op(e.stranger, OP.claim), 0);
    const d = await e.delta(s0);
    near(d.poster, rest / 2n, toNano('0.1')); near(d.worker, rest / 2n, toNano('0.1'));
  });

  await t('defect too late: after hold the poster cannot freeze the payout', async () => {
    const e = await setup(c);
    await e.deploy(); await e.op(e.poster, OP.accept);
    e.bc.now = e.now + HOLD + 1;
    assert.equal(await e.op(e.poster, OP.defect), 407);
  });

  await t('decline and refund: worker declines anytime; poster refunds only after deadline and only if not accepted', async () => {
    let e = await setup(c);
    await e.deploy();
    assert.equal(await e.op(e.poster, OP.decline), 402);
    assert.equal(await e.op(e.poster, OP.refund), 403);
    assert.equal(await e.op(e.stranger, OP.refund), 401);
    let s0 = await e.snap();
    assert.equal(await e.op(e.worker, OP.decline), 0);
    assert.ok((await e.delta(s0)).poster > toNano('9.9'));
    e = await setup(c);
    await e.deploy(); e.bc.now = e.now + 3 * DAY + 1;
    s0 = await e.snap();
    assert.equal(await e.op(e.poster, OP.refund), 0);
    assert.ok((await e.delta(s0)).poster > toNano('9.9'));
    e = await setup(c);
    await e.deploy(); await e.op(e.poster, OP.accept); e.bc.now = e.now + 3 * DAY + 1;
    assert.equal(await e.op(e.poster, OP.refund), 406);               // accepted work cannot be clawed back by refund
  });

  await t('rates above the 20% code caps are rejected at deploy', async () => {
    assert.equal(await (await setup(c, { feeBps: 5000 })).deploy(), 405);
    assert.equal(await (await setup(c, { revBps: 2500 })).deploy(), 405);
  });

  await t('get_escrow returns parties, state and terms', async () => {
    const e = await setup(c, { taskId: 42n });
    await e.deploy(); await e.op(e.poster, OP.accept);
    const s = (await e.bc.runGetMethod(e.address, 'get_escrow')).stackReader;
    assert.ok(s.readAddress().equals(e.poster.address));
    assert.ok(s.readAddress().equals(e.worker.address));
    assert.equal(s.readBigNumber(), 1n);
    assert.ok(s.readBigNumber() > 0n); s.readBigNumber();
    assert.ok(s.readAddress().equals(e.treasury.address));
    assert.equal(s.readBigNumber(), 1500n);
    assert.ok(s.readAddress().equals(e.reviewer.address));
    assert.equal(s.readBigNumber(), 1500n); s.readBigNumber();
    assert.equal(s.readBigNumber(), 42n);
    assert.equal(s.readBigNumber(), BigInt(HOLD));
  });

  console.log(`ESCROW OK ${n}/9`);
})().catch((err) => { console.error(err); process.exit(1); });
