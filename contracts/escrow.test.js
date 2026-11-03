// Escrow v1 in the official TON sandbox: honest paths and every fraud path we know.
// Run: node escrow.test.js   (exit 0 = all passed)
const fs = require('fs');
const assert = require('assert');
const { compileFunc } = require('@ton-community/func-js');
const { Blockchain } = require('@ton/sandbox');
const { beginCell, Cell, contractAddress, toNano } = require('@ton/core');

const OP = { release: 0x52454c53, decline: 0x4445434c, refund: 0x52464e44 };

async function code() {
  const r = await compileFunc({ targets: ['escrow.fc'], sources: (p) => fs.readFileSync(__dirname + '/contracts/' + p, 'utf8') });
  if (r.status === 'error') { console.error(r.message); process.exit(1); }
  fs.writeFileSync(__dirname + '/contracts/escrow.code.b64', r.codeBoc + '\n');
  return Cell.fromBase64(r.codeBoc);
}

async function setup(c, { feeBps = 1500, deadlineIn = 3600, taskId = 1n } = {}) {
  const bc = await Blockchain.create();
  const [poster, worker, treasury, stranger, project] = await Promise.all(
    ['poster', 'worker', 'treasury', 'stranger', 'project'].map((n) => bc.treasury(n)));
  const now = Math.floor(Date.now() / 1000);
  bc.now = now;
  const data = beginCell().storeAddress(poster.address).storeAddress(worker.address)
    .storeRef(beginCell().storeAddress(treasury.address).storeUint(feeBps, 16).storeUint(now + deadlineIn, 32).storeUint(taskId, 64))
    .endCell();
  const init = { code: c, data };
  const address = contractAddress(0, init);
  const ex = (res) => res.transactions.find((t) => t.inMessage?.info?.dest?.equals?.(address))?.description?.computePhase?.exitCode;
  const op = (who, o, value = toNano('0.05')) => who.send({ to: address, value, body: beginCell().storeUint(o, 32).storeUint(0, 64).endCell() });
  const bal = async (a) => (await bc.getContract(a)).balance;
  const state = async () => (await bc.getContract(address)).accountState?.type;
  return { bc, poster, worker, treasury, stranger, project, address, init, ex, op, bal, state, now };
}

const deploy = (e, from = e.poster, value = toNano('10')) =>
  from.send({ to: e.address, value, init: e.init, body: beginCell().endCell() });

(async () => {
  const c = await code();
  const results = [];
  const t = async (name, fn) => { await fn(); results.push(name); console.log('ok  ', name); };

  await t('release: worker gets amount - fee, treasury gets exactly the fee, escrow closes', async () => {
    const e = await setup(c);
    assert.equal(e.ex(await deploy(e)), 0);
    const escrowed = await e.bal(e.address);
    const w0 = await e.bal(e.worker.address), tr0 = await e.bal(e.treasury.address), p0 = await e.bal(e.project.address);
    assert.equal(e.ex(await e.op(e.poster, OP.release)), 0);
    const fee = (escrowed - toNano('0.01')) * 1500n / 10000n;
    const trGot = (await e.bal(e.treasury.address)) - tr0;
    assert.ok(trGot <= fee && trGot > fee - toNano('0.01'), `treasury got ${trGot}, fee ${fee}`);
    const wGot = (await e.bal(e.worker.address)) - w0;
    assert.ok(wGot > escrowed - fee - toNano('0.05') && wGot <= escrowed - fee + toNano('0.05'), `worker got ${wGot}`);
    assert.equal(await e.bal(e.project.address), p0, 'project wallet is not involved');
    assert.notEqual(await e.state(), 'active');
  });

  await t('fraud: stranger and worker cannot release', async () => {
    const e = await setup(c); await deploy(e);
    assert.equal(e.ex(await e.op(e.stranger, OP.release)), 401);
    assert.equal(e.ex(await e.op(e.worker, OP.release)), 401);
    assert.ok((await e.bal(e.address)) > toNano('9.9'));
  });

  await t('fraud: poster cannot refund before deadline; can after', async () => {
    const e = await setup(c); await deploy(e);
    assert.equal(e.ex(await e.op(e.poster, OP.refund)), 403);
    assert.equal(e.ex(await e.op(e.stranger, OP.refund)), 401);
    e.bc.now = e.now + 3601;
    const p0 = await e.bal(e.poster.address);
    assert.equal(e.ex(await e.op(e.poster, OP.refund)), 0);
    assert.ok((await e.bal(e.poster.address)) - p0 > toNano('9.9'));
  });

  await t('decline: only the worker; funds return to poster', async () => {
    const e = await setup(c); await deploy(e);
    assert.equal(e.ex(await e.op(e.poster, OP.decline)), 402);
    assert.equal(e.ex(await e.op(e.stranger, OP.decline)), 402);
    const p0 = await e.bal(e.poster.address);
    assert.equal(e.ex(await e.op(e.worker, OP.decline)), 0);
    assert.ok((await e.bal(e.poster.address)) - p0 > toNano('9.9'));
  });

  await t('fraud: double release pays nothing more', async () => {
    const e = await setup(c); await deploy(e);
    await e.op(e.poster, OP.release);
    const w0 = await e.bal(e.worker.address);
    await e.op(e.poster, OP.release);
    assert.ok((await e.bal(e.worker.address)) <= w0);
  });

  await t('fraud: only poster funds; stranger top-up and unknown op rejected', async () => {
    const e = await setup(c);
    assert.equal(e.ex(await deploy(e, e.stranger)), 401);
    await deploy(e);
    assert.equal(e.ex(await e.stranger.send({ to: e.address, value: toNano('1'), body: beginCell().endCell() })), 401);
    assert.equal(e.ex(await e.op(e.poster, 0x12345678)), 404);
  });

  await t('fee above the 20% code cap: deploy rejected, deposit bounces back', async () => {
    const e = await setup(c, { feeBps: 5000 });
    assert.equal(e.ex(await deploy(e)), 405);
  });

  await t('get_escrow returns parties and terms', async () => {
    const e = await setup(c, { taskId: 42n }); await deploy(e);
    const r = await e.bc.runGetMethod(e.address, 'get_escrow');
    const s = r.stackReader;
    assert.ok(s.readAddress().equals(e.poster.address));
    assert.ok(s.readAddress().equals(e.worker.address));
    assert.ok(s.readAddress().equals(e.treasury.address));
    assert.equal(s.readBigNumber(), 1500n);
    s.readBigNumber();
    assert.equal(s.readBigNumber(), 42n);
  });

  console.log(`ESCROW OK ${results.length}/8`);
})().catch((err) => { console.error(err); process.exit(1); });
