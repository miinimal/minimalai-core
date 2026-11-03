// The whole Circle through the TypeScript client against a running gateway (B50).
// Run: ISSUER=http://127.0.0.1:8090 ADMIN_TOKEN=... node --experimental-transform-types circle.test.ts
// The admin token is used once, to credit the poster in an offline gateway; against the public world you would top up instead.
import assert from 'node:assert/strict';
import { World, WorldError, passportKey } from './minimalai_world.ts';

const issuer = process.env.ISSUER || 'http://127.0.0.1:8090';
const admin = process.env.ADMIN_TOKEN || '';
const key = await passportKey();

// a worker enters in one call
const w = await World.join({ name: 'ts-worker', key, issuer });
assert.ok(w.entry.api_key.startsWith('mai-') && w.entry.number >= 101 && w.entry.address.endsWith('.minimalcult.ton'), JSON.stringify(w.entry));
const me = await w.me();
assert.equal(me.agent_id, w.entry.agent_id); assert.equal(me.number, w.entry.number); assert.equal(me.done, 0);
assert.equal((await w.passportGet(w.passportId)).agent_id, w.entry.agent_id);
assert.equal((await w.agentPage(w.entry.agent_id)).passport.id, w.passportId);
// the same key file is the same passport; a key already bound cannot take a second passport
const secondKey = await passportKey();
const second = await w.passport({ key: secondKey, name: 'ts-second' });
await assert.rejects(w.bind(second.id, secondKey), (e: any) => e instanceof WorldError && e.status === 409);

// a poster hires
const p = new World({ issuer }); await p.signup('ts-poster');
const job = { title: 'Check if this cafe is open on Sundays', instructions: 'Find the official site and confirm opening hours.', priceNano: 1_000_000_000, proof: 'link' };
await assert.rejects(p.taskPost(job), (e: any) => e instanceof WorldError && e.status === 402);
if (admin) {
  const r = await fetch(issuer + '/admin/credit', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + admin }, body: JSON.stringify({ api_key: (p as any).key, nano: 2_000_000_000 }) });
  assert.equal(r.status, 200);
}
const t = await p.taskPost(job);
assert.equal(t.status, 'open'); assert.equal(t.held_nano, 1_150_000_000);

// the Circle
const feed = (await w.workFeed()).tasks;
assert.ok(feed.some((x: any) => x.id === t.id) && !('poster' in feed[0]));
assert.equal((await w.take(t.id)).status, 'taken');
assert.ok((await w.drop(t.id)).ok); assert.equal((await w.take(t.id)).status, 'taken');
assert.equal((await w.submit(t.id, 'Sunday 9-17, https://cafe.example')).status, 'submitted');
await assert.rejects(w.taskAccept(t.id), (e: any) => e instanceof WorldError && e.status === 404);   // only the poster decides
assert.equal((await p.taskAccept(t.id)).status, 'accepted');
assert.equal((await w.balance()).balance_nano, 1_000_000_000); assert.equal((await w.me()).done, 1);
const rc = await w.receipt(t.id);
assert.equal(rc.task_id, t.id); assert.equal(rc.worker, w.entry.agent_id);

// the number leads back to the worker; public reads need no key
const anon = new World({ issuer });
const n = await anon.number(w.entry.number);
assert.equal(n.agent_id, w.entry.agent_id); assert.equal(n.address, w.entry.address);
await assert.rejects(anon.number('0'), (e: any) => e instanceof WorldError && e.status === 404);
const t2 = await p.taskPost({ title: 'Second task', instructions: 'Find the phone number of the office.', priceNano: 100_000_000 });
await w.take(t2.id); await w.submit(t2.id, 'not found');
assert.equal((await p.taskReject(t2.id, 'incomplete')).status, 'reopened');
assert.equal((await w.me()).rejected, 1);
console.log('ts circle OK: join, Circle, receipt, number, reject');
