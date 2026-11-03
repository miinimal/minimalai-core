// TON Agentic Wallet pays a GRAM-402 invoice (R1 proof, sandbox). The contracts are TON Tech's open source
// (github.com/the-ton-tech/agentic-wallet-contract, commit a11ddb7, compiled here with @ton/tolk-js 1.2.0 into
// agentic/*.code.b64 — nothing of that project is executed on our machines beyond the TVM emulator).
// What this proves: an agent holding only the operator key of an agentic wallet can send an ordinary internal transfer
// with a text comment (the GRAM-402 invoice id) to a merchant; the merchant sees a plain op=0 comment message from the
// wallet's own address. That is exactly what the GRAM-402 facilitator already accepts: no change on our side.
// Run: node agentic.test.js
const fs = require('fs');
const assert = require('assert');
const { Blockchain } = require('@ton/sandbox');
const { beginCell, Cell, contractAddress, toNano, internal, storeOutList, SendMode, Dictionary } = require('@ton/core');
const { keyPairFromSeed, sign } = require('@ton/crypto');

const code = (f) => Cell.fromBase64(fs.readFileSync(__dirname + '/agentic/' + f, 'utf8').trim());
const OP_DEPLOY_WALLET = 0x0609e47b, OP_EXTERNAL_SIGNED = 0xbf235204;

(async () => {
  const walletCode = code('agentic_wallet.code.b64'), collCode = code('agentic_collection.code.b64');
  const bc = await Blockchain.create();
  const owner = await bc.treasury('owner'), merchant = await bc.treasury('merchant');
  const operator = keyPairFromSeed(Buffer.alloc(32, 7));
  const opPub = BigInt('0x' + operator.publicKey.toString('hex'));

  // 1. the collection (admin = the owner): storage = admin ^content ^item_code
  const meta = beginCell().storeUint(0, 8).storeDict(Dictionary.empty()).endCell();   // on-chain metadata, empty
  const collInit = { code: collCode, data: beginCell().storeAddress(owner.address).storeRef(meta).storeRef(walletCode).endCell() };
  const coll = contractAddress(0, collInit);
  await owner.send({ to: coll, value: toNano('0.1'), init: collInit, body: beginCell().endCell() });

  // 2. the wallet item: index = hash(owner, origin operator key, deployedByUser); data = index, collection, flags
  const index = BigInt('0x' + beginCell().storeAddress(owner.address).storeUint(opPub, 256).storeBit(true).endCell().hash().toString('hex'));
  const walletInit = { code: walletCode, data: beginCell().storeUint(index, 256).storeAddress(coll).storeBit(true).storeUint(0, 32).storeDict(null).storeMaybeRef(null).endCell() };
  const wallet = contractAddress(0, walletInit);
  const byColl = (await bc.runGetMethod(coll, 'get_nft_address_by_index', [{ type: 'int', value: index }])).stackReader.readAddress();
  assert.ok(byColl.equals(wallet), 'the collection derives the same wallet address');
  const runtime = beginCell().storeAddress(owner.address).storeMaybeRef(null).storeUint(opPub, 256).storeUint(opPub, 256).storeBit(true).endCell();
  const deployBody = beginCell().storeUint(OP_DEPLOY_WALLET, 32).storeUint(1n, 64).storeRef(runtime).storeUint(0n, 256).endCell();
  const dep = await owner.send({ to: wallet, value: toNano('1'), init: walletInit, body: deployBody, bounce: false });   // the owner funds it: "fund what you risk"
  assert.ok(dep.transactions.some((t) => t.inMessage?.info?.dest?.equals?.(wallet) && t.description?.computePhase?.exitCode === 0), 'wallet deployed by its owner');
  const nft = (await bc.runGetMethod(wallet, 'get_nft_data', [])).stackReader;
  assert.equal(nft.readBigNumber(), -1n); assert.equal(nft.readBigNumber(), index); assert.ok(nft.readAddress().equals(coll)); assert.ok(nft.readAddress().equals(owner.address));
  assert.equal((await bc.runGetMethod(wallet, 'get_public_key', [])).stackReader.readBigNumber(), opPub);
  assert.equal((await bc.runGetMethod(wallet, 'seqno', [])).stackReader.readNumber(), 0);

  // 3. the agent pays an invoice: external request signed by the operator key; one out-action = transfer with a comment
  const comment = 'mai:inv:test-402';
  const out = beginCell().store(storeOutList([{ type: 'sendMsg', mode: SendMode.PAY_GAS_SEPARATELY | SendMode.IGNORE_ERRORS,
    outMsg: internal({ to: merchant.address, value: toNano('0.25'), bounce: false, body: beginCell().storeUint(0, 32).storeStringTail(comment).endCell() }) }])).endCell();
  const validUntil = Math.floor(Date.now() / 1000) + 600;
  const unsigned = beginCell().storeUint(OP_EXTERNAL_SIGNED, 32).storeUint(index, 256).storeUint(validUntil, 32).storeUint(0, 32).storeMaybeRef(out).storeMaybeRef(null).endCell();
  const signed = beginCell().storeSlice(unsigned.beginParse()).storeBuffer(sign(unsigned.hash(), operator.secretKey)).endCell();
  const before = (await bc.getContract(merchant.address)).balance;
  const res = await bc.sendMessage({ info: { type: 'external-in', dest: wallet, importFee: 0n }, body: signed });
  const paid = res.transactions.find((t) => t.inMessage?.info?.dest?.equals?.(merchant.address));
  assert.ok(paid, 'the merchant received a message');
  assert.ok(paid.inMessage.info.src.equals(wallet), 'the sender is the agentic wallet contract itself');
  assert.equal(paid.inMessage.info.value.coins, toNano('0.25'));
  const body = paid.inMessage.body.beginParse();
  assert.equal(body.loadUint(32), 0); assert.equal(body.loadStringTail(), comment);           // a plain text comment, as GRAM-402 wants
  assert.ok((await bc.getContract(merchant.address)).balance - before > toNano('0.249'));   // minus the merchant's own receive gas
  assert.equal((await bc.runGetMethod(wallet, 'seqno', [])).stackReader.readNumber(), 1);

  // 4. a replay or a stranger's key is refused; the owner can still withdraw with a plain internal message? (owner powers are
  //    internal-message based; here: the stranger's signature fails, the replayed seqno fails)
  await assert.rejects(bc.sendMessage({ info: { type: 'external-in', dest: wallet, importFee: 0n }, body: signed }), /./, 'replay rejected');
  const stranger = keyPairFromSeed(Buffer.alloc(32, 9));
  const unsigned2 = beginCell().storeUint(OP_EXTERNAL_SIGNED, 32).storeUint(index, 256).storeUint(validUntil, 32).storeUint(1, 32).storeMaybeRef(out).storeMaybeRef(null).endCell();
  const bad = beginCell().storeSlice(unsigned2.beginParse()).storeBuffer(sign(unsigned2.hash(), stranger.secretKey)).endCell();
  await assert.rejects(bc.sendMessage({ info: { type: 'external-in', dest: wallet, importFee: 0n }, body: bad }), /./, 'foreign key rejected');
  console.log(`AGENTIC OK: wallet ${wallet.toString()} paid 0.25 with comment "${comment}" to the merchant from its own address; replay and foreign key refused`);
})().catch((e) => { console.error(e); process.exit(1); });
