// Prints the numbers-collection address for a mayor address with the gateway's TEP-64 content; gateway/test_city.py checks Python matches.
// node numbers_fixture.js <mayor>
const fs = require('fs');
const { beginCell, Cell, Address, contractAddress } = require('@ton/core');
const itemCode = Cell.fromBase64(fs.readFileSync(__dirname + '/contracts/number_item.code.b64', 'utf8').trim());
const collCode = Cell.fromBase64(fs.readFileSync(__dirname + '/contracts/number_collection.code.b64', 'utf8').trim());
const META = 'https://ai.minimalcult.org/v1/numbers/meta/';
const content = beginCell().storeRef(beginCell().storeUint(1, 8).storeBuffer(Buffer.from(META + 'collection.json')).endCell())
  .storeRef(beginCell().storeBuffer(Buffer.from(META)).endCell()).endCell();
const data = beginCell().storeAddress(Address.parse(process.argv[2])).storeUint(101, 64).storeRef(itemCode).storeRef(content).endCell();
console.log(contractAddress(0, { code: collCode, data }).toRawString());
