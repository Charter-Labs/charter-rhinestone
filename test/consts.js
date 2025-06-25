"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MOCK_API_KEY = exports.passkeyAccount = exports.accountD = exports.accountC = exports.accountB = exports.accountA = void 0;
const account_abstraction_1 = require("viem/account-abstraction");
const accounts_1 = require("viem/accounts");
const accountA = (0, accounts_1.privateKeyToAccount)('0x2be89d993f98bbaab8b83f1a2830cb9414e19662967c7ba2a0f43d2a9125bd6d');
exports.accountA = accountA;
const accountB = (0, accounts_1.privateKeyToAccount)('0x39e2fec1a04c088f939d81de8f1abebdebf899a6cfb9968f9b663a7afba8301b');
exports.accountB = accountB;
const accountC = (0, accounts_1.privateKeyToAccount)('0xb63c74af219a3949cf95f5e3a3d20b0137425de053bb03e5cc0f46fe0d19f22f');
exports.accountC = accountC;
const accountD = (0, accounts_1.privateKeyToAccount)('0xa4aba81871b7b51fff56bfe441ea7f9a4879dd4bc8ce8c15fdb06dc92e63d1d7');
exports.accountD = accountD;
const passkeyAccount = (0, account_abstraction_1.toWebAuthnAccount)({
    credential: {
        id: '9IwX9n6cn-l9SzqFzfQXvDHRuTM',
        publicKey: '0x580a9af0569ad3905b26a703201b358aa0904236642ebe79b22a19d00d3737637d46f725a5427ae45a9569259bf67e1e16b187d7b3ad1ed70138c4f0409677d1',
    },
});
exports.passkeyAccount = passkeyAccount;
const MOCK_API_KEY = 'MOCK_KEY';
exports.MOCK_API_KEY = MOCK_API_KEY;
