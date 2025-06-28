import { createPublicClient, http, parseEther, keccak256, encodeAbiParameters } from 'viem'
import { generatePrivateKey } from 'viem/accounts'
import { privateKeyToAccount } from 'viem/accounts'
import { baseSepolia } from 'viem/chains'
import { describe, expect, it } from 'vitest'

import { createRhinestoneAccount } from '../src'

import './utils/polyfill'
import { getAnvil } from './utils/anvil'
import { getForkUrl } from './utils/utils'
import { MOCK_API_KEY, passkeyAccount } from './consts'
import { setupOrchestratorMock } from './orchestrator'
import { setupViemMock } from './utils/viem'

const deployerPrivateKey =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const deployerAccount = privateKeyToAccount(deployerPrivateKey)

const sourceChain = baseSepolia
const anvil = getAnvil(sourceChain, getForkUrl(sourceChain))

setupOrchestratorMock()
setupViemMock(anvil, deployerAccount)

export function runBundlesTestCases() {
  describe('Bundles', () => {
    describe('Same-Chain', () => {
      it(
        'should deploy an account using an EOA',
        {
          timeout: 10_000,
        },
        async () => {
          const ownerPrivateKey = generatePrivateKey()
          const ownerAccount = privateKeyToAccount(ownerPrivateKey)
          const receiverPrivateKey = generatePrivateKey()
          const receiverAccount = privateKeyToAccount(receiverPrivateKey)
          const rhinestoneApiKey = MOCK_API_KEY

          const rhinestoneAccount = await createRhinestoneAccount({
            account: {
              type: 'nexus',
            },
            owners: {
              type: 'ecdsa',
              accounts: [ownerAccount],
            },
            rhinestoneApiKey,
            deployerAccount,
          })

          // Create a proper publicClient instance
          const publicClient = createPublicClient({
            chain: sourceChain,
            transport: http(),
          })

          // Fund the account
          const client = anvil.getWalletClient(deployerAccount)
          await client.sendTransaction({
            to: rhinestoneAccount.getAddress(),
            value: parseEther('1'),
          })

          // Check the account is funded
          const balanceBefore = await publicClient.getBalance({
            address: rhinestoneAccount.getAddress(),
          })
          expect(balanceBefore).toEqual(parseEther('1'))

          await rhinestoneAccount.sendTransaction({
            chain: sourceChain,
            calls: [
              {
                to: receiverAccount.address,
                data: '0x',
                value: parseEther('0.1'),
              },
            ],
            tokenRequests: [],
          })

          // // Check the account balance after transaction
          // const balanceAfter = await publicClient.getBalance({
          //   address: rhinestoneAccount.getAddress(),
          // })
          // // Account balance should be less than 0.9 ETH due to gas costs
          // expect(balanceAfter).toBeLessThan(parseEther('0.9'))

          // const receiverBalance = await publicClient.getBalance({
          //   address: receiverAccount.address,
          // })
          // expect(receiverBalance).toEqual(parseEther('0.1'))
        },
      )

      it(
        'should deploy an account using a Passkey',
        {
          timeout: 10_000,
        },
        async () => {
          const rhinestoneApiKey = MOCK_API_KEY
          const receiverPrivateKey = generatePrivateKey()
          const receiverAccount = privateKeyToAccount(receiverPrivateKey)
          const webAuthnAccount = passkeyAccount
          const pubKeyHex = webAuthnAccount.publicKey
          const rawPubKey = pubKeyHex.slice(2)
          const pubKeyXHex = '0x' + rawPubKey.slice(0, 64)
          const pubKeyYHex = '0x' + rawPubKey.slice(64)
          const rhinestoneAccountPasskey = await createRhinestoneAccount({
            account: { type: 'nexus' },
            owners: { type: 'passkey', account: webAuthnAccount, credentialIds: [] },
            rhinestoneApiKey,
            deployerAccount,
          })
          const accountAddressPasskey = rhinestoneAccountPasskey.getAddress()
          const credentialId = keccak256(
            encodeAbiParameters(
              [
                { name: 'pubKeyX',    type: 'uint256' },
                { name: 'pubKeyY',    type: 'uint256' },
                { name: 'requireUV',  type: 'bool'    },
                { name: 'account',    type: 'address' },
              ],
              [BigInt(pubKeyXHex), BigInt(pubKeyYHex), false, accountAddressPasskey],
            ),
          )
          rhinestoneAccountPasskey.config.owners = {
            type: 'passkey',
            account: webAuthnAccount,
            credentialIds: [credentialId],
          }

          // Fund the passkey account
          const client = anvil.getWalletClient(deployerAccount)
          await client.sendTransaction({
            to: accountAddressPasskey,
            value: parseEther('1'),
          })

          // Send transaction using passkey
          await rhinestoneAccountPasskey.sendTransaction({
            chain: sourceChain,
            calls: [
              {
                to: receiverAccount.address,
                data: '0x',
                value: parseEther('0.1'),
              },
            ],
            tokenRequests: [],
          })
        },
      )
    })
  })
}
