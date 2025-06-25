import { describe, expect, it, beforeAll } from 'vitest'
import { privateKeyToAccount } from 'viem/accounts'
import { baseSepolia } from 'viem/chains'
import { createPublicClient, http } from 'viem'
import { setupOrchestratorMock } from './orchestrator'
import { setupViemMock } from './utils/viem'
import { getAnvil } from './utils/anvil'
import { getForkUrl } from './utils/utils'
import { createRhinestoneAccount } from '../src'
import { biconomyImplementationAbi } from './abi/biconomy'
import { ownbleValidatorAbi } from './abi/validators'
import { passkeyAccount } from './consts'

const deployerPrivateKey =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'

const deployerAccount = privateKeyToAccount(deployerPrivateKey)
const sourceChain = baseSepolia
const anvil = getAnvil(sourceChain, getForkUrl(sourceChain))

setupOrchestratorMock()
setupViemMock(anvil, deployerAccount)

describe.sequential('Passkey Nexus Deployment', () => {
  beforeAll(async () => {
    await anvil.start()
  })

  it(
    'should deploy a Nexus account with WebAuthn validator',
    { timeout: 20_000 },
    async () => {
      const rhinestoneApiKey = ''

      const rhinestoneAccount = await createRhinestoneAccount({
        account: { type: 'nexus' },
        owners: { type: 'passkey', account: passkeyAccount },
        rhinestoneApiKey,
        deployerAccount,
      })

      console.log('rhinestoneAccount', rhinestoneAccount)

      // Deploy the account directly (EOA deployment)
      await rhinestoneAccount.deploy(sourceChain)

      // Verify account code exists after deployment
      const publicClient = createPublicClient({ chain: sourceChain, transport: http() })
      const code = await publicClient.getCode({ address: rhinestoneAccount.getAddress() })
      expect(code).not.toBeUndefined()
      expect(code).toMatch(/^0x[0-9a-fA-F]+$/)

      // Check that WebAuthnValidator is installed
      const SENTINEL_ADDRESS = '0x0000000000000000000000000000000000000001'
      const WEBAUTHN_VALIDATOR_ADDRESS = '0xb9E9CcF81464482897c687Dc876606961C547A77'
      const validatorList = await publicClient.readContract({
        address: rhinestoneAccount.getAddress(),
        abi: biconomyImplementationAbi,
        functionName: 'getValidatorsPaginated',
        args: [SENTINEL_ADDRESS, 10n],
      })
      const validators = (validatorList[0] as string[]).filter(v => v !== SENTINEL_ADDRESS)
      expect(validators).toEqual([WEBAUTHN_VALIDATOR_ADDRESS])

      // Check threshold for passkey account
      const threshold = await publicClient.readContract({
        address: WEBAUTHN_VALIDATOR_ADDRESS,
        abi: ownbleValidatorAbi,
        functionName: 'threshold',
        args: [rhinestoneAccount.getAddress()],
      })
      expect(threshold).toEqual(1n)
    },
  )
})