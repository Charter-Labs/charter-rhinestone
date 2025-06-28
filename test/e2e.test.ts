import { privateKeyToAccount } from 'viem/accounts'
import { baseSepolia } from 'viem/chains'
import { beforeAll, describe } from 'vitest'

import './utils/polyfill'

import { runBundlesTestCases } from './bundles'
import { runPasskeyDeploymentTestCases } from './passkey-deployment.test'
import { getAnvil } from './utils/anvil'
import { getForkUrl } from './utils/utils'
import { setupOrchestratorMock } from './orchestrator'
import { setupViemMock } from './utils/viem'

const deployerPrivateKey =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const deployerAccount = privateKeyToAccount(deployerPrivateKey)

const sourceChain = baseSepolia
const anvil = getAnvil(sourceChain, getForkUrl(sourceChain))

setupOrchestratorMock()
setupViemMock(anvil, deployerAccount)

describe.sequential('E2E Tests', () => {
  beforeAll(async () => {
    await anvil.start()
  })

   runPasskeyDeploymentTestCases()
  // runBundlesTestCases()
})
