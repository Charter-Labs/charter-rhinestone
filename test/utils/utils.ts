import { Chain } from 'viem'

import { baseSepolia } from 'viem/chains'

function getForkUrl(chain: Chain) {
  if (chain.id === baseSepolia.id) {
    return 'https://sepolia.base.org'
  }
  throw new Error(`Unsupported chain: ${chain.id}`)
}

export { getForkUrl }
