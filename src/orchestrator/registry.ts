import * as shared from '@rhinestone/shared-configs'
import type { Address, Chain } from 'viem'
import { isAddress } from 'viem'
import {
  arbitrum,
  arbitrumSepolia,
  base,
  baseSepolia,
  mainnet,
  optimism,
  optimismSepolia,
  polygon,
  sepolia,
  soneium,
  sonic,
} from 'viem/chains'
import type { TokenSymbol } from '../types'
import { UnsupportedChainError, UnsupportedTokenError } from './error'
import type { SupportedChain, TokenConfig } from './types'

function getSupportedChainIds(): number[] {
  const arr = ((shared as any).chains ?? []) as any[]
  return arr.map((c) => (c as any).id as number)
}

function getChainEntry(chainId: number) {
  const registry =
    (shared as any).chainRegistry || (shared as any).ChainRegistry
  return registry[chainId.toString()]
}

function getWethAddress(chain: Chain): Address {
  const chainEntry = getChainEntry(chain.id)
  if (!chainEntry) {
    throw new UnsupportedChainError(chain.id)
  }

  const wethToken = chainEntry.tokens.find(
    (token: any) => token.symbol === 'WETH',
  )
  if (!wethToken) {
    throw new UnsupportedTokenError('WETH', chain.id)
  }

  return wethToken.address
}

function getTokenSymbol(tokenAddress: Address, chainId: number): string {
  const chainEntry = getChainEntry(chainId)
  if (!chainEntry) {
    throw new UnsupportedChainError(chainId)
  }

  const token = chainEntry.tokens.find(
    (t: any) =>
      (t.address as string).toLowerCase() === tokenAddress.toLowerCase(),
  )

  if (!token) {
    throw new UnsupportedTokenError(tokenAddress, chainId)
  }

  return token.symbol
}

function getTokenAddress(
  token: TokenSymbol | Address,
  chainId: number,
): Address {
  if (!isChainIdSupported(chainId)) {
    throw new UnsupportedChainError(chainId)
  }
  if (typeof token === 'string' && isAddress(token)) return token as Address
  const tokens = getSupportedTokens(chainId)
  const found = tokens.find((x: TokenConfig) => x.symbol === token)
  if (!found) throw new UnsupportedTokenError(token as string, chainId)
  return found.address
}

function isChainIdSupported(chainId: number): chainId is SupportedChain {
  const arr = ((shared as any).chains ?? []) as any[]
  const chainIds = arr.map((c) => (c as any).id as number)
  return chainIds.includes(chainId)
}

function getChainById(chainId: number): Chain {
  const map: Record<number, Chain> = {
    [mainnet.id]: mainnet,
    [sepolia.id]: sepolia,
    [base.id]: base,
    [baseSepolia.id]: baseSepolia,
    [arbitrum.id]: arbitrum,
    [arbitrumSepolia.id]: arbitrumSepolia,
    [optimism.id]: optimism,
    [optimismSepolia.id]: optimismSepolia,
    [polygon.id]: polygon,
    [soneium.id]: soneium,
    [sonic.id]: sonic,
  }
  if (!isChainIdSupported(chainId)) {
    throw new UnsupportedChainError(chainId)
  }
  return map[chainId]
}

function isTestnet(chainId: number): boolean {
  const chain = getChainById(chainId)
  return chain.testnet ?? false
}

function isTokenAddressSupported(address: Address, chainId: number): boolean {
  const chainEntry = getChainEntry(chainId)
  if (!chainEntry) {
    return false
  }

  return chainEntry.tokens.some(
    (token: any) =>
      (token.address as string).toLowerCase() === address.toLowerCase(),
  )
}

function getSupportedTokens(chainId: number): TokenConfig[] {
  if (!isChainIdSupported(chainId)) {
    throw new UnsupportedChainError(chainId)
  }
  const entry = getChainEntry(chainId)
  return (entry.tokens as any[]).map((t: any) => ({
    symbol: t.symbol as string,
    address: t.address as Address,
    decimals: t.decimals as number,
  }))
}

function getDefaultAccountAccessList(onTestnets?: boolean) {
  const supportedChainIds = getSupportedChainIds()
  const filteredChainIds = supportedChainIds.filter((chainId) => {
    try {
      return isTestnet(chainId) === !!onTestnets
    } catch {
      return false
    }
  })

  return {
    chainIds: filteredChainIds,
  }
}

function resolveTokenAddress(
  token: TokenSymbol | Address,
  chainId: number,
): Address {
  if (isAddress(token)) {
    return token
  }
  return getTokenAddress(token, chainId)
}

export {
  getTokenSymbol,
  getTokenAddress,
  getWethAddress,
  getChainById,
  getSupportedTokens,
  getSupportedChainIds,
  isTestnet,
  isTokenAddressSupported,
  getDefaultAccountAccessList,
  resolveTokenAddress,
}
