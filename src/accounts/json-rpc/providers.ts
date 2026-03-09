import * as sharedConfigs from '@rhinestone/shared-configs'

import type { SupportedChain } from '../../orchestrator'

function getAlchemyUrl(chainId: SupportedChain, apiKey: string): string {
  const providers =
    (sharedConfigs as any).providerRegistry ||
    (sharedConfigs as any).ProviderRegistry
  const urlTemplate = (providers as any).Alchemy.url_template as string
  const mapping = (providers as any).Alchemy
    .chain_mapping as Record<number, string>
  const chainParam = mapping[chainId]
  if (!chainParam) {
    throw new Error(`Unsupported chain: ${chainId}`)
  }
  return urlTemplate
    .replace('{{chain_param}}', chainParam)
    .split('${ALCHEMY_API_KEY}')
    .join(apiKey)
}

function getCustomUrl(
  chainId: number,
  urls: Record<number, string>,
): string | undefined {
  return urls[chainId]
}

export { getAlchemyUrl, getCustomUrl }
