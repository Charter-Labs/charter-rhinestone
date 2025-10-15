import {
  type Address,
  type Chain,
  createPublicClient,
  encodeFunctionData,
  type Hex,
} from 'viem'

import { createTransport } from '../../accounts/utils'
import type { Call, ProviderConfig } from '../../types'
import { WEBAUTHN_VALIDATOR_ADDRESS } from './core'

/**
 * WebAuthn Validator Contract ABI - Contains the functions we need to interact with
 */
const WEBAUTHN_VALIDATOR_ABI = [
  {
    type: 'function',
    name: 'generateCredentialId',
    inputs: [
      { name: 'pubKeyX', type: 'uint256' },
      { name: 'pubKeyY', type: 'uint256' },
      { name: 'account', type: 'address' },
    ],
    outputs: [{ name: '', type: 'bytes32' }],
    stateMutability: 'pure',
  },
  {
    type: 'function',
    name: 'getCredentialIds',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ name: 'credentialsIds', type: 'bytes32[]' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'hasCredentialById',
    inputs: [
      { name: 'credentialId', type: 'bytes32' },
      { name: 'account', type: 'address' },
    ],
    outputs: [{ name: 'exists', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'hasCredential',
    inputs: [
      { name: 'pubKeyX', type: 'uint256' },
      { name: 'pubKeyY', type: 'uint256' },
      { name: 'account', type: 'address' },
    ],
    outputs: [{ name: 'exists', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'addCredential',
    inputs: [
      { name: 'pubKeyX', type: 'uint256' },
      { name: 'pubKeyY', type: 'uint256' },
      { name: 'requireUV', type: 'bool' },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'removeCredential',
    inputs: [
      { name: 'pubKeyX', type: 'uint256' },
      { name: 'pubKeyY', type: 'uint256' },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'setThreshold',
    inputs: [{ name: '_threshold', type: 'uint256' }],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'getCredentialInfo',
    inputs: [
      { name: 'credentialId', type: 'bytes32' },
      { name: 'account', type: 'address' },
    ],
    outputs: [
      { name: 'pubKeyX', type: 'uint256' },
      { name: 'pubKeyY', type: 'uint256' },
      { name: 'requireUV', type: 'bool' },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'threshold',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
  },
] as const

/**
 * Generates a deterministic credential ID for a WebAuthn credential
 * @param pubKeyX X coordinate of the public key
 * @param pubKeyY Y coordinate of the public key
 * @param accountAddress Address of the account
 * @param chain Chain to query on
 * @param provider Optional provider configuration
 * @returns Promise resolving to the credential ID
 */
async function generateCredentialId(
  pubKeyX: bigint,
  pubKeyY: bigint,
  accountAddress: Address,
  chain: Chain,
  provider?: ProviderConfig,
): Promise<Hex> {
  const publicClient = createPublicClient({
    chain,
    transport: createTransport(chain, provider),
  })

  const result = await publicClient.readContract({
    abi: WEBAUTHN_VALIDATOR_ABI,
    address: WEBAUTHN_VALIDATOR_ADDRESS,
    functionName: 'generateCredentialId',
    args: [pubKeyX, pubKeyY, accountAddress],
  })

  return result as Hex
}

/**
 * Gets all credential IDs for an account
 * @param accountAddress Address of the account
 * @param chain Chain to query on
 * @param provider Optional provider configuration
 * @returns Promise resolving to array of credential IDs
 */
async function getCredentialIds(
  accountAddress: Address,
  chain: Chain,
  provider?: ProviderConfig,
): Promise<Hex[]> {
  const publicClient = createPublicClient({
    chain,
    transport: createTransport(chain, provider),
  })

  const result = await publicClient.readContract({
    abi: WEBAUTHN_VALIDATOR_ABI,
    address: WEBAUTHN_VALIDATOR_ADDRESS,
    functionName: 'getCredentialIds',
    args: [accountAddress],
  })

  return result as Hex[]
}

/**
 * Checks if a credential exists by its ID
 * @param credentialId The credential ID to check
 * @param accountAddress Address of the account
 * @param chain Chain to query on
 * @param provider Optional provider configuration
 * @returns Promise resolving to whether the credential exists
 */
async function hasCredentialById(
  credentialId: Hex,
  accountAddress: Address,
  chain: Chain,
  provider?: ProviderConfig,
): Promise<boolean> {
  const publicClient = createPublicClient({
    chain,
    transport: createTransport(chain, provider),
  })

  const result = await publicClient.readContract({
    abi: WEBAUTHN_VALIDATOR_ABI,
    address: WEBAUTHN_VALIDATOR_ADDRESS,
    functionName: 'hasCredentialById',
    args: [credentialId, accountAddress],
  })

  return result as boolean
}

/**
 * Checks if a credential exists by its public key coordinates
 * @param pubKeyX X coordinate of the public key
 * @param pubKeyY Y coordinate of the public key
 * @param accountAddress Address of the account
 * @param chain Chain to query on
 * @param provider Optional provider configuration
 * @returns Promise resolving to whether the credential exists
 */
async function hasCredential(
  pubKeyX: bigint,
  pubKeyY: bigint,
  accountAddress: Address,
  chain: Chain,
  provider?: ProviderConfig,
): Promise<boolean> {
  const publicClient = createPublicClient({
    chain,
    transport: createTransport(chain, provider),
  })

  const result = await publicClient.readContract({
    abi: WEBAUTHN_VALIDATOR_ABI,
    address: WEBAUTHN_VALIDATOR_ADDRESS,
    functionName: 'hasCredential',
    args: [pubKeyX, pubKeyY, accountAddress],
  })

  return result as boolean
}

/**
 * Creates a transaction call to add a WebAuthn credential to an account
 * @param pubKeyX X coordinate of the public key
 * @param pubKeyY Y coordinate of the public key
 * @param requireUV Whether user verification (biometrics/PIN) is required
 * @returns Call object for adding the credential
 */
function addCredential(
  pubKeyX: bigint,
  pubKeyY: bigint,
  requireUV = false,
): Call {
  return {
    to: WEBAUTHN_VALIDATOR_ADDRESS,
    value: 0n,
    data: encodeFunctionData({
      abi: WEBAUTHN_VALIDATOR_ABI,
      functionName: 'addCredential',
      args: [pubKeyX, pubKeyY, requireUV],
    }),
  }
}

/**
 * Creates a transaction call to remove a WebAuthn credential from an account
 * @param pubKeyX X coordinate of the public key
 * @param pubKeyY Y coordinate of the public key
 * @returns Call object for removing the credential
 */
function removeCredential(pubKeyX: bigint, pubKeyY: bigint): Call {
  return {
    to: WEBAUTHN_VALIDATOR_ADDRESS,
    value: 0n,
    data: encodeFunctionData({
      abi: WEBAUTHN_VALIDATOR_ABI,
      functionName: 'removeCredential',
      args: [pubKeyX, pubKeyY],
    }),
  }
}

/**
 * Creates a transaction call to set the threshold for WebAuthn validation
 * @param threshold Number of required signatures for validation
 * @returns Call object for setting the threshold
 */
function setThreshold(threshold: number): Call {
  return {
    to: WEBAUTHN_VALIDATOR_ADDRESS,
    value: 0n,
    data: encodeFunctionData({
      abi: WEBAUTHN_VALIDATOR_ABI,
      functionName: 'setThreshold',
      args: [BigInt(threshold)],
    }),
  }
}

/**
 * Gets detailed information about a credential
 * @param credentialId The credential ID to query
 * @param accountAddress Address of the account
 * @param chain Chain to query on
 * @param provider Optional provider configuration
 * @returns Promise resolving to credential details
 */
async function getCredentialInfo(
  credentialId: Hex,
  accountAddress: Address,
  chain: Chain,
  provider?: ProviderConfig,
): Promise<{
  pubKeyX: bigint
  pubKeyY: bigint
  requireUV: boolean
}> {
  const publicClient = createPublicClient({
    chain,
    transport: createTransport(chain, provider),
  })

  const result = await publicClient.readContract({
    abi: WEBAUTHN_VALIDATOR_ABI,
    address: WEBAUTHN_VALIDATOR_ADDRESS,
    functionName: 'getCredentialInfo',
    args: [credentialId, accountAddress],
  })

  const [pubKeyX, pubKeyY, requireUV] = result as [bigint, bigint, boolean]
  return { pubKeyX, pubKeyY, requireUV }
}

/**
 * Gets the current threshold for an account
 * @param accountAddress Address of the account
 * @param chain Chain to query on
 * @param provider Optional provider configuration
 * @returns Promise resolving to the current threshold
 */
async function getThreshold(
  accountAddress: Address,
  chain: Chain,
  provider?: ProviderConfig,
): Promise<number> {
  const publicClient = createPublicClient({
    chain,
    transport: createTransport(chain, provider),
  })

  const result = await publicClient.readContract({
    abi: WEBAUTHN_VALIDATOR_ABI,
    address: WEBAUTHN_VALIDATOR_ADDRESS,
    functionName: 'threshold',
    args: [accountAddress],
  })

  return Number(result as bigint)
}

/**
 * Gets all credentials for an account with their detailed information
 * @param accountAddress Address of the account
 * @param chain Chain to query on
 * @param provider Optional provider configuration
 * @returns Promise resolving to array of credentials with their details
 */
async function getCredentials(
  accountAddress: Address,
  chain: Chain,
  provider?: ProviderConfig,
): Promise<
  Array<{
    credentialId: Hex
    pubKeyX: bigint
    pubKeyY: bigint
    requireUV: boolean
  }>
> {
  // First get all credential IDs
  const credentialIds = await getCredentialIds(accountAddress, chain, provider)

  // Then get detailed info for each credential
  const credentials = await Promise.all(
    credentialIds.map(async (credentialId) => {
      const info = await getCredentialInfo(
        credentialId,
        accountAddress,
        chain,
        provider,
      )
      return {
        credentialId,
        ...info,
      }
    }),
  )

  return credentials
}

export {
  generateCredentialId,
  getCredentialIds,
  hasCredentialById,
  hasCredential,
  addCredential,
  removeCredential,
  setThreshold,
  getCredentialInfo,
  getThreshold,
  getCredentials,
  WEBAUTHN_VALIDATOR_ABI,
}
