import type { Address, Chain, Hex } from 'viem'
import { UserOperationReceipt } from 'viem/account-abstraction'
import {
  deploy as deployInternal,
  getAddress as getAddressInternal,
  deploySource as deploySourceInternal
} from './accounts'
import {
  addOwner,
  changeThreshold,
  disableEcdsa,
  disablePasskeys,
  enableEcdsa,
  enablePasskeys,
  encodeSmartSessionSignature,
  recover,
  removeOwner,
  setUpRecovery,
  trustAttester,
} from './actions'
import type { TransactionResult } from './execution'
import {
  getMaxSpendableAmount as getMaxSpendableAmountInternal,
  getPortfolio as getPortfolioInternal,
  sendTransaction as sendTransactionInternal,
  waitForExecution as waitForExecutionInternal,
} from './execution'
import {
  getSessionDetails as getSessionDetailsInternal,
  SessionDetails,
} from './execution/smart-session'
import {
  BundleData,
  PreparedTransactionData,
  prepareTransaction as prepareTransactionInternal,
  SignedTransactionData,
  signTransaction as signTransactionInternal,
  submitTransaction as submitTransactionInternal,
} from './execution/utils'
import {
  areAttestersTrusted as areAttestersTrustedInternal,
  getOwners as getOwnersInternal,
  getValidators as getValidatorsInternal,
} from './modules'
import type {
  BundleResult,
  BundleStatus,
  MetaIntent,
  MultiChainCompact,
  PostOrderBundleResult,
  SignedMultiChainCompact,
  UserTokenBalance,
} from './orchestrator'
import type {
  Call,
  Execution,
  RhinestoneAccountConfig,
  Session,
  Transaction,
} from './types'

interface RhinestoneAccount {
  config: RhinestoneAccountConfig
  deploy: (chain: Chain, session?: Session) => Promise<void>
  prepareTransaction: (
    transaction: Transaction,
  ) => Promise<PreparedTransactionData>
  signTransaction: (
    preparedTransaction: PreparedTransactionData,
  ) => Promise<SignedTransactionData>
  submitTransaction: (
    signedTransaction: SignedTransactionData,
  ) => Promise<TransactionResult>
  sendTransaction: (transaction: Transaction) => Promise<TransactionResult>
  waitForExecution: (
    result: TransactionResult,
    acceptsPreconfirmations?: boolean,
  ) => Promise<BundleResult | UserOperationReceipt>
  getAddress: () => Address
  getPortfolio: (onTestnets?: boolean) => Promise<UserTokenBalance[]>
  getMaxSpendableAmount: (
    chain: Chain,
    tokenAddress: Address,
    gasUnits: bigint,
  ) => Promise<bigint>
  deploySource: (chain: Chain) => Promise<void>
  getSessionDetails: (
    sessions: Session[],
    sessionIndex: number,
    signature?: Hex,
  ) => Promise<SessionDetails>
  areAttestersTrusted: (chain: Chain) => Promise<boolean>
  getOwners: (chain: Chain) => Promise<{
    accounts: Address[]
    threshold: number
  } | null>
  getValidators: (chain: Chain) => Promise<Address[]>
}

/**
 * Initialize a Rhinestone account
 * Note: accounts are deployed onchain only when the first transaction is sent.
 * @param config Account config (e.g. implementation vendor, owner signers, smart sessions)
 * @returns account
 */
async function createRhinestoneAccount(
  config: RhinestoneAccountConfig,
): Promise<RhinestoneAccount> {
  function deploy(chain: Chain, session?: Session) {
    return deployInternal(config, chain, session)
  }

  function prepareTransaction(transaction: Transaction) {
    return prepareTransactionInternal(config, transaction)
  }

  function signTransaction(preparedTransaction: PreparedTransactionData) {
    return signTransactionInternal(config, preparedTransaction)
  }

  function submitTransaction(signedTransaction: SignedTransactionData) {
    return submitTransactionInternal(config, signedTransaction)
  }

  /**
   * Sign and send a transaction
   * @param transaction Transaction to send
   * @returns transaction result object (a bundle ID or a UserOp hash)
   */
  function sendTransaction(transaction: Transaction) {
    return sendTransactionInternal(config, transaction)
  }

  /**
   * Wait for the transaction execution onchain
   * @param result transaction result object
   * @param acceptsPreconfirmations whether to accept preconfirmations from relayers before the transaction lands onchain (enabled by default)
   * @returns bundle result or a UserOp receipt
   */
  function waitForExecution(
    result: TransactionResult,
    acceptsPreconfirmations = true,
  ) {
    return waitForExecutionInternal(config, result, acceptsPreconfirmations)
  }

  /**
   * Get account address
   * @returns Address of the smart account
   */
  function getAddress() {
    return getAddressInternal(config)
  }

  /**
   * Get account portfolio
   * @param onTestnets Whether to query the testnet balances (default is `false`)
   * @returns Account balances
   */
  function getPortfolio(onTestnets = false) {
    return getPortfolioInternal(config, onTestnets)
  }

  /**
   * Get the maximum spendable token amount on the target chain
   * @param chain Target chain
   * @param tokenAddress Token address (on the target chain)
   * @param gasUnits Gas cost estimate for the transaction execution
   * @returns Maximum spendable amount in absolute units
   */
  function getMaxSpendableAmount(
    chain: Chain,
    tokenAddress: Address,
    gasUnits: bigint,
  ) {
    return getMaxSpendableAmountInternal(config, chain, tokenAddress, gasUnits)
  }

  function deploySource(chain: Chain) {
    return deploySourceInternal(chain, config)
  }

  function getSessionDetails(
    sessions: Session[],
    sessionIndex: number,
    signature?: Hex,
  ) {
    return getSessionDetailsInternal(config, sessions, sessionIndex, signature)
  }

  function areAttestersTrusted(chain: Chain) {
    const account = getAddress()
    return areAttestersTrustedInternal(account, chain)
  }

  function getOwners(chain: Chain) {
    const account = getAddress()
    return getOwnersInternal(account, chain)
  }

  function getValidators(chain: Chain) {
    const accountType = config.account?.type || 'nexus'
    const account = getAddress()
    return getValidatorsInternal(accountType, account, chain)
  }

  return {
    config,
    deploy,
    prepareTransaction,
    signTransaction,
    submitTransaction,
    sendTransaction,
    waitForExecution,
    getAddress,
    getPortfolio,
    getMaxSpendableAmount,
    deploySource,
    getSessionDetails,
    areAttestersTrusted,
    getOwners,
    getValidators,
  }
}

export {
  createRhinestoneAccount,
  addOwner,
  changeThreshold,
  disableEcdsa,
  disablePasskeys,
  enableEcdsa,
  enablePasskeys,
  recover,
  removeOwner,
  setUpRecovery,
  encodeSmartSessionSignature,
  trustAttester,
}
export type {
  RhinestoneAccount,
  BundleStatus,
  Session,
  Call,
  Execution,
  MetaIntent,
  MultiChainCompact,
  PostOrderBundleResult,
  SignedMultiChainCompact,
  BundleData,
  PreparedTransactionData,
  SignedTransactionData,
  TransactionResult,
}
