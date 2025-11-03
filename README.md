# Account Abstraction DID (did:aa:eip155:...).  Verifiable Credentials, Verifiable Presentation  leveraging EIP-1271


# Account Abstraction DID

## Core Capabilities

- **Agent Interoperability**  
  Enables subject and issuer identification for Verifiable Credential (VC) and Verifiable Presentation (VP) communications between agents.

- **DIDComm-based Agent Interactions**  
  Supports DIDComm messaging across Model Context Protocol (MCP) agents.

- **Multi-Signer Management**  
  Enables organizations to distribute DID control across multiple authorized signers, with configurable thresholds and permissions for different operations.

- **Simplified UI**  
  Utilizes gasless transactions, batching, and sponsored on-chain invocation via Paymasters.

- **Delegation and Role Access**  
  Simplifies delegation and role-based permissions through Account Abstraction-based delegation.

- **Key Rotation**  
  Allows key rotation without losing the DID, as DIDs are not tied to a single EOA (Externally Owned Account), eliminating the need for updates or re-publication.

- **Zero-Knowledge and MPC Integration**  
  Can be plugged into ZK circuits and Multi-Party Computation (MPC) wallets.

---
## Implementation

### DID Method Specification

The Account Abstraction DID method follows the format:
```
did:aa:eip155:{chainId}:{smartAccountAddress}
```

### Core Components

- **Smart Account Contract**  
  Implements ERC-4337 and ERC-1271 for signature validation and account abstraction.

- **DID Resolver**  
  Resolves DID documents by querying on-chain state and metadata.

- **Signature Provider**  
  Handles EIP-712 typed data signing through delegated EOAs.  EOA signs on behalf of the Smart Account.

### Core Infrastructure

- **Ethereum DID Registry**  
  The ethr-did-registry maintains core identity records. This forms the base layer of the DID Document with minimal verification and authentication data.

  **Ethereum Attestation Service**
  The ethereum attestation service maintains core metadata and delegation records

- **Signature Verification**  
  Validates VC, VP, and message signatures through ERC-1271's `isValidSignature`. No public key is required in the DID Document as verification happens on-chain.

- **DID Document Structure**  
  The complete AA DID Document combines data from multiple sources:

  1. Base Layer (from ethr-did-registry):
  ```json
  {
    "@context": "https://w3id.org/did/v1",
    "id": "did:ethr:0x5:0xAaSmartWallet123...",
    "verificationMethod": [
      {
        "id": "did:ethr:0x5:0xAaSmartWallet123#controller",
        "type": "EcdsaSecp256k1RecoveryMethod2020",
        "controller": "did:ethr:0x5:0xAaSmartWallet123",
        "blockchainAccountId": "eip155:5:0xAaSmartWallet123"
      }
    ],
    "authentication": [
      "did:ethr:0x5:0xAaSmartWallet123#controller"
    ]
  }
  ```

  2. Extended Properties (from EAS):
  - Delegation relationships
  - Service endpoints
  - Organization metadata
  - Role-based permissions
  - Custom attestations

  ```json
  {
    "capabilityDelegation": [
      {
        "id": "eas:eip155:1:0xEasContract789:0xATTUID123",
        "type": "EASDelegation2024",
        "controller": "did:aa:eip155:1:0xDelegateAgent456",
        "capability": "signVerifiableCredential",
        "easSchema": "0xSchemaUID",
        "attestationUid": "0xATTUID123",
        "easContract": "0xEasContract789",
        "validFrom": 1717800000,
        "validUntil": 1719800000
      }
    ]
  }
  ```

  The DID resolver combines these sources to construct the complete DID Document.

### Account Abstraction Support Capabilities 

- **DID Indexing Layer (Searchable)**

- **Verifiable Credential and Verifiable Presentation**

  Example Verifiable Credential:
  ```json
  {
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "id": "urn:uuid:${uuid}",
    "type": [
      "VerifiableCredential",
      "DIDMetadataCredential"
    ],
    "issuer": "did:aa:eip155:11155111:0xSmartAccountAddress",
    "issuanceDate": "2024-03-20T12:00:00Z",
    "credentialSubject": {
      "id": "did:aa:eip155:11155111:0xSmartAccountAddress",
      "metadata": {
        "category": "Organization",
        "industry": "Healthcare",
        "registeredRegion": "Colorado",
        "website": "https://example.org"
      }
    }
  }
  ```
  **Social Login**
  Allowing users to log in using social authentication mechanisms (e.g., Google, Facebook) alongside their DID-based identifier.

  **Social Recovery**
  Social Recovery: Implementing a recovery mechanism that utilizes social accounts to recover access to the Digital Identity Wallet in case of key loss or compromise.

---
## Demonstration

![Account Abstraction DID Demo](./did-aa-demo.jpg)

## When to Use Account Abstraction-based DIDs

Use Account Abstraction DIDs when:

- You need **organization wallets** or **multi-signature control**.
- You want **social recovery** or **modular signing**.
- You require **gasless onboarding** or **sponsored credentials**.
- You're integrating with **ERC-4337**, **EIP-1271**, or **ZK workflows**.

---

## Signature and Verification Mechanics

- **EIP-712 Delegated Signing**  
  A delegator (typically an EOA) uses `signTypedData` to sign structured data on behalf of a smart account.

- **ERC-1271 Signature Verification**  
  Delegated signatures are verified on-chain using the `isValidSignature` method defined by ERC-1271.

- **Credential and Presentation Validation**  
  Once a VC or VP is signed, it can be validated across agents and on-chain using smart account logic.

- **Decoupled Identity**  
  Subject/Issuer DIDs are linked to account abstraction smart contracts and not tied to a single EOA.

---

## MyOrgWallet Integration

- Ties all attestations to **organizational** and **individual account abstractions**.
- Manages **Account Abstraction DIDs** for organizations and individuals.
- Supports **discovery** of Account Abstraction DID Documents.
- Captures **delegation relationships** between organizations and individuals.
- Registers and maintains **services provided by organizations** in DID Documents.

---

## Why Account Abstraction DIDs Are Not Yet Common

- **Legacy Assumptions**  
  Traditional DID methods (`did:ethr`, `did:web`, `did:key`, `did:peer`) are designed for EOAs with static keys.

- **New Identity Model**  
  Account Abstraction (via ERC-4337) enables smart contracts to act as DIDs without holding private keys.

- **Tooling Gaps**  
  Most DID resolvers and signature verification tools assume direct access to signing keys, which smart contracts do not have.

---

## Veramo Extensions

Planned or ongoing extensions to Veramo include:

- Support for **ERC-4337 smart accounts**.
- Signature and verification support using **ERC-1271**.
- Management of Account Abstraction DIDs, VCs, and VPs within the Veramo agent framework.



## Project Setup

```
cd mcp-aa-did
touch client/.env
touch server/.env

[Add Environment Variables]

git switch caveats-instead-of-permissions

pnpm install
pnpm i --save-dev @types/debug -w
pnpm run build

open http:localhost:5173
cd client
pnpm run dev

open http:localhost:3001
cd server
npx tsx src/index.ts
```

## Features

- Support for `did:aa` (Account Abstraction) DID method
- EIP-1271 signature verification for smart contracts
- Verifiable Credentials and Presentations using EIP-712 typed data
- Integration with Veramo framework
- TypeScript/ESM support

## Project Structure

```
.
├── client/           # Frontend application
├── server/           # Backend server
└── shared/           # Shared TypeScript code
    ├── src/
    │   ├── agents/  # Veramo agent configuration
    │   └── utils/   # Shared utilities and types
```

## Prerequisites

- Node.js v20+
- pnpm (recommended) or npm

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/mcp.git
cd mcp
```

2. Install dependencies:
```bash
pnpm install
```

3. Build the packages:
```bash
pnpm run build
```

## Development

1. Start the development server:
```bash
cd server
npx tsx src/index.ts
```

2. In another terminal, start the client:
```bash
cd client
pnpm dev
```

## Environment Variables

Create a `.env` file in the server directory with the following variables:

```env
OPTIMISM_RPC_URL=your_optimism_rpc_url
ETHEREUM_RPC_URL=your_mainnet_rpc_url
```

## License

MIT


HACKATHON NOTES:

🚀 The Future of Organizational Digital Wallets and Online Trust
Empowering seamless and secure Web3 interactions for organizations

MyOrgWallet.io helps organizations operate and build trust in a world where agent-to-agent communication is outpacing Web2 traffic



MetaMask Dev Cook-Off focus on Identity and OnChain Reputation are essential components of MyOrgWallet.io. Building online organization trust is much bigger then just KYB. The key is that businesses maintain control over building their reputation in a way that is verifiable yet privacy-preserving—enabling them to selectively disclose credible signals while safeguarding sensitive data.

Our solution fully leverages MetaMask DTK, Circle CCTP v2 and LiFi and associated capabilities to:
- Build organization on-chain reputation through verifiable credentials, attestations, and zero knowledge proofs.
- Provide organization explorer via a standardized org trust score
- Provide an MCP agent-to-agent platform standards for establishing trust (did:aa interop)


Why our focus on Money and Chart-Of-Accounts?

This Dev Cook-off focus on money (MetaMask Card, Circle USDC, LiFi) could not have come at a better time for our platform evolution. 

Organizations build trust and loyalty with both customers and third parties by demonstrating the ability to handle money safely, securely, transparently, and credibly. An initial payment or loan is just the beginning of a long-term, trusted relationship. On-chain mechanisms for refunds, loyalty rewards, installment plans, and referral incentives will define the next generation of Web3 experiences—where financial interactions are not just transactions, but trust-building moments.

Our README page presents videos and implementations that directly address capabilities talked about in all 5 Tracks. We believe our solutions directly meet the true spirit of these tracks.

https://github.com/RichCanvas3/MyOrgWallet
https://github.com/RichCanvas3/mcp-aa-did


We have worked hard to demonstrate the power of these core technologies within real world use-cases.

myOrgWallet use-cases incorporating USDC single-chain and cross-chain transactions

LiFi USDC transfer from Optimism AA (Savings Account) to Linea MetaMask Card (MetaMask EOA account)

CCTP v2 USDC transfer from Eth Sepolia Testnet to Linea Sepolia Testnet

ERC-20 USDC transfer between Optimism AA (Savings Account) to Optimism EOA

CCTP v2 MCP Agent-to-Agent USDC transfer from Client (USDC burn), post to Service (attestation read, USDC mint). Fully trusted via did:aa based nounce and VC/VP exchanges.

ERC-20 MCP Agent-to-Agent Eth on-chain transfer. Fully trusted leveraging did:aa Client/Service integration

ERC-7715 Permission Delegation Transfer

MetaMask Card Validation and USDC widrawl analytics. Used for Organization Leadership KYC.



Technical Architecture - this is our target

linea L2 - MetaMask DTK - Verax Attestation - Masca - Veramo - LiFi - USDC - Linea Name Service - Coinmunity - Account Abstraction DID - zkProofs - Agentic AI - LangChain Tech - OpenAI tech - Ontology (RichCanvas)


Our current technology stack was chosen as a gateway to our Technical Architecture. For example we us Optimism L2 and EAS because it was the available mainnet platform that works with MetaMask DTK. Our demonstration use-cases leverage multiple mainnets and testnets so we could demonstrate the features of LiFi, CCTP v2, and all the MetaMask DTK.

Over the next several months we look forward to be able to consolidated on a Synergistic Ecosystem build around linea L2. I would hope that our extensive use of EAS would show our commitment to on-chain trust/reputation and the Verax vision.



Logical Architecture

Although not a focus of this hackathon, myOrgWallet.io fully leverages the power of MetaMask design principles for security, extensibility, scalability, interoperability, transparency and usability.


All organization sensitive information is held in Verifiable Credentials stored within MetaMask Snap storage (masca/veramo). Associated on-chain attestations hold only limited data. Zero-Knowledge proofs provide trusted linkage between attestations and VC issuers.



All MyOrgWallet information (other than VC's) are maintain on-chain via attestations, delegations, and zero-knowledge proofs. Full data integrity is maintained. The Delegation frameworks provided within DTK are an essential part of our solution.



Simplified user experience powered by MetaMask: We fully leverage MetaMask’s Delegation Toolkit, Snaps, and related technologies to streamline interactions and reduce complexity for end users.



Lovable.dev is our benchmark of how an AI assistant can blend the power of an app with the simplicity of conversation. All actions within MyOrgWallet will be intent driven and callable by our AI Assistant. We fully leverage LangChain Graph, Agents, Tools and associated OpenAI LLM's to drive application interaction.