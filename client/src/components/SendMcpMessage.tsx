// src/components/SendMcpMessage.tsx

import React from 'react';
import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { type TypedDataDomain, type TypedDataField } from 'ethers'
import { ethers } from "ethers";
import { sepolia, linea } from "viem/chains";
import { createPublicClient, parseAbi, formatUnits, TransactionExecutionError, Hex, createWalletClient, http, createClient, custom, parseEther, zeroAddress, toHex, type Address, encodeFunctionData, hashMessage } from "viem";
import { agent } from '../agents/veramoAgent';
import { 
  CreateDelegationOptions, 
  Implementation, 
  toMetaMaskSmartAccount, 
  createCaveatBuilder, 
  createDelegation,
  DelegationFramework,
  SINGLE_DEFAULT_MODE,
} from "@metamask/delegation-toolkit";

import { createPimlicoClient } from "permissionless/clients/pimlico";
import { createBundlerClient } from "viem/account-abstraction";
import { AAKmsSigner } from '@mcp/shared';
import '../custom-styles.css';

import axios from 'axios';

import DelegationService from '../service/DelegationService';
import { privateKeyToAccount, PrivateKeyAccount, generatePrivateKey } from "viem/accounts";

import { erc7715ProviderActions } from "@metamask/delegation-toolkit/experimental";
import { erc7710BundlerActions } from "@metamask/delegation-toolkit/experimental";

import { CHAIN_ID, CIRCLE_API_KEY, RPC_URL, ETHERUM_RPC_URL, OPTIMISM_RPC_URL, OPTIMISM_SEPOLIA_RPC_URL, SEPOLIA_RPC_URL, LINEA_RPC_URL, BUNDLER_URL, PAYMASTER_URL } from "../config";
import { IRIS_API_URL, CHAIN_IDS_TO_EXPLORER_URL, CHAIN_IDS_TO_MESSAGE_TRANSMITTER, CIRCLE_SUPPORTED_CHAINS, CHAIN_IDS_TO_USDC_ADDRESSES, CHAIN_TO_CHAIN_NAME, CHAIN_IDS_TO_TOKEN_MESSENGER, CHAIN_IDS_TO_RPC_URLS, DESTINATION_DOMAINS, CHAINS, CHAIN_IDS_TO_BUNDLER_URL } from '../libs/chains';

interface SendMcpMessageProps {
  onAAWalletDeployed?: (address: string) => void;
}


export const SendMcpMessage: React.FC<SendMcpMessageProps> = ({ onAAWalletDeployed }) => {

  
  const [eoaAddress, setEoaAddress] = useState<string>('');
  const [eoaBalance, setEoaBalance] = useState<string>('');
  const [aaBalance, setAaBalance] = useState<string>('');
  const [aaWalletAddress, setAaWalletAddress] = useState<string>('');
  const [metamaskCardResults, setMetamaskCardResults] = useState<any[]>([]);
  const [metamaskCardLoading, setMetamaskCardLoading] = useState(false);
  const [usdcTransferResults, setUsdcTransferResults] = useState<any>(null);
  const [usdcTransferLoading, setUsdcTransferLoading] = useState(false);


  const chain = sepolia;



  // Linea RPC or Etherscan-compatible API
  const lineaProvider = new ethers.JsonRpcProvider("https://rpc.linea.build");

  const METAMASK_CARD_CONTRACT_ADDR = "0xA90b298d05C2667dDC64e2A4e17111357c215dD2";
  const WITHDRAW_SELECTOR = "0xf7ece0cf" //ethers.id("withdraw()").substring(0, 10); // e.g. "0x3ccfd60b"

  const LINEASCAN_API_KEY = "Z68JJAC45R53NRQN8VMBWGVKWNU6N3JQR6";

  const ERC20_ABI = [
    "event Transfer(address indexed from, address indexed to, uint256 value)",
  ];
  const iface = new ethers.Interface(ERC20_ABI);
  

  const START_BLOCK = 20071449;
  const END_BLOCK = 21000000;

  /*
  async function getTokenTransfers(txHash: string) {
    const url = `https://api.lineascan.build/api?module=account&action=tokentx&txhash=${txHash}&apikey=${LINEASCAN_API_KEY}`;
    const response = await axios.get(url);
    const logs = response.data.result;
  
    if (!Array.isArray(logs)) {
      console.error("Unexpected tokentx response for", txHash, response.data);
      return [];
    }
  
    return logs.map((log: any) => ({
      tokenSymbol: log.tokenSymbol,
      tokenName: log.tokenName,
      tokenAmount: log.value,
      from: log.from,
      to: log.to,
      contractAddress: log.contractAddress,
    }));
  }
  */

  async function getTokenTransfersFromTx(txHash: string) {
    const receipt = await lineaProvider.getTransactionReceipt(txHash);
    const transferTopic = iface.getEvent("Transfer");

    console.info("........ receipt: ", receipt)
  
    const tokenTransfers = receipt?.logs
      //.filter(log => log.topics[0] === transferTopic)
      .map(log => {
        const parsed = iface.parseLog(log);
        if (parsed) {
          //console.info("........ parsed: ", parsed)

          //if (parsed.args.from === "0x682cb87b59363226456eAd22f41C206717827571") {
            console.info("........ from Metamask Card EOA: ", parsed.args.from)
            console.info("........ to Central Card Fund: ", parsed.args.to)
            console.info("........ withdraw amount USDC: ", (Number(parsed.args.value) / 10 ** 6).toFixed(2))
            
            console.info("........ tokenAddress: ", log.address)
            console.info("........ Metamask Card Contract (withdraw processor: to): ", receipt.to)
            console.info("........ Central Card Fund Contract (withdraw originator: from): ", receipt.from)
          //}

          return {
            from: parsed.args.from,
            to: parsed.args.to,
            value: parsed.args.value.toString(),
            tokenAddress: log.address,
            withdrawOriginator: receipt.from,
            withdrawProcessor: receipt.to
            
          };
        }
        
      });
  
    return tokenTransfers;
  }

  async function getEOAWithdrawRecipients(transactionHash: string) {

    // Get transaction and receipt to confirm source
    const tx = await lineaProvider.getTransaction(transactionHash);
    const txReceipt = await lineaProvider.getTransactionReceipt(transactionHash);

    const erc20TransferTopic = ethers.id("Transfer(address,address,uint256)");
    console.info("........ erc20TransferTopic: ", txReceipt)

    const tokenTransfers = txReceipt?.logs.filter(log =>
      log.topics[0] === erc20TransferTopic
    );

    console.info("........ tokenTransfers: ", tokenTransfers)

    /*
    const isWithdrawCall =
      tx.to?.toLowerCase() === METAMASK_CARD_CONTRACT_ADDR.toLowerCase() &&
      tx.data.startsWith(WITHDRAW_SELECTOR);

    if (isWithdrawCall) {
      console.info("........ from: ", tx.from)
      console.info("........ to: ", tx.to)

    }
    */
  }





  async function getMetamaskCardWithdrawTransactions() {
    const url = `https://api.lineascan.build/api?module=account&action=txlist&address=${METAMASK_CARD_CONTRACT_ADDR}&startblock=${START_BLOCK}&endblock=${END_BLOCK}&sort=asc&apikey=${LINEASCAN_API_KEY}`;
    const response = await axios.get(url);
    const transactions = response.data.result;
  
    return transactions
  }
  

  

  /*
  async function getMetamaskCardEOAWithdrawRecipients() {
    setMetamaskCardLoading(true);
    setMetamaskCardResults([]);
    
    try {
      const withdrawTxs = await getMetamaskCardWithdrawTransactions();
      console.log(`Found ${withdrawTxs.length} withdraw() transactions.\n`);
      
      const results: any[] = [];
      
      for (const tx of withdrawTxs) {
        console.info("........  ")
        const rtn = await getTokenTransfersFromTx(tx.hash);
        console.info("........ rtn: ", rtn);
        
        if (rtn && rtn.length > 0) {
          results.push({
            transactionHash: tx.hash,
            timestamp: new Date(parseInt(tx.timeStamp) * 1000).toLocaleString(),
            ...rtn[0]
          });
        }
      }
      
      setMetamaskCardResults(results);
    } catch (error) {
      console.error("Error analyzing MetaMask Card transactions:", error);
      setMetamaskCardResults([{ error: "Failed to fetch MetaMask Card data" }]);
    } finally {
      setMetamaskCardLoading(false);
    }
  }
  */



  // ERC-7715 permissions delegated to Account Abstraction to move funds (withdraw)
  const handlePermissionDelegation = async () => {


    const client = createClient({
      transport: custom((window as any).ethereum),
    }).extend(erc7715ProviderActions());

    const publicClient = createPublicClient({
      chain: chain,
      transport: http(),
    });

    const loginResp = await login()
    console.info("........ client: ", loginResp)
    const otherAccountClient = await getOtherSmartAccount(loginResp.owner, loginResp.signatory, publicClient)


    const currentTime = Math.floor(Date.now() / 1000);
    const oneDayInSeconds = 24 * 60 * 60;
    const expiry = currentTime + oneDayInSeconds;

    // EOA - default AA 0xaC70Cb86615e09eFBEcB9bA29F5B35382A3e6cEc
    // assuming that the AA will have address same as EOA when go live
    const permissions = await client.grantPermissions([
      {
        chainId: sepolia.id,
        expiry,
        signer: {
          type: "account",
          data: {
            address: otherAccountClient.address,
          },
        },
        permission: {
          type: "native-token-stream",
          data: {
            initialAmount: 1n, // 1 WEI
            amountPerSecond: 1n, // 1 WEI per second
            startTime: currentTime,
            maxAmount: 10n, // 10 WEI
            justification: "Payment for a subscription service",
          },
        },
      },
    ]);

    const permission = permissions[0];
    const { accountMeta, context, signerMeta } = permission;

    const delegationManager = signerMeta?.delegationManager;

    const pimlicoClient = createPimlicoClient({
      transport: http(import.meta.env.VITE_BUNDLER_URL),
      chain: chain
    });
    const { fast: fee } = await pimlicoClient.getUserOperationGasPrice();


    const bundlerClient = createBundlerClient({
      transport: http(import.meta.env.VITE_BUNDLER_URL) as any,
      chain: chain,
      paymaster: true,
    }).extend(erc7710BundlerActions()) as any;

    const hash = await bundlerClient.sendUserOperationWithDelegation({
      publicClient,
      account: otherAccountClient,
      calls: [
        {
          to: otherAccountClient.address,
          data: "0x",
          value: 1n,
          permissionsContext: context,
          delegationManager,
        },
      ],
      ...fee,
      accountMetadata: accountMeta,
    });

    const { receipt } = await bundlerClient.waitForUserOperationReceipt({
      hash,
    });

    console.info("........ handlePermissionDelegation receipt: ", receipt)


  }





  const fetchBalances = async () => {
    try {
      if ((window as any).ethereum) {
        const provider = new ethers.BrowserProvider((window as any).ethereum);
        const accounts = await provider.send("eth_requestAccounts", []);
        if (accounts[0]) {
          const balance = await provider.getBalance(accounts[0]);
          setEoaAddress(accounts[0])
          setEoaBalance(ethers.formatEther(balance));
        }

        if (aaWalletAddress) {
          const aaBalance = await provider.getBalance(aaWalletAddress);
          setAaBalance(ethers.formatEther(aaBalance));
        }
      }
    } catch (error) {
      console.error('Error fetching balances:', error);
    }
  };

  useEffect(() => {
    fetchBalances();
    const interval = setInterval(fetchBalances, 10000);
    return () => clearInterval(interval);
  }, [aaWalletAddress]);


  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const provider = (window as any).ethereum;
  const login = async () => {
    const selectedNetwork = await provider.request({ method: "eth_chainId" });

    if (parseInt(selectedNetwork) !== chain.id) {
      await provider.request({
      method: "wallet_switchEthereumChain",
      params: [
          {
          chainId: toHex(chain.id),
          },
      ],
      });
    }

    const [owner] = (await provider.request({
      method: "eth_requestAccounts",
    })) as Address[];

    const walletClient = createWalletClient({
      chain: chain,
      transport: custom(provider),
      account: owner as `0x${string}`
    });

    console.info("........> wallet address: ", owner)

    return {
      owner,
      signatory: { walletClient: walletClient },
    };
  };

  const getEOASmartAccount = async(
    owner: any,
    signatory: any,
    publicClient: any
  ) : Promise<any> => {
    console.info("Creating smart account with owner:", owner);
    
    const accountClient = await toMetaMaskSmartAccount({
      client: publicClient as any,
      implementation: Implementation.Hybrid,
      deployParams: [
        owner,
        [] as string[],
        [] as bigint[],
        [] as bigint[]
      ] as [owner: `0x${string}`, keyIds: string[], xValues: bigint[], yValues: bigint[]],
      deploySalt: "0x0000000000000000000000000000000000000000000000000000000000000001",
      signatory: signatory as any,
    });

    console.info("Smart account created with address:", accountClient.address);
    const isDeployed = await accountClient.isDeployed();
    console.info("Smart account deployment status:", isDeployed);

    if (!isDeployed) {
      console.info("Deploying smart account...");
      const pimlicoClient = createPimlicoClient({
        transport: http(import.meta.env.VITE_BUNDLER_URL),
        chain: chain
      });

      const bundlerClient = createBundlerClient({
        transport: http(import.meta.env.VITE_BUNDLER_URL) as any,
        chain: chain,
        paymaster: true,
      }) as any;

      const { fast: fee } = await pimlicoClient.getUserOperationGasPrice();

      try {
        const userOperationHash = await bundlerClient.sendUserOperation({
          account: accountClient,
          calls: [
            {
              to: accountClient.address,
              data: "0x",
              value: 0n,
            },
          ],
          callGasLimit: 5000000n,
          verificationGasLimit: 5000000n,
          preVerificationGas: 2000000n,
          maxFeePerGas: fee.maxFeePerGas,
          maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
        });

        console.info("Waiting for deployment receipt...");
        const { receipt } = await bundlerClient.waitForUserOperationReceipt({
          hash: userOperationHash,
        });
        console.info("Deployment receipt 1:", receipt);
      } catch (error) {
        console.error("Deployment error:", error);
        throw error;
      }
    }

    return accountClient;
  }

  const getOtherSmartAccount = async(
    owner: any,
    signatory: any,
    publicClient: any
  ) : Promise<any> => {

    // Issue with metamask smart contract created.  I don't have an owner address and cannot get signature using ERC-1271
    // For now we return a default account for DID, VC and VP
    // Money is still taken out of the metamask smart wallet defined by address.

    const accountClient = await toMetaMaskSmartAccount({
      client: publicClient as any,
      implementation: Implementation.Hybrid,
      deployParams: [
          owner,
        [] as string[],
        [] as bigint[],
        [] as bigint[]
      ] as [owner: `0x${string}`, keyIds: string[], xValues: bigint[], yValues: bigint[]],
      deploySalt: "0x0000000000000000000000000000000000000000000000000000000000000002",
      signatory: signatory as any,
    });

    // After creating the account client, we can check if it's deployed
    const isDeployed = await accountClient.isDeployed();
    console.log("Smart account deployment status 2:", isDeployed);

    if (isDeployed == false) {
      console.info("Deploying smart account...");
      const pimlicoClient = createPimlicoClient({
        transport: http(import.meta.env.VITE_BUNDLER_URL),
        chain: chain
      });

      const bundlerClient = createBundlerClient({
        transport: http(import.meta.env.VITE_BUNDLER_URL) as any,
        chain: chain,
        paymaster: true,
      }) as any;

      const { fast: fee } = await pimlicoClient.getUserOperationGasPrice();

      try {
        const userOperationHash = await bundlerClient.sendUserOperation({
          account: accountClient,
          calls: [
            {
              to: accountClient.address,
              data: "0x",
              value: 0n,
            },
          ],
          callGasLimit: 5000000n,
          verificationGasLimit: 5000000n,
          preVerificationGas: 2000000n,
          maxFeePerGas: fee.maxFeePerGas,
          maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
        });

        console.info("Waiting for deployment receipt...");
        const { receipt } = await bundlerClient.waitForUserOperationReceipt({
          hash: userOperationHash,
        });
        console.info("Deployment receipt 2:", receipt);
      } catch (error) {
        console.error("Deployment error:", error);
        throw error;
      }
    } else {
        console.log("Smart account is deployed");
        console.log("........ smart accountClient: ", accountClient.address)
    }

    return accountClient;
  }

  async function getBalance(address: string) {
    const sepProv = new ethers.JsonRpcProvider(import.meta.env.VITE_RPC_URL);
    const balance = await sepProv.getBalance(address);
    const eth = ethers.formatEther(balance);
    console.log(`Balance: ${eth} ETH for address: ${address}`);
    return eth;
  }

  const handleMetamaskCardEOAWithdrawRecipients = async () => {
    setMetamaskCardLoading(true);
    setMetamaskCardResults([]);
    
    try {
      const withdrawTxs = await getMetamaskCardWithdrawTransactions();
      console.log(`Found ${withdrawTxs.length} withdraw() transactions.\n`);
      
      const results: any[] = [];
      
      let count = 0;
      for (const tx of withdrawTxs) {
        count++;
        if (count > 1) {
          break;
        }
        const rtn = await getTokenTransfersFromTx(tx.hash);
        
        if (rtn && rtn.length > 0) {
          results.push({
            transactionHash: tx.hash,
            timestamp: new Date(parseInt(tx.timeStamp) * 1000).toLocaleString(),
            ...rtn[0]
          });
        }
      }
      
      setMetamaskCardResults(results);
    } catch (error) {
      console.error("Error analyzing MetaMask Card transactions:", error);
      setMetamaskCardResults([{ error: "Failed to fetch MetaMask Card data" }]);
    } finally {
      setMetamaskCardLoading(false);
    }
  }

  const handleSendWebDIDJWT = async () => {
      const challengeResult : any = await fetch('http://localhost:3001/mcp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
          type: 'SendWebDIDJWT',
          payload: {
              action: 'ServiceSubscriptionRequest'
          },
          }),
      });
      const challengeData : any = await challengeResult.json()
      console.info("........ challengeResult: ", challengeData)
  }

  const handleSendEthrDIDJWT = async () => {
      const challengeResult : any = await fetch('http://localhost:3001/mcp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
          type: 'SendEthrDIDJWT',
          payload: {
              action: 'ServiceSubscriptionRequest'
          },
          }),
      });
      const challengeData : any = await challengeResult.json()
      console.info("........ challengeResult: ", challengeData)
  }

  const handleSendAADIDJWT = async () => {
      const challengeResult : any = await fetch('http://localhost:3001/mcp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: 'SendAADIDJWT',
            payload: {
                action: 'ServiceSubscriptionRequest'
            },
          }),
      });
      const challengeData : any = await challengeResult.json()
      console.info("........ challengeResult: ", challengeData)
  }

  const handleSendEOADelegatedDIDCommJWT = async () => {

    const challengeResult : any = await fetch('http://localhost:3001/mcp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
        type: 'handleSendEOADelegatedDIDCommJWT',
        payload: {
            action: 'ServiceSubscriptionRequest'
        },
        }),
    });
    const challengeData : any = await challengeResult.json()
    console.info("........ challengeResult: ", challengeData)
  }


  const extractFromAccountDid = (accountDid: string): { chainId: number; address: `0x${string}` } | null => {
    try {
      // Parse did:pkh:eip155:chainId:address format
      const parts = accountDid.split(':');
      if (parts.length === 5 && parts[0] === 'did' && parts[1] === 'aa' && parts[2] === 'eip155') {
        const chainId = parseInt(parts[3], 10);
        const address = parts[4] as `0x${string}`;
        return { chainId, address };
      }
      return null;
    } catch (error) {
      console.error('Error parsing accountDid:', error);
      return null;
    }
  };

  const burnUSDC = async (
    delegationChain: any,
    indivAccountClient: any,
    sourceChainId: number,
    amount: bigint,
    destinationChainId: number,
    destinationAddress: string,
    transferType: "fast" | "standard",
  ) => {
    console.info("*********** burnUSDC ****************");
    console.info("*********** delegationChain ****************", delegationChain);
    console.info("*********** indivAccountClient ****************", indivAccountClient);

    // Get the correct bundler URL for the source chain
    const bundlerUrl = CHAIN_IDS_TO_BUNDLER_URL[sourceChainId];
    if (!bundlerUrl) {
      throw new Error(`No bundler URL configured for chain ${sourceChainId}`);
    }

    const bundlerClient = createBundlerClient({
      transport: http(bundlerUrl),
      paymaster: true,
      chain: chain,
      paymasterContext: {
        mode: 'SPONSORED',
      },
    });

    let calls: any[] = [];

    // Use the actual amount parameter
    const fundingAmount = amount;

    const tokenMessenger = CHAIN_IDS_TO_TOKEN_MESSENGER[sourceChainId] as `0x${string}`
    const usdcAddress = CHAIN_IDS_TO_USDC_ADDRESSES[sourceChainId] as `0x${string}`
    const approvalExecution = {
      target: usdcAddress,
      callData: encodeFunctionData({
        abi: parseAbi(["function approve(address,uint)"]),
        functionName: "approve",
        args: [tokenMessenger, fundingAmount],
      }),
      value: 0n, // since it's an ERC-20 approval, you don't need to send ETH
    };

    const data0 = DelegationFramework.encode.redeemDelegations({
      delegations: [delegationChain],
      modes: [SINGLE_DEFAULT_MODE],
      executions: [[approvalExecution]]
    });

    const call0 = {
      to: indivAccountClient.address,
      data: data0,
    }

    calls.push(call0)

    const finalityThreshold = transferType === "fast" ? 1000 : 2000;
    const maxFee = fundingAmount - 1n;

    const mintRecipient = `0x${destinationAddress
      .replace(/^0x/, "")
      .padStart(64, "0")}`;

    const callData = encodeFunctionData({
      abi: [
        {
          type: "function",
          name: "depositForBurn",
          stateMutability: "nonpayable",
          inputs: [
            { name: "amount", type: "uint256" },
            { name: "destinationDomain", type: "uint32" },
            { name: "mintRecipient", type: "bytes32" },
            { name: "burnToken", type: "address" },
            { name: "hookData", type: "bytes32" },
            { name: "maxFee", type: "uint256" },
            { name: "finalityThreshold", type: "uint32" },
          ],
          outputs: [],
        },
      ],
      functionName: "depositForBurn",
      args: [
        fundingAmount,
        DESTINATION_DOMAINS[destinationChainId],
        mintRecipient as Hex,
        CHAIN_IDS_TO_USDC_ADDRESSES[sourceChainId] as `0x${string}`,
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        maxFee,
        finalityThreshold,
      ],
    })

    const execution = {
      target: CHAIN_IDS_TO_TOKEN_MESSENGER[sourceChainId] as `0x${string}`,
      callData: callData,
      value: 0n, // since it's an ERC-20 approval, you don't need to send ETH
    };

    console.info("*********** redeemDelegations ****************");
    const data = DelegationFramework.encode.redeemDelegations({
      delegations: [delegationChain],
      modes: [SINGLE_DEFAULT_MODE],
      executions: [[execution]]
    });

    const call = {
      to: indivAccountClient.address,
      data: data,
    }
    calls.push(call)

    const fee = {maxFeePerGas: 412596685n, maxPriorityFeePerGas: 412596676n}

    // Send user operation
    console.info("*********** sendUserOperation ****************");
    const userOpHash = await bundlerClient.sendUserOperation({
      account: indivAccountClient,
      calls: calls,
      ...fee
    });

    console.info("*********** waitForUserOperationReceipt ****************");
    const userOperationReceipt = await bundlerClient.waitForUserOperationReceipt({ hash: userOpHash });

    console.info("*********** burn tx ****************", userOperationReceipt);

    return userOperationReceipt;
  };




  const handleMCPAgentToAgentUSDCSend = async () => {

    try {
      setUsdcTransferLoading(true);
      setUsdcTransferResults(null);

      const loginResp = await login()
      const publicClient = createPublicClient({
        chain: chain,
        transport: http(),
      });

      let burnerPrivateKey = await DelegationService.getBurnerKeyFromStorage(loginResp.owner)
      if (!burnerPrivateKey) {
        console.info("create new burner key")
        burnerPrivateKey = generatePrivateKey() as `0x${string}`;
        await DelegationService.saveBurnerKeyToStorage(loginResp.owner, burnerPrivateKey)
      }

      const burnerAccount = privateKeyToAccount(burnerPrivateKey as `0x${string}`);

      const burnerAccountClient = await toMetaMaskSmartAccount({
        client: publicClient,
        implementation: Implementation.Hybrid,
        deployParams: [burnerAccount.address, [], [], []],
        signatory: { account: burnerAccount },
        deploySalt: toHex(10),
      })


      const clientSubscriptionAccountClient = await getEOASmartAccount(loginResp.owner, loginResp.signatory, publicClient)
      console.info("client smart account address: ",  clientSubscriptionAccountClient.address)
      const isDeployedb = await publicClient.getCode({ address: clientSubscriptionAccountClient.address });
      console.info("isDeployedb .....: ", isDeployedb)


      // Notify parent component about AA wallet address
      if (onAAWalletDeployed) {
        onAAWalletDeployed(clientSubscriptionAccountClient.address);
      }
      setAaWalletAddress(clientSubscriptionAccountClient.address)



      // Ensure account is properly initialized
      if (!clientSubscriptionAccountClient || !clientSubscriptionAccountClient.address) {
        throw new Error("Failed to initialize account client");
      }

      const clientSubscriptionChainId = chain.id
      const clientSubscriberSmartAddress = clientSubscriptionAccountClient.address.toLowerCase()
      const clientSubscriberDid = "did:aa:eip155:" + clientSubscriptionChainId + ":" + clientSubscriberSmartAddress.toLowerCase()
      
      console.info("client subscription chain id: ", clientSubscriptionChainId)
      console.info("client subscriber smart account address : ", clientSubscriberSmartAddress)
      console.info("client subscriber did: ", clientSubscriberDid)

      // build delegation to burner account
      let burnerDel = createDelegation({
        to: burnerAccountClient.address,
        from: clientSubscriptionAccountClient.address,
        caveats: [] }
      );

      const signature = await clientSubscriptionAccountClient.signDelegation({
        delegation: burnerDel,
      });

      burnerDel = {
        ...burnerDel,
        signature,
      }


      // get challenge from organization providing service,  along with challenge phrase
      const challengeResult : any = await fetch('http://localhost:3001/mcp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
        type: 'ServiceRequest',
        payload: {
            action: 'ServiceSubscriptionRequest'
        },
        }),
      });

      const challengeData : any = await challengeResult.json()
      console.info("........ challengeResult: ", challengeData)



      // generate payment delegation for service account

      const { chainId: serviceChainId, address: serviceAddress } = extractFromAccountDid(challengeData.did) || {};
      console.info("serviceChainId: ", serviceChainId)
      console.info("serviceAddress: ", serviceAddress)

      



      // get balance for client subscriber smart account
      const aaBalance = await getBalance(clientSubscriberSmartAddress)
      setAaBalance(aaBalance)
      console.info("client subscriber smart account balance: ", aaBalance)

      const availableFunds = {
        "USDC": 1000000000000000000000000,
        "ETH": aaBalance,
      }

      const isDeployed = await clientSubscriptionAccountClient?.isDeployed()
      console.info("************* is EOA Smart Account Deployed: ", isDeployed, clientSubscriptionAccountClient.address)

      if (isDeployed == false) {
        console.info("deploying client smart account")
        const pimlicoClient = createPimlicoClient({
          transport: http(import.meta.env.VITE_BUNDLER_URL),
          chain: chain
        });

        console.info("creating bundler client for chain: ", chain.name)
        console.info("creating bundler client for bundler: ", import.meta.env.VITE_BUNDLER_URL)

        const bundlerClient = createBundlerClient({
          transport: http(import.meta.env.VITE_BUNDLER_URL) as any,
          chain: chain,
          paymaster: true,
        }) as any;

        const { fast: fee } = await pimlicoClient.getUserOperationGasPrice();

        try {
          console.info("sending user operation to deploy client smart account")
          const userOperationHash = await bundlerClient!.sendUserOperation({
            account: clientSubscriptionAccountClient,
            calls: [
              {
                to: clientSubscriptionAccountClient.address,
                data: "0x",
                value: 0n,
              },
            ],
            callGasLimit: 3000000n,
            verificationGasLimit: 3000000n,
            preVerificationGas: 1000000n,
            maxFeePerGas: fee.maxFeePerGas,
            maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
          });

          console.info("send user operation - done")
          const { receipt } = await bundlerClient!.waitForUserOperationReceipt({
            hash: userOperationHash,
          });
        }
        catch (error) {
          console.error("error deploying client smart account: ", error)
        }
      }

  
      // get agent available methods, this is a capability demonstration
      // const availableMethods = await agent.availableMethods()

      // add did and key to our agent
      await agent.didManagerImport({
        did: clientSubscriberDid, // or did:aa if you're using a custom method
        provider: 'did:aa:client',
        alias: 'subscriber-smart-account',
        keys:[]
      })

      await agent.keyManagerImport({
        kms: 'aa',
        kid: 'aa-' + clientSubscriberSmartAddress,
        type: 'Secp256k1',
        publicKeyHex: '0x', // replace with actual public key
        privateKeyHex: '0x' // replace with actual private key if available
      });

      const identifier = await agent.didManagerGet({ did: clientSubscriberDid });
      console.info("clientSubscriberDid did identifier: ", identifier)


      // construct the verifiable credential and presentation for service request and payment delegation

      // @ts-ignore
      const signerAAVC: AAKmsSigner = {
          async signTypedData(
            domain: TypedDataDomain,
            types: Record<string, Array<TypedDataField>>,
            value: Record<string, any>,
          ): Promise<string> {
              const result = await clientSubscriptionAccountClient?.signTypedData({
                  account: loginResp.owner, // EOA that controls the smart contract

                  // @ts-ignore
                  domain: domain as TypedDataDomain,
                  chainId: domain?.chainId,
                  types,
                  primaryType: 'VerifiableCredential',
                  message: value,
              });
              if (!result) {
                  throw new Error("signTypedData returned undefined");
              }

              console.info("owner account: ", loginResp.owner)
              console.info("client smart account signTypedData result: ", result)
              return result;
          },

          async getAddress(): Promise<Address> {
              if (!clientSubscriptionAccountClient) {
                  throw new Error("clientSubscriptionAccountClient is not initialized");
              }
              return clientSubscriptionAccountClient.address;
          },
      };

      const vcAA = await agent.createVerifiableCredentialEIP1271({
        credential: {
          issuer: { id: clientSubscriberDid },
          issuanceDate: new Date().toISOString(),
          type: ['VerifiableCredential'],
          credentialSubject: {
            id: clientSubscriberDid,
            fundsAvailable: JSON.stringify(availableFunds),
          },

          '@context': ['https://www.w3.org/2018/credentials/v1'],
        },

        signer: signerAAVC
      })

      console.info("service request and funds available verifiable credential: ", vcAA)

      // demonstrate verification of the verifiable credential
      const vcVerified = await agent.verifyCredentialEIP1271({ credential: vcAA, });
      console.info("verify VC: ", vcVerified)

      // @ts-ignore
      const signerAAVP: AAKmsSigner = {
          async signTypedData(
              domain: TypedDataDomain,
              types: Record<string, Array<TypedDataField>>,
              value: Record<string, any>,
          ): Promise<string> {
              console.info("signTypedData called with domain: ", domain);
              console.info("signTypedData called with types: ", types);
              console.info("signTypedData called with value: ", value);
              const result = await clientSubscriptionAccountClient?.signTypedData({
                  account: loginResp.owner, // EOA that controls the smart contract
                  // @ts-ignore
                  domain: domain,
                  chainId: domain?.chainId,
                  types,
                  primaryType: 'VerifiablePresentation',
                  message: value,
              });
              if (!result) {
                  throw new Error("signTypedData returned undefined");
              }
              return result;
          },

          async getAddress(): Promise<Address> {
              if (!clientSubscriptionAccountClient) {
                  throw new Error("clientSubscriptionAccountClient is not initialized");
              }
              return clientSubscriptionAccountClient.address;
          },

      };
      const vpAA = await agent.createVerifiablePresentationEIP1271(
          {
              presentation: {
                  holder: clientSubscriberDid,
                  verifiableCredential: [vcAA],
              },
              proofFormat: 'EthereumEip712Signature2021',
              challenge: challengeData.challenge,
              signer: signerAAVP
          }
      );
      console.info("verifiable presentation: ", vpAA)

      // demonstrate verification of the verifiable presentation
      const vpVerified = await agent.verifyPresentationEIP1271({ presentation: vpAA, });
      console.info("verify VP 1: ", vpVerified)



      const serviceAgentResponse = await fetch('http://localhost:3001/mcp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
        type: 'AskForServiceProposal',
        sender: clientSubscriberDid,
        payload: {
            location: 'Erie, CO',
            service: 'Lawn Care',
            presentation: vpAA
        },
        }),
      });

      const data = await serviceAgentResponse.json();

      // transfer USDC to service provider
      const sourceChainId = clientSubscriptionChainId
      const sourceAddress = clientSubscriptionAccountClient.address.toLowerCase()
      const destinationChainId = serviceChainId
      const destinationAddress = serviceAddress

      if (!sourceChainId || !destinationChainId || !sourceAddress || !destinationAddress) {
        return
      }
      

      console.info("************ sourceChainId: ", sourceChainId);
      console.info("************ sourceAddress: ", sourceAddress);
      
      console.info("************ destinationAddress: ", destinationAddress);
      console.info("************ destinationChainId: ", destinationChainId);


      const amount = 100000n

      const transferType = "fast";
      let burnTx = await burnUSDC(
        [burnerDel],
        burnerAccountClient,
        sourceChainId,
        amount,
        destinationChainId,
        destinationAddress,
        transferType,
      );

      const paymentPayload = {
        transactionHash: burnTx.receipt.transactionHash,
        clientDid: clientSubscriberDid
      }

      console.info("***********  transactionHash", burnTx.receipt.transactionHash);
      console.info("***********  clientSubscriberDid", clientSubscriberDid);

      const paymentResponse = await fetch('http://localhost:3001/mcp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'ProcessPayment',
          sender: clientSubscriberDid,
          payload: {
            transactionHash: burnTx.receipt.transactionHash,
            clientDid: clientSubscriberDid
          },
        }),
      });



      const dataPaymentRes = await paymentResponse.json();

      const name = dataPaymentRes.name
      const location = dataPaymentRes.location
      const confirmation = dataPaymentRes.confirmation

      // Set the USDC transfer results
      setUsdcTransferResults({
        name,
        location,
        confirmation,
        transactionHash: burnTx.receipt.transactionHash,
        amount: (Number(amount) / 10 ** 6).toFixed(2),
        sourceChainId,
        sourceAddress,
        destinationChainId,
        destinationAddress
      });



      return;
    
  } catch (err) {
    console.error('Error sending MCP message:', err);

    setResponse({ error: 'Request failed' });
  } finally {
    setLoading(false);
    setUsdcTransferLoading(false);
  }
  }


  const handleMCPAgentToAgentEthSend = async () => {
      setLoading(true);

      try {
          // get challenge from organization providing service,  along with challenge phrase
          const challengeResult : any = await fetch('http://localhost:3001/mcp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
            type: 'PresentationRequest',
            //from: clientSubscriberDid,
            payload: {
                action: 'ServiceSubscriptionRequest'
            },
            }),
          });

          const challengeData : any = await challengeResult.json()
          console.info("........ challengeResult: ", challengeData)

          const loginResp = await login()
          const publicClient = createPublicClient({
            chain: chain,
            transport: http(),
          });

          // generate payment delegation for service account
          const smartServiceAccountAddress = challengeData.address

          const clientSubscriptionAccountClient = await getEOASmartAccount(loginResp.owner, loginResp.signatory, publicClient)
          console.info("client smart account address: ",  clientSubscriptionAccountClient.address)
          const isDeployedb = await publicClient.getCode({ address: clientSubscriptionAccountClient.address });
          console.info("isDeployedb .....: ", isDeployedb)
          const otherAccountClient = await getOtherSmartAccount(loginResp.owner, loginResp.signatory, publicClient)
          console.info("other account address: ",  otherAccountClient.address)

          // Notify parent component about AA wallet address
          if (onAAWalletDeployed) {
            onAAWalletDeployed(clientSubscriptionAccountClient.address);
          }


          setAaWalletAddress(clientSubscriptionAccountClient.address)

          const environment = clientSubscriptionAccountClient.environment;
          const caveatBuilder = createCaveatBuilder(environment);

          // get list of careat types: https://docs.gator.metamask.io/how-to/create-delegation/restrict-delegation
          caveatBuilder.addCaveat("nativeTokenPeriodTransfer",
              10n, // 1 ETH in wei
              86400, // 1 day in seconds
              1743763600, // April 4th, 2025, at 00:00:00 UTC
          )

          const caveats = caveatBuilder.build()

          // Ensure account is properly initialized
          if (!clientSubscriptionAccountClient || !clientSubscriptionAccountClient.address) {
            throw new Error("Failed to initialize account client");
          }

          const clientSubscriberSmartAddress = clientSubscriptionAccountClient.address.toLowerCase()
          const clientSubscriberDid = "did:aa:eip155:" + chain.id + ":" + clientSubscriberSmartAddress.toLowerCase()
          console.info("client subscriber smart account address : ", clientSubscriberSmartAddress)
          console.info("client subscriber did: ", clientSubscriberDid)


          /*


          // get did document for client subscriber
          const clientSubscriberEthrDid = "did:ethr:" + clientSubscriberSmartAddress.toLowerCase()
          const clientSubscriberEthrDidDoc = await agent.resolveDid({didUrl: clientSubscriberEthrDid})
          console.info("client subscriber ethr did document: ", clientSubscriberEthrDidDoc)

          const message = "hello world"; // the signed message
          const clientSubScriberEOAEthrDid = "did:ethr:" + loginResp.owner.toLowerCase()

          const clientEOASigner = loginResp.signatory.walletClient

          const signature2 = await loginResp.signatory.walletClient.signMessage({
              message: message,
            });

          const recoveredAddress = ethers.verifyMessage(message, signature2);
          console.info(" *********** recoveredAddress: ", recoveredAddress)

          const eoaEthrDid = "did:ethr:" + loginResp.owner.toLowerCase()
          const eoaEthrDidDoc = await agent.resolveDid({didUrl: eoaEthrDid})
          console.info("gator client eoa ethr did document: ", eoaEthrDidDoc)

          const eoaBalance = await getBalance(loginResp.owner.toLowerCase())
          setEoaBalance(eoaBalance)
          console.info("client subscriber eoa balance: ", eoaBalance)

          const aaEthrDid = "did:ethr:" + clientSubscriberSmartAddress.toLowerCase()
          const aaEthrDidDoc = await agent.resolveDid({didUrl: aaEthrDid})
          console.info("gator client aa ethr did document: ", aaEthrDidDoc)

          */


          // get balance for client subscriber smart account
          const aaBalance = await getBalance(clientSubscriberSmartAddress)
          setAaBalance(aaBalance)
          console.info("client subscriber smart account balance: ", aaBalance)

          const isDeployed = await clientSubscriptionAccountClient?.isDeployed()
          console.info("************* is EOA Smart Account Deployed: ", isDeployed, clientSubscriptionAccountClient.address)

          if (isDeployed == false) {
            console.info("deploying client smart account")
            const pimlicoClient = createPimlicoClient({
              transport: http(import.meta.env.VITE_BUNDLER_URL),
              chain: chain
            });

            console.info("creating bundler client for chain: ", chain.name)
            console.info("creating bundler client for bundler: ", import.meta.env.VITE_BUNDLER_URL)

            const bundlerClient = createBundlerClient({
              transport: http(import.meta.env.VITE_BUNDLER_URL) as any,
              chain: chain,
              paymaster: true,
            }) as any;

            const { fast: fee } = await pimlicoClient.getUserOperationGasPrice();

            try {
              console.info("sending user operation to deploy client smart account")
              const userOperationHash = await bundlerClient!.sendUserOperation({
                account: clientSubscriptionAccountClient,
                calls: [
                  {
                    to: clientSubscriptionAccountClient.address,
                    data: "0x",
                    value: 0n,
                  },
                ],
                callGasLimit: 3000000n,
                verificationGasLimit: 3000000n,
                preVerificationGas: 1000000n,
                maxFeePerGas: fee.maxFeePerGas,
                maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
              });

              console.info("send user operation - done")
              const { receipt } = await bundlerClient!.waitForUserOperationReceipt({
                hash: userOperationHash,
              });
            }
            catch (error) {
              console.error("error deploying client smart account: ", error)
            }
          }

          
          
          const isOtherDeployed = await otherAccountClient?.isDeployed()
          console.info("************* is Other Smart Account Deployed: ", isOtherDeployed, otherAccountClient.address)

          if (isOtherDeployed == false) {
            const pimlicoClient = createPimlicoClient({
              transport: http(import.meta.env.VITE_BUNDLER_URL),
              chain: chain
            });

            const bundlerClient = createBundlerClient({
              transport: http(import.meta.env.VITE_BUNDLER_URL) as any,
              chain: chain,
              paymaster: true,
            }) as any;

            const { fast: fee } = await pimlicoClient.getUserOperationGasPrice();
            const userOperationHash = await bundlerClient!.sendUserOperation({
              account: otherAccountClient,
              calls: [
                  {
                  to: zeroAddress,
                  },
              ],
              ...fee,
              });

              console.info("send user operation - done")
              const { receipt } = await bundlerClient!.waitForUserOperationReceipt({
              hash: userOperationHash,
            });
          }

          


          /*
          console.info("create delegation from EOA AA to other AA")
          const delegation = createDelegation({
            from: clientSubscriptionAccountClient.address,
            to: otherAccountClient.address,
            caveats: [],
          });



          //const sig = await clientSubscriptionAccountClient.signDelegation({
          //  delegation: delegation,
          //});

          console.info("sign delegation")
          const sig = await clientSubscriptionAccountClient.signDelegation({
            delegation: delegation,
          });
      
          console.info("set signature for delegation")
          const signedDelegation = {
            ...delegation,
            signature: sig,
          }
      

          console.info("execute delegation")
          const pimlicoClient = createPimlicoClient({
            transport: http(import.meta.env.VITE_BUNDLER_URL),
            chain: chain
          });
          const { fast: fee } = await pimlicoClient.getUserOperationGasPrice();

          const bundlerClient = createBundlerClient({
            transport: http(import.meta.env.VITE_BUNDLER_URL),
            chain: chain,
            paymaster: true,
          }) as any;


          const executions = [
            {
              target: otherAccountClient.address,
              value: 10n,
              callData: "0x" as `0x${string}`
            },
          ];

          const delegationData = DelegationFramework.encode.redeemDelegations({
            delegations: [ [signedDelegation] ],
            modes: [SINGLE_DEFAULT_MODE],
            executions: [executions]
          });


          const key1 = BigInt(Date.now()) 
          const nonce1 = encodeNonce({ key: key1, sequence: 0n })
          const userOperationHash = await bundlerClient.sendUserOperation({
            account: otherAccountClient,
            calls: [
              {
                to: otherAccountClient.address,
                delegationData,
              },
            ],
            nonce: nonce1,
            ...fee
            
          });

          const { receipt } = await bundlerClient.waitForUserOperationReceipt({
              hash: userOperationHash,
          });

          console.info("delegation transfer from eoa to client smart account: ", receipt)
          */


















          // create delegation to server smart account providing service these caveats
          let paymentDel = createDelegation({
            from: clientSubscriptionAccountClient.address,
            to: smartServiceAccountAddress,
            caveats: caveats }
          );

          const signature = await clientSubscriptionAccountClient.signDelegation({
            delegation: paymentDel,
          });

          paymentDel = {
            ...paymentDel,
            signature,
          }

          // get agent available methods, this is a capability demonstration
          // const availableMethods = await agent.availableMethods()

          // add did and key to our agent
          await agent.didManagerImport({
            did: clientSubscriberDid, // or did:aa if you're using a custom method
            provider: 'did:aa:client',
            alias: 'subscriber-smart-account',
            keys:[]
          })

          await agent.keyManagerImport({
            kms: 'aa',
            kid: 'aa-' + clientSubscriberSmartAddress,
            type: 'Secp256k1',
            publicKeyHex: '0x', // replace with actual public key
            privateKeyHex: '0x' // replace with actual private key if available
          });

          const identifier = await agent.didManagerGet({ did: clientSubscriberDid });
          console.info("clientSubscriberDid did identifier: ", identifier)


          // construct the verifiable credential and presentation for service request and payment delegation

          // @ts-ignore
          const signerAAVC: AAKmsSigner = {
              async signTypedData(
                domain: TypedDataDomain,
                types: Record<string, Array<TypedDataField>>,
                value: Record<string, any>,
              ): Promise<string> {
                  const result = await clientSubscriptionAccountClient?.signTypedData({
                      account: loginResp.owner, // EOA that controls the smart contract

                      // @ts-ignore
                      domain: domain as TypedDataDomain,
                      chainId: domain?.chainId,
                      types,
                      primaryType: 'VerifiableCredential',
                      message: value,
                  });
                  if (!result) {
                      throw new Error("signTypedData returned undefined");
                  }

                  console.info("owner account: ", loginResp.owner)
                  console.info("client smart account signTypedData result: ", result)
                  return result;
              },

              async getAddress(): Promise<Address> {
                  if (!clientSubscriptionAccountClient) {
                      throw new Error("clientSubscriptionAccountClient is not initialized");
                  }
                  return clientSubscriptionAccountClient.address;
              },
          };

          const vcAA = await agent.createVerifiableCredentialEIP1271({
            credential: {
              issuer: { id: clientSubscriberDid },
              issuanceDate: new Date().toISOString(),
              type: ['VerifiableCredential'],
              credentialSubject: {
                id: clientSubscriberDid,
                paymentDelegation: JSON.stringify(paymentDel),
              },

              '@context': ['https://www.w3.org/2018/credentials/v1'],
            },

            signer: signerAAVC
          })

          console.info("service request and payment delegation verifiable credential: ", vcAA)

          // demonstrate verification of the verifiable credential
          const vcVerified = await agent.verifyCredentialEIP1271({ credential: vcAA, });
          console.info("verify VC: ", vcVerified)

          // @ts-ignore
          const signerAAVP: AAKmsSigner = {
              async signTypedData(
                  domain: TypedDataDomain,
                  types: Record<string, Array<TypedDataField>>,
                  value: Record<string, any>,
              ): Promise<string> {
                  console.info("signTypedData called with domain: ", domain);
                  console.info("signTypedData called with types: ", types);
                  console.info("signTypedData called with value: ", value);
                  const result = await clientSubscriptionAccountClient?.signTypedData({
                      account: loginResp.owner, // EOA that controls the smart contract
                      // @ts-ignore
                      domain: domain,
                      chainId: domain?.chainId,
                      types,
                      primaryType: 'VerifiablePresentation',
                      message: value,
                  });
                  if (!result) {
                      throw new Error("signTypedData returned undefined");
                  }
                  return result;
              },

              async getAddress(): Promise<Address> {
                  if (!clientSubscriptionAccountClient) {
                      throw new Error("clientSubscriptionAccountClient is not initialized");
                  }
                  return clientSubscriptionAccountClient.address;
              },

          };
          const vpAA = await agent.createVerifiablePresentationEIP1271(
              {
                  presentation: {
                      holder: clientSubscriberDid,
                      verifiableCredential: [vcAA],
                  },
                  proofFormat: 'EthereumEip712Signature2021',
                  challenge: challengeData.challenge,
                  signer: signerAAVP
              }
          );
          console.info("verifiable presentation: ", vpAA)

          // demonstrate verification of the verifiable presentation
          const vpVerified = await agent.verifyPresentationEIP1271({ presentation: vpAA, });
          console.info("verify VP 2: ", vpVerified)

          /*
              vc and vp using masca if using did:dthr or did:pkh

          // get metamask current account did
          const snapId = 'npm:@blockchain-lab-um/masca'
          const mascaRslt = await enableMasca(address, {
              snapId: snapId,
              //supportedMethods: ['did:ethr', 'did:key', 'did:pkh'], // Specify supported DID methods
              supportedMethods: ['did:pkh'],
          });

          const mascaApi = await mascaRslt.data.getMascaApi();
          const did = await mascaApi.getDID()
          const holderDid = did.data

          // interact with mcp server as a client

          const challengeResult = await fetch('http://localhost:3001/mcp', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
              type: 'PresentationRequest',
              from: 'did:web:client.myorgwallet.io',
              payload: {
                  action: 'ServiceSubscriptionRequest'
              },
              }),
          });
          const challengeData = await challengeResult.json()

          // 1. Issue VC
          console.info("create vc with subject for did: ", holderDid)
          const unsignedCredential = {
              "@context": ["https://www.w3.org/2018/credentials/v1"],
              type: ["VerifiableCredential", "ExampleCredential"],
              issuer: holderDid,
              issuanceDate: new Date().toISOString(),
              credentialSubject: {
                  id: holderDid,
                  name: "Alice",
              },
              }

          const credentialResult = await mascaApi.createCredential({
              minimalUnsignedCredential: unsignedCredential,
              proofFormat: 'EthereumEip712Signature2021',
              options: {
                  save: true, // store in Snap or other connected store
                  store: ['snap'],
              },
              })

          const vcs = [credentialResult.data]
          console.info("vc generated: ", credentialResult)

          console.info("challenge phrase: ", challengeData.challenge)

          // 2. Package VC into VP

          const holder = holderDid
          const challenge = challengeData.challenge
          const domain = "wallet.myorgwallet.io"

          console.info("create vp with subject and challenge: ", holder, challenge)

          // did has to be loaded and to do that private key is needed
          const presentationResult = await agent.createVerifiablePresentation({
          presentation: {
              holder,
              verifiableCredential: vcs,
          },
          proofFormat: 'EthereumEip712Signature2021',
          domain,
          challenge: challenge
          });

          const proofOptions = { type: 'EthereumEip712Signature2021', domain, challenge };
          const presentationResult = await mascaApi.createPresentation({
              vcs,
              proofFormat: 'EthereumEip712Signature2021',
              proofOptions,
              })

          const vp = presentationResult.data
          //vp.proof.challenge = challenge
          //vp.proof.domain = domain
          console.info("........ vp: ", JSON.stringify(vp))

          */

        const res = await fetch('http://localhost:3001/mcp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
          type: 'AskForService',
          sender: clientSubscriberDid,
          payload: {
              location: 'Erie, CO',
              service: 'Lawn Care',
              presentation: vpAA
          },
          }),
        });

        const data = await res.json();

        setResponse(data);
        await fetchBalances()
        
      } catch (err) {
        console.error('Error sending MCP message:', err);

        setResponse({ error: 'Request failed' });
      } finally {
        setLoading(false);
      }
  };

  return (
    <div>
      <br></br>
      <br></br>
      <h2> MCP Agent-to-Agent Interaction </h2>
      <div>

      <button className='service-button' onClick={handleMCPAgentToAgentEthSend} disabled={loading}>
        {loading ? 'Sending...' : 'MCP agent-to-agent request and fund withdrawal..  VP holding VC for dd:aa:eip155:...'}
      </button>
      <div className="balance-info" style={{ 
        marginTop: '20px', 
        padding: '15px',
        backgroundColor: '#f5f5f5',
        borderRadius: '8px',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
      }}>
        <h3 style={{ margin: '0 0 10px 0' }}>Wallet Balances</h3>
        <div style={{ display: 'flex', gap: '20px' }}>
          <div>
            <strong>Client EOA Address:</strong> {eoaAddress ? `${eoaAddress} ` : 'Loading...'}
          </div>
          <div>
            <strong>Client AA Wallet Balance:</strong> {aaWalletAddress ? `${aaWalletAddress} ` :  'Loading...' }
          </div>
        </div>
        <div style={{ display: 'flex', gap: '20px' }}>
          <div>
            <strong>Client EOA Balance:</strong> {eoaBalance ? `${eoaBalance} ETH` : 'Loading...'}
          </div>
          <div>
            <strong>Client AA Wallet Balance:</strong> {aaBalance ? `${aaBalance} ETH` : aaWalletAddress ? 'Loading...' : 'Not deployed'}
          </div>
        </div>
      </div>
      {response && (
        <div style={{ marginTop: 20, backgroundColor: 'black', color: 'white', padding: '2px 20px', borderRadius: '10px' }}>
          <h3>Response:</h3>
          <pre>{JSON.stringify(response, null, 2)}</pre>
        </div>
      )}
      </div>
      <br></br>
      <button className='service-button' onClick={handleMCPAgentToAgentUSDCSend} disabled={usdcTransferLoading}>
        {usdcTransferLoading ? 'Processing USDC Transfer...' : 'MCP agent-to-agent service agreement and CCTP v2 USDC transfer:aa:eip155:...'}
      </button>
      
      {usdcTransferResults && (
        <div style={{ 
          marginTop: '20px', 
          padding: '15px',
          backgroundColor: '#e8f5e8',
          borderRadius: '8px',
          border: '1px solid #28a745'
        }}>
          <h3 style={{ margin: '0 0 15px 0', color: '#155724' }}>
            USDC Cross Chain CCTP v2 Transfer Results
          </h3>
          
          <div style={{ 
            marginBottom: '10px', 
            padding: '10px',
            backgroundColor: 'white',
            borderRadius: '5px',
            border: '1px solid #d4edda'
          }}>
            
            <div>
              <strong>USDC Amount:</strong> 
              <span style={{ color: '#28a745', fontWeight: 'bold' }}>
                {usdcTransferResults.amount} USDC
              </span>
            </div>
            <div>
              <strong>Source Chain ID:</strong> {usdcTransferResults.sourceChainId}
            </div>
            <div>
              <strong>Source Address:</strong> 
              <span style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                {usdcTransferResults.sourceAddress}
              </span>
            </div>
            <div>
              <strong>Destination Chain ID:</strong> {usdcTransferResults.destinationChainId}
            </div>
            <div>
              <strong>Destination Address:</strong> 
              <span style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                {usdcTransferResults.destinationAddress}
              </span>
            </div>
          </div>
        </div>
      )}
      
      <br></br>
      <div>
        <h2>JWT transfer and signature verification using Web DID, Ethr DID, and AA DID</h2>
      </div>
      <br></br>
      <div>
      <button onClick={handleSendWebDIDJWT} >
        {loading ? 'Sending...' : 'Send Web DID JWT'}
      </button>
      </div>
      <br></br>
      <div>
      <button onClick={handleSendEthrDIDJWT} >
        {loading ? 'Sending...' : 'Send Ethr DID JWT'}
      </button>
      </div>
      <br></br>
      <div>
      <button onClick={handleSendAADIDJWT} >
        {loading ? 'Sending...' : 'Send AA DID JWT'}
      </button>
      </div>
      <br></br>
      <div>
      <button onClick={handleSendEOADelegatedDIDCommJWT} >
        {loading ? 'Sending...' : 'Send Delegated DIDComm JWT'}
      </button>
      </div>
      <br></br>
      <div>
      <button onClick={handleMetamaskCardEOAWithdrawRecipients} disabled={metamaskCardLoading}>
        {metamaskCardLoading ? 'Analyzing MetaMask Card...' : 'Check for MetaMask Card and Withdrawals'}
      </button>
      </div>
      
      {metamaskCardResults.length > 0 && (
        <div style={{ 
          marginTop: '20px', 
          padding: '15px',
          backgroundColor: '#f8f9fa',
          borderRadius: '8px',
          border: '1px solid #dee2e6'
        }}>
          <h3 style={{ margin: '0 0 15px 0', color: '#495057' }}>
            MetaMask Card Analysis Results 
            <span style={{ fontSize: '0.9em', fontWeight: 'normal', color: '#6c757d' }}>
              {' '}({metamaskCardResults.length} transactions found)
            </span>
          </h3>
          
          {metamaskCardResults.map((result, index) => (
            <div key={index} style={{ 
              marginBottom: '15px', 
              padding: '10px',
              backgroundColor: 'white',
              borderRadius: '5px',
              border: '1px solid #e9ecef'
            }}>
              {result.error ? (
                <div style={{ color: '#dc3545' }}>{result.error}</div>
              ) : (
                <>
                  <div style={{ marginBottom: '8px' }}>
                    <strong>Transaction:</strong> 
                    <a 
                      href={`https://lineascan.build/tx/${result.transactionHash}`} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      style={{ color: '#007bff', textDecoration: 'none', marginLeft: '5px' }}
                    >
                      {result.transactionHash.substring(0, 10)}...
                    </a>
                  </div>
                  <div style={{ marginBottom: '5px' }}>
                    <strong>Timestamp:</strong> {result.timestamp}
                  </div>
                  <div style={{ marginBottom: '5px' }}>
                    <strong>From (MetaMask Card EOA):</strong> 
                    <span style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                      {result.from}
                    </span>
                  </div>
                  <div style={{ marginBottom: '5px' }}>
                    <strong>To (Central Card Fund):</strong> 
                    <span style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                      {result.to}
                    </span>
                  </div>
                  <div style={{ marginBottom: '5px' }}>
                    <strong>USDC Amount:</strong> 
                    <span style={{ color: '#28a745', fontWeight: 'bold' }}>
                      {(BigInt(result.value) / BigInt(10 ** 6)).toString()} USDC
                    </span>
                  </div>
                  <div style={{ marginBottom: '5px' }}>
                    <strong>Token Contract:</strong> 
                    <span style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                      {result.tokenAddress}
                    </span>
                  </div>
                  <div style={{ marginBottom: '5px' }}>
                    <strong>Withdraw Originator:</strong> 
                    <span style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                      {result.withdrawOriginator}
                    </span>
                  </div>
                  <div>
                    <strong>Withdraw Processor:</strong> 
                    <span style={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                      {result.withdrawProcessor}
                    </span>
                  </div>
                </>
              )}
            </div>
          ))}
        </div>
      )}
      <br></br>
      <div>
      <button onClick={handlePermissionDelegation} >
        {loading ? 'permission delegation ...' : 'ERC-7715 Permission Delegation'}
      </button>
      </div>


      
      
    </div>
  );
};