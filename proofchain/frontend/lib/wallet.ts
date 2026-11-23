import { BrowserProvider, Contract, JsonRpcProvider, type Signer } from "ethers";
import type { ChainConfig } from "./api";

export type Wallet = { signer: Signer; address: string; label: string };

declare global {
  interface Window {
    ethereum?: any;
  }
}

export const hasInjectedWallet = () => typeof window !== "undefined" && !!window.ethereum;

/** Connect MetaMask (or any injected wallet) and make sure it is on the registry's chain. */
export async function connectInjected(cfg: ChainConfig): Promise<Wallet> {
  if (!window.ethereum) throw new Error("No browser wallet found. Install MetaMask, or use a local dev account.");
  const chainHex = "0x" + cfg.chainId.toString(16);
  await window.ethereum.request({ method: "eth_requestAccounts" });
  try {
    await window.ethereum.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chainHex }] });
  } catch (err: any) {
    if (err?.code === 4902 && cfg.rpcUrl) {
      await window.ethereum.request({
        method: "wallet_addEthereumChain",
        params: [{
          chainId: chainHex,
          chainName: "Hardhat Local",
          rpcUrls: [cfg.rpcUrl],
          nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
        }],
      });
    } else {
      throw new Error(`Please switch your wallet to ${cfg.network} (chain ${cfg.chainId}).`);
    }
  }
  const signer = await new BrowserProvider(window.ethereum).getSigner();
  return { signer, address: await signer.getAddress(), label: "Browser wallet" };
}

/** Local development only: use one of the Hardhat node's unlocked accounts.
 *  No key is handled here; the node signs. Unavailable on real networks. */
export async function connectDev(cfg: ChainConfig, index: number): Promise<Wallet> {
  if (!cfg.rpcUrl) throw new Error("Dev accounts are only available on a local chain.");
  const signer = await new JsonRpcProvider(cfg.rpcUrl).getSigner(index);
  return { signer, address: await signer.getAddress(), label: `Local dev account #${index}` };
}

export const registry = (cfg: ChainConfig, signer: Signer) => new Contract(cfg.address, cfg.abi, signer);

/** Turn an ethers/contract error into something a person can read. */
export function explainTxError(err: any): string {
  const name = err?.revert?.name;
  const known: Record<string, string> = {
    AlreadyRegistered: "This fingerprint is already registered.",
    NotCreator: "Only the wallet that registered the previous version can do this.",
    ParentNotFound: "The previous version is not registered on-chain.",
    ParentRevoked: "The previous version was revoked, so it cannot have new versions.",
    EmptyName: "Enter a display name.",
  };
  if (name && known[name]) return known[name];
  if (err?.code === "ACTION_REJECTED") return "You rejected the request in your wallet.";
  if (err?.code === "INSUFFICIENT_FUNDS") return "This wallet does not have enough ETH to pay for gas.";
  return err?.shortMessage || err?.message || "Transaction failed.";
}
