// Deploys ProvenanceRegistry and writes deployments/<network>.json, which the
// backend reads (and serves to the frontend) so nothing is hard-coded.
const fs = require("fs");
const path = require("path");
const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const registry = await hre.ethers.deployContract("ProvenanceRegistry");
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  const tx = registry.deploymentTransaction();
  const receipt = await tx.wait();
  const { chainId } = await hre.ethers.provider.getNetwork();
  const artifact = await hre.artifacts.readArtifact("ProvenanceRegistry");

  const out = {
    network: hre.network.name,
    chainId: Number(chainId),
    address,
    deployer: deployer.address,
    deployBlock: receipt.blockNumber,
    abi: artifact.abi,
  };
  const dir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${hre.network.name}.json`), JSON.stringify(out, null, 2));

  console.log(`ProvenanceRegistry deployed to ${address} on ${hre.network.name} (chain ${chainId})`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
