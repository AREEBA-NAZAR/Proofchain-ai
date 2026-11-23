const { expect } = require("chai");
const { ethers } = require("hardhat");

const h = (s) => ethers.sha256(ethers.toUtf8Bytes(s));
const ZERO = ethers.ZeroHash;

describe("ProvenanceRegistry", function () {
  let registry, admin, alice, bob;

  beforeEach(async function () {
    [admin, alice, bob] = await ethers.getSigners();
    registry = await ethers.deployContract("ProvenanceRegistry");
  });

  describe("register", function () {
    it("stores an original record and emits Registered", async function () {
      await expect(registry.connect(alice).register(h("v1"), ZERO, "ipfs://meta"))
        .to.emit(registry, "Registered");

      const r = await registry.getRecord(h("v1"));
      expect(r.creator).to.equal(alice.address);
      expect(r.version).to.equal(1);
      expect(r.parentHash).to.equal(ZERO);
      expect(r.rootHash).to.equal(h("v1"));
      expect(r.metadataURI).to.equal("ipfs://meta");
      expect(r.revoked).to.equal(false);
      expect(r.timestamp).to.be.greaterThan(0);
      expect(await registry.recordCount()).to.equal(1);
      expect(await registry.isRegistered(h("v1"))).to.equal(true);
    });

    it("rejects the zero hash and duplicates, even from another wallet", async function () {
      await expect(registry.register(ZERO, ZERO, "")).to.be.revertedWithCustomError(registry, "EmptyHash");
      await registry.connect(alice).register(h("v1"), ZERO, "");
      await expect(registry.connect(bob).register(h("v1"), ZERO, ""))
        .to.be.revertedWithCustomError(registry, "AlreadyRegistered");
    });

    it("reverts getRecord for unknown hashes", async function () {
      await expect(registry.getRecord(h("nope"))).to.be.revertedWithCustomError(registry, "NotFound");
      expect(await registry.isRegistered(h("nope"))).to.equal(false);
    });
  });

  describe("versions", function () {
    beforeEach(async function () {
      await registry.connect(alice).register(h("v1"), ZERO, "");
    });

    it("links a new version to its parent and root", async function () {
      await registry.connect(alice).register(h("v2"), h("v1"), "");
      await registry.connect(alice).register(h("v3"), h("v2"), "");

      const v3 = await registry.getRecord(h("v3"));
      expect(v3.version).to.equal(3);
      expect(v3.parentHash).to.equal(h("v2"));
      expect(v3.rootHash).to.equal(h("v1"));
      expect(await registry.getChildren(h("v1"))).to.deep.equal([h("v2")]);
      expect(await registry.getRecordsByCreator(alice.address)).to.deep.equal([h("v1"), h("v2"), h("v3")]);
    });

    it("only lets the parent's creator add a version", async function () {
      await expect(registry.connect(bob).register(h("v2"), h("v1"), ""))
        .to.be.revertedWithCustomError(registry, "NotCreator");
    });

    it("rejects an unknown or revoked parent", async function () {
      await expect(registry.connect(alice).register(h("v2"), h("ghost"), ""))
        .to.be.revertedWithCustomError(registry, "ParentNotFound");
      await registry.connect(alice).revoke(h("v1"), "mistake");
      await expect(registry.connect(alice).register(h("v2"), h("v1"), ""))
        .to.be.revertedWithCustomError(registry, "ParentRevoked");
    });
  });

  describe("revoke", function () {
    beforeEach(async function () {
      await registry.connect(alice).register(h("v1"), ZERO, "");
    });

    it("lets only the creator revoke, once", async function () {
      await expect(registry.connect(bob).revoke(h("v1"), "x"))
        .to.be.revertedWithCustomError(registry, "NotCreator");
      await expect(registry.connect(alice).revoke(h("v1"), "published in error"))
        .to.emit(registry, "Revoked").withArgs(h("v1"), alice.address, "published in error");
      expect((await registry.getRecord(h("v1"))).revoked).to.equal(true);
      await expect(registry.connect(alice).revoke(h("v1"), "again"))
        .to.be.revertedWithCustomError(registry, "AlreadyRevoked");
    });

    it("reverts for unknown hashes", async function () {
      await expect(registry.revoke(h("nope"), "")).to.be.revertedWithCustomError(registry, "NotFound");
    });
  });

  describe("identity", function () {
    it("self-declares a profile that starts unverified", async function () {
      await expect(registry.connect(alice).setIdentity("Alice Press", "ipfs://alice"))
        .to.emit(registry, "IdentityUpdated").withArgs(alice.address, "Alice Press", "ipfs://alice");
      const id = await registry.identities(alice.address);
      expect(id.name).to.equal("Alice Press");
      expect(id.verified).to.equal(false);
      await expect(registry.connect(alice).setIdentity("", "")).to.be.revertedWithCustomError(registry, "EmptyName");
    });

    it("only the admin can verify, and only existing profiles", async function () {
      await expect(registry.setVerified(alice.address, true)).to.be.revertedWithCustomError(registry, "NotFound");
      await registry.connect(alice).setIdentity("Alice Press", "");
      await expect(registry.connect(bob).setVerified(alice.address, true))
        .to.be.revertedWithCustomError(registry, "NotAdmin");
      await registry.setVerified(alice.address, true);
      expect((await registry.identities(alice.address)).verified).to.equal(true);
    });

    it("clears verification when the profile changes", async function () {
      await registry.connect(alice).setIdentity("Alice Press", "");
      await registry.setVerified(alice.address, true);
      await registry.connect(alice).setIdentity("Totally A Bank", "");
      expect((await registry.identities(alice.address)).verified).to.equal(false);
    });
  });

  describe("admin", function () {
    it("transfers admin rights", async function () {
      await expect(registry.connect(bob).transferAdmin(bob.address))
        .to.be.revertedWithCustomError(registry, "NotAdmin");
      await expect(registry.transferAdmin(ethers.ZeroAddress))
        .to.be.revertedWithCustomError(registry, "ZeroAddress");
      await registry.transferAdmin(bob.address);
      expect(await registry.admin()).to.equal(bob.address);
    });
  });
});
