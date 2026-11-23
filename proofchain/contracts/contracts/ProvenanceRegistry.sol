// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ProofChain ProvenanceRegistry
/// @notice Append-only registry of content fingerprints.
/// @dev A record proves that `creator` registered `contentHash` at `timestamp`
///      and that the record has not changed since. It does NOT prove the
///      content is truthful, nor that the registrant is the original author.
contract ProvenanceRegistry {
    struct Record {
        address creator; // wallet that signed the registration transaction
        uint64 timestamp; // block timestamp of registration
        uint32 version; // 1 for an original, parent.version + 1 for a revision
        bool revoked; // creator has withdrawn their attestation
        bytes32 parentHash; // previous version (0x0 for an original)
        bytes32 rootHash; // first version in the lineage
        string metadataURI; // off-chain metadata (ipfs://… or https://…)
    }

    struct Identity {
        string name;
        string metadataURI;
        bool verified; // attested by the registry admin (e.g. an institution check)
        uint64 registeredAt;
    }

    address public admin;
    uint256 public recordCount;

    mapping(bytes32 => Record) private _records;
    mapping(bytes32 => bytes32[]) private _children;
    mapping(address => bytes32[]) private _byCreator;
    mapping(address => Identity) public identities;

    event Registered(
        bytes32 indexed contentHash,
        address indexed creator,
        bytes32 indexed parentHash,
        bytes32 rootHash,
        uint32 version,
        uint64 timestamp,
        string metadataURI
    );
    event Revoked(bytes32 indexed contentHash, address indexed creator, string reason);
    event IdentityUpdated(address indexed account, string name, string metadataURI);
    event IdentityVerified(address indexed account, bool verified);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    error EmptyHash();
    error AlreadyRegistered(bytes32 contentHash);
    error ParentNotFound(bytes32 parentHash);
    error NotCreator();
    error NotAdmin();
    error NotFound(bytes32 contentHash);
    error AlreadyRevoked();
    error ParentRevoked();
    error ZeroAddress();
    error EmptyName();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor() {
        admin = msg.sender;
        emit AdminTransferred(address(0), msg.sender);
    }

    // ---------------------------------------------------------------- records

    /// @notice Register a content fingerprint. Pass parentHash = 0x0 for an
    ///         original, or an existing hash you created to register a new version.
    function register(bytes32 contentHash, bytes32 parentHash, string calldata metadataURI) external {
        if (contentHash == bytes32(0)) revert EmptyHash();
        if (_records[contentHash].timestamp != 0) revert AlreadyRegistered(contentHash);

        uint32 version = 1;
        bytes32 rootHash = contentHash;

        if (parentHash != bytes32(0)) {
            Record storage parent = _records[parentHash];
            if (parent.timestamp == 0) revert ParentNotFound(parentHash);
            if (parent.creator != msg.sender) revert NotCreator();
            if (parent.revoked) revert ParentRevoked();
            version = parent.version + 1;
            rootHash = parent.rootHash;
            _children[parentHash].push(contentHash);
        }

        uint64 ts = uint64(block.timestamp);
        _records[contentHash] = Record({
            creator: msg.sender,
            timestamp: ts,
            version: version,
            revoked: false,
            parentHash: parentHash,
            rootHash: rootHash,
            metadataURI: metadataURI
        });
        _byCreator[msg.sender].push(contentHash);
        recordCount += 1;

        emit Registered(contentHash, msg.sender, parentHash, rootHash, version, ts, metadataURI);
    }

    /// @notice Withdraw your attestation. The record stays on chain, flagged as revoked.
    function revoke(bytes32 contentHash, string calldata reason) external {
        Record storage r = _records[contentHash];
        if (r.timestamp == 0) revert NotFound(contentHash);
        if (r.creator != msg.sender) revert NotCreator();
        if (r.revoked) revert AlreadyRevoked();
        r.revoked = true;
        emit Revoked(contentHash, msg.sender, reason);
    }

    function isRegistered(bytes32 contentHash) external view returns (bool) {
        return _records[contentHash].timestamp != 0;
    }

    function getRecord(bytes32 contentHash) external view returns (Record memory) {
        Record memory r = _records[contentHash];
        if (r.timestamp == 0) revert NotFound(contentHash);
        return r;
    }

    function getChildren(bytes32 contentHash) external view returns (bytes32[] memory) {
        return _children[contentHash];
    }

    function getRecordsByCreator(address creator) external view returns (bytes32[] memory) {
        return _byCreator[creator];
    }

    // -------------------------------------------------------------- identity

    /// @notice Self-declare a display name. Unverified until the admin attests it.
    ///         Changing the profile clears any existing verification.
    function setIdentity(string calldata name, string calldata metadataURI) external {
        if (bytes(name).length == 0) revert EmptyName();
        Identity storage id = identities[msg.sender];
        id.name = name;
        id.metadataURI = metadataURI;
        if (id.registeredAt == 0) id.registeredAt = uint64(block.timestamp);
        if (id.verified) {
            id.verified = false;
            emit IdentityVerified(msg.sender, false);
        }
        emit IdentityUpdated(msg.sender, name, metadataURI);
    }

    function setVerified(address account, bool verified) external onlyAdmin {
        if (identities[account].registeredAt == 0) revert NotFound(bytes32(uint256(uint160(account))));
        identities[account].verified = verified;
        emit IdentityVerified(account, verified);
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }
}
