// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IBitTorrent {
    event TorrentAdded(bytes32 indexed torrentHash, address indexed owner);
    event TorrentRemoved(bytes32 indexed torrentHash, address indexed remover);
    event SwarmJoined(bytes32 indexed torrentHash, address indexed peer);
    event SwarmLeft(bytes32 indexed torrentHash, address indexed peer);

    function addTorrent(bytes32 torrentHash, bytes memory metadata) external;
    function joinSwarm(bytes32 torrentHash) external;
    function leaveSwarm(bytes32 torrentHash) external;
    function getTorrentMetadata(bytes32 torrentHash) external view returns (bytes memory);
    function getSwarmPeers(bytes32 torrentHash) external view returns (address[] memory);
    function isPeerInSwarm(bytes32 torrentHash, address peer) external view returns (bool);
    function removeTorrent(bytes32 torrentHash) external;
}