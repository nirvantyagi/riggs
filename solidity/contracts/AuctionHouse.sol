pragma solidity ^0.8.10;

import "./TC.sol";
import "./BulletproofsVerifier.sol";

contract AuctionHouse {
    mapping(uint256 => Auction) active_auctions;
    uint256 ctr_auction;
    uint256 bid_collection_num_blocks;
    uint256 bid_self_open_num_blocks;

    struct Auction {
        uint256 start_block;
        uint256 bid_collection_end_block;
        uint256 bid_self_open_end_block;
        mapping(address => TC.Comm) bidder_to_comm;
        mapping(address => TC.Comm) bidder_to_bid;
        mapping(address => bool) bidders;
        mapping(bytes32 => bool) comms;
        uint256 bids_to_open;
    }

    // TODO: Allow auctions to have different time parameters
    constructor(uint256 bid_collection_num_blocks_, uint256 bid_self_open_num_blocks_) {
        bid_collection_num_blocks = bid_collection_num_blocks_;
        bid_self_open_num_blocks = bid_self_open_num_blocks_;
    }

    enum AuctionPhase { BidCollection, BidSelfOpening, BidForceOpening, Complete }

    function newAuction() public returns (uint256 id) {
        id = ctr_auction;
        ctr_auction += 1;
        Auction storage auction = active_auctions[id];
        auction.start_block = block.number;
        auction.bid_collection_end_block = block.number + bid_collection_num_blocks;
        auction.bid_self_open_end_block = block.number + bid_collection_num_blocks + bid_self_open_num_blocks;
    }

    function getAuctionPhase(uint256 id) public view returns (AuctionPhase) {
        Auction storage auction = active_auctions[id];
        require(auction.start_block > 0);  // Check if auction id is valid
        if (auction.start_block <= block.number && block.number < auction.bid_collection_end_block) {
            return AuctionPhase.BidCollection;
        } else if (auction.bids_to_open == 0) {
            return AuctionPhase.Complete;
        } else if (auction.bid_collection_end_block <= block.number && block.number < auction.bid_self_open_end_block) {
            return AuctionPhase.BidSelfOpening;
        } else {
            return AuctionPhase.BidForceOpening;
        }
    }

    function bidAuction(uint256 id) public returns (bool) {
        Auction storage auction = active_auctions[id];
        require(auction.start_block > 0);  // Check if auction id is valid
        auction.bids_to_open += 1;
        return true;
    }

}
