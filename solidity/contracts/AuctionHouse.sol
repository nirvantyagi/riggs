pragma solidity ^0.8.11;

import "./RSA2048.sol";

// 0x6523784162348715238471625341873265421652378416234871523847162534


contract AuctionHouse {
    
    struct TCbid {
        bool opened;
        bytes pc;
        RSA2048.Element tc;
        // need a pedersen commitment element
        uint256 bid;
    }

    struct Auction {
        bytes32 auction_id;
        bool active;

        
        uint256 bid_bno;
        uint256 open_bno;
        TCbid[] bids;
        // bytes32[] bidKeys;
        // mapping(bytes32 => TCbid) bidMap;
    }

    uint public num_auctions;
    // Auction[] public auctions;

    mapping(bytes32 => Auction) auctionMap;
    bytes32[] auctionIDs;

    address public founder;

    constructor() {
        num_auctions = 0;
        founder = msg.sender;
    }

    function create_auction(bytes32 input_id) external {
        // uint ano = num_auctions;
        // auctions[ano].auction_id = num_auctions;
        // auctions[ano].active = true;
        // auctions[ano].bid_bno = 0;
        // auctions[ano].open_bno = 0;

        auctionMap[input_id].auction_id = input_id;
        auctionMap[input_id].active = true;
        auctionMap[input_id].bid_bno = 0;
        auctionMap[input_id].open_bno = 0;

        auctionIDs.push(input_id);
        num_auctions++;
    }

    // res = await instance.bid("0x6523784162348715238471625341873265421652378416234871523847162534", "0x00", "0x00")

    function bid(bytes32 auction_id, bytes calldata bid_pc, bytes calldata bid_tc) 
    external returns (uint) {
        // currently ignoring the pedersen part
        TCbid memory new_bid = TCbid(false, bid_pc, RSA2048._new(bid_tc), 0);

        auctionMap[auction_id].bids.push(new_bid);

	    //auctions[auction_id].bids.push(new_bid);
        return auctionMap[auction_id].bids.length;
    }

    function open_bid(bytes32 auction_id, uint bidno, uint bid_value, 
        bytes calldata open_pc, bytes calldata open_tc) 
    external {
        
    }

}
