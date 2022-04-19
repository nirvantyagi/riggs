// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./TC.sol";
import "./BulletproofsVerifier.sol";
import "./IERC20.sol";
import "./IERC721.sol";

contract AuctionHouse is IERC165, IERC20, IERC20Metadata, IERC721Receiver {
    mapping(uint256 => Auction) active_auctions;
    uint256 ctr_auction;
    uint256 bid_collection_num_blocks;
    uint256 bid_self_open_num_blocks;

    // ERC-20
    string public constant erc20_name = "AuctionHouseCoin";
    string public constant erc20_symbol = "AHC";
    uint8 public constant erc20_decimals = 18;
    mapping(address => uint256) erc20_balances;
    mapping(address => mapping (address => uint256)) erc20_allowed;
    uint256 erc20_total_supply;

    struct Auction {
        uint256 start_block;
        uint256 bid_collection_end_block;
        uint256 bid_self_open_end_block;
        mapping(address => TC.Comm) bidder_to_comm;
        mapping(address => TC.Comm) bidder_to_bid;
        mapping(address => bool) bidders;
        mapping(bytes32 => bool) comms;
        uint256 bids_to_open;
        IERC721 token;
        uint256 token_id;
    }

    // TODO: Allow auctions to have different time parameters
    constructor(uint256 bid_collection_num_blocks_, uint256 bid_self_open_num_blocks_) {
        bid_collection_num_blocks = bid_collection_num_blocks_;
        bid_self_open_num_blocks = bid_self_open_num_blocks_;
    }

    enum AuctionPhase { BidCollection, BidSelfOpening, BidForceOpening, Complete }

    // IERC-165 Implementation
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return
        interfaceId == type(IERC20).interfaceId ||
        interfaceId == type(IERC20Metadata).interfaceId ||
        interfaceId == type(IERC721Receiver).interfaceId ||
        interfaceId == type(IERC165).interfaceId;
    }

    // IERC-20 Implementation
    function name() public view virtual override returns (string memory) {
        return erc20_name;
    }

    function symbol() public view virtual override returns (string memory) {
        return erc20_symbol;
    }

    function decimals() public view virtual override returns (uint8) {
        return erc20_decimals;
    }
    function totalSupply() public override view returns (uint256) {
        return erc20_total_supply;
    }

    function balanceOf(address tokenOwner) public override view returns (uint256) {
        return erc20_balances[tokenOwner];
    }

    function transfer(address receiver, uint256 numTokens) public override returns (bool) {
        require(numTokens <= erc20_balances[msg.sender], "ERC20: insufficient balance");
        erc20_balances[msg.sender] = erc20_balances[msg.sender]-numTokens;
        erc20_balances[receiver] = erc20_balances[receiver]+numTokens;
        emit Transfer(msg.sender, receiver, numTokens);
        return true;
    }

    function approve(address delegate, uint256 numTokens) public override returns (bool) {
        erc20_allowed[msg.sender][delegate] = numTokens;
        emit Approval(msg.sender, delegate, numTokens);
        return true;
    }

    function allowance(address owner, address delegate) public override view returns (uint) {
        return erc20_allowed[owner][delegate];
    }

    function transferFrom(address owner, address buyer, uint256 numTokens) public override returns (bool) {
        require(numTokens <= erc20_balances[owner], "ERC20: insufficient balance");
        require(numTokens <= erc20_allowed[owner][msg.sender], "ERC20: sender not allowed");

        erc20_balances[owner] = erc20_balances[owner]-numTokens;
        erc20_allowed[owner][msg.sender] = erc20_allowed[owner][msg.sender]-numTokens;
        erc20_balances[buyer] = erc20_balances[buyer]+numTokens;
        emit Transfer(owner, buyer, numTokens);
        return true;
    }

    // IERC-721 Receiver Implementation
    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) public override returns (bytes4) {
        return this.onERC721Received.selector;
    }

    // Auction House Implementation

    function newAuction(address token, uint256 token_id) public returns (uint256 id) {
        id = ctr_auction;
        Auction storage auction = active_auctions[id];
        auction.token = IERC721(token);
        auction.token_id = token_id;
        require(msg.sender == auction.token.ownerOf(token_id));
        auction.token.safeTransferFrom(msg.sender, address(this), token_id); // Transfer token to house
        auction.start_block = block.number;
        auction.bid_collection_end_block = block.number + bid_collection_num_blocks;
        auction.bid_self_open_end_block = block.number + bid_collection_num_blocks + bid_self_open_num_blocks;
        ctr_auction += 1;
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
