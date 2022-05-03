// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./BN254.sol";
import "./Pedersen.sol";
import "./TC.sol";
import "./BulletproofsVerifier.sol";
import "./IERC20.sol";
import "./IERC721.sol";
import "./AuctionHouseCoin.sol";

contract AuctionHouse is IERC721Receiver {
    AuctionHouseCoin AHC_contract;

    mapping(uint256 => Auction) active_auctions;
    uint256 ctr_auction;
    uint256 bid_collection_num_blocks;
    uint256 bid_self_open_num_blocks;
    uint256 reward_self_open;
    uint256 reward_force_open;
    // mapping(address => uint256) balances;
    mapping(address => BN254.G1Point) active_bid_comms;

    // // ERC-20
    // string public constant erc20_name = "AuctionHouseCoin";
    // string public constant erc20_symbol = "AHC";
    // uint8 public constant erc20_decimals = 18;
    // mapping(address => uint256) erc20_balances;
    // mapping(address => mapping (address => uint256)) erc20_allowed;
    // uint256 erc20_total_supply;

    struct Auction {
        uint256 start_block;
        uint256 bid_collection_end_block;
        uint256 bid_self_open_end_block;
        mapping(address => TC.Comm) bidder_to_comm;
        mapping(address => uint256) bidder_to_bid;
        mapping(address => bool) bidders;
        address[] bidders_list;
        mapping(bytes32 => bool) comms;
        uint256 bids_to_open;
        uint256 total_valid_bids;
        IERC721 token;
        uint256 token_id;
        address owner;
    }

    // TODO: Allow auctions to have different time parameters
    constructor(
            address AHC_contract_addr,
            uint256 bid_collection_num_blocks_,
            uint256 bid_self_open_num_blocks_,
            uint256 reward_self_open_,
            uint256 reward_force_open_) {
        AHC_contract = AuctionHouseCoin(AHC_contract_addr);
        bid_collection_num_blocks = bid_collection_num_blocks_;
        bid_self_open_num_blocks = bid_self_open_num_blocks_;
        reward_self_open = reward_self_open_;
        reward_force_open = reward_force_open_;
    }

    enum AuctionPhase { BidCollection, BidSelfOpening, BidForceOpening, Complete }

    // // IERC-165 Implementation

    // function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
    //     return
    //     interfaceId == type(IERC20).interfaceId ||
    //     interfaceId == type(IERC20Metadata).interfaceId ||
    //     interfaceId == type(IERC721Receiver).interfaceId ||
    //     interfaceId == type(IERC165).interfaceId;
    // }

    // // IERC-20 Implementation

    // function name() public view virtual override returns (string memory) {
    //     return erc20_name;
    // }

    // function symbol() public view virtual override returns (string memory) {
    //     return erc20_symbol;
    // }

    // function decimals() public view virtual override returns (uint8) {
    //     return erc20_decimals;
    // }
    // function totalSupply() public override view returns (uint256) {
    //     return erc20_total_supply;
    // }

    // function balanceOf(address tokenOwner) public override view returns (uint256) {
    //     return erc20_balances[tokenOwner];
    // }

    // function transfer(address receiver, uint256 numTokens) public override returns (bool) {
    //     require(numTokens <= erc20_balances[msg.sender], "ERC20: insufficient balance");
    //     erc20_balances[msg.sender] = erc20_balances[msg.sender]-numTokens;
    //     erc20_balances[receiver] = erc20_balances[receiver]+numTokens;
    //     emit Transfer(msg.sender, receiver, numTokens);
    //     return true;
    // }

    // function approve(address delegate, uint256 numTokens) public override returns (bool) {
    //     erc20_allowed[msg.sender][delegate] = numTokens;
    //     emit Approval(msg.sender, delegate, numTokens);
    //     return true;
    // }

    // function allowance(address owner, address delegate) public override view returns (uint) {
    //     return erc20_allowed[owner][delegate];
    // }

    // function transferFrom(address owner, address buyer, uint256 numTokens) public override returns (bool) {
    //     require(numTokens <= erc20_balances[owner], "ERC20: insufficient balance");
    //     require(numTokens <= erc20_allowed[owner][msg.sender], "ERC20: sender not allowed");

    //     erc20_balances[owner] = erc20_balances[owner]-numTokens;
    //     erc20_allowed[owner][msg.sender] = erc20_allowed[owner][msg.sender]-numTokens;
    //     erc20_balances[buyer] = erc20_balances[buyer]+numTokens;
    //     emit Transfer(owner, buyer, numTokens);
    //     return true;
    // }

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

    // function exchangeAHCFromEther() payable public {
    //     uint256 amt = msg.value;
    //     require(amt > 0, "You need to send some ether");
    //     erc20_total_supply += amt;
    //     erc20_balances[msg.sender] += amt;
    // }

    // function exchangeAHCToEther(uint256 amt) public {
    //     require(erc20_balances[msg.sender] >= amt, "Insufficient balance");
    //     require(address(this).balance >= amt, "Contract has insufficient balance"); // Should not occur
    //     erc20_balances[msg.sender] -= amt;
    //     payable(msg.sender).transfer(amt);
    // }

    // function deposit(uint256 amt) public {
    //     this.transferFrom(msg.sender, address(this), amt);
    //     balances[msg.sender] += amt;
    // }

    function queryDeposit(address user) public view returns (uint256) {
      return AHC_contract.queryDeposit(user);
    }

    function setDeposit(address user, uint256 amount) public {
      return AHC_contract.setDeposit(user, amount);
    }

    function incrementDeposit(address user, uint256 amount) public {
      return AHC_contract.incrementDeposit(user, amount);
    }

    function decrementDeposit(address user, uint256 amount) public {
      return AHC_contract.decrementDeposit(user, amount);
    }



    // TODO: Optimization: Shouldn't need to provide range proof if no active bids
    function withdraw(uint256 amt, BulletproofsVerifier.Proof memory proof) public {
        uint256 balance_less_amt = queryDeposit(msg.sender) - amt;
        BN254.G1Point storage active_bids_comm = active_bid_comms[msg.sender];
        BN254.G1Point memory ped_g = Pedersen.publicParams().G;
        BN254.G1Point memory balance_comm = BN254.g1add(BN254.g1mul(ped_g, balance_less_amt), BN254.g1negate(active_bids_comm));
        require(BulletproofsVerifier.verify(balance_comm, proof));
        AHC_contract.transfer(msg.sender, amt); // !!!
        // balances[msg.sender] = balance_less_amt;
        setDeposit(msg.sender, balance_less_amt);
    }

    function newAuction(address token, uint256 token_id) public returns (uint256 id) {
        id = ctr_auction;
        Auction storage auction = active_auctions[id];
        auction.token = IERC721(token);
        auction.token_id = token_id;
        require(msg.sender == auction.token.ownerOf(token_id));  
        auction.token.safeTransferFrom(msg.sender, address(this), token_id); // Transfer token to house
        auction.owner = msg.sender;
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

    function bidAuction(
            uint256 id,
            TC.Comm memory bid_comm,
            BulletproofsVerifier.Proof memory bid_proof,
            BulletproofsVerifier.Proof memory balance_proof) public {

        require(getAuctionPhase(id) == AuctionPhase.BidCollection);
        Auction storage auction = active_auctions[id];
        require(!auction.bidders[msg.sender]);  // TODO: Allow multiple bids by single account
        bytes32 comm_hash = keccak256(abi.encodePacked(bid_comm.ped.X, bid_comm.ped.Y, bid_comm.fkps.h_hat.n.val, bid_comm.fkps.ct));
        require(!auction.comms[comm_hash]);  // Prevent duplicate bids

        // Verify bid > 0
        require(BulletproofsVerifier.verify(bid_comm.ped, bid_proof));

        // Verify balance - reward - bid - active_bids > 0
        uint256 balance_less_reward = queryDeposit(msg.sender) - reward_self_open - reward_force_open;
        BN254.G1Point storage active_bids_comm = active_bid_comms[msg.sender];
        BN254.G1Point memory ped_g = Pedersen.publicParams().G;
        BN254.G1Point memory balance_comm = BN254.g1add(BN254.g1mul(ped_g, balance_less_reward), BN254.g1negate(bid_comm.ped));
        balance_comm = BN254.g1add(balance_comm, BN254.g1negate(active_bids_comm));
        require(BulletproofsVerifier.verify(balance_comm, balance_proof));

        // Update state
        // balances[msg.sender] = balance_less_reward;
        setDeposit(msg.sender, balance_less_reward);
        active_bid_comms[msg.sender] = BN254.g1add(active_bids_comm, bid_comm.ped);
        auction.bidders[msg.sender] = true;
        auction.bidders_list.push(msg.sender);
        auction.comms[comm_hash] = true;
        auction.bidder_to_comm[msg.sender] = bid_comm;
        auction.bids_to_open += 1;
    }

    function getNumBidsToOpen(uint256 id) public view returns (uint256) {
        Auction storage auction = active_auctions[id];
        return auction.bids_to_open; 
    }

    function selfOpenAuction(uint256 id, uint256 bid, TC.SelfOpening memory opening) public {
        require(getAuctionPhase(id) == AuctionPhase.BidSelfOpening);
        Auction storage auction = active_auctions[id];
        require(auction.bidders[msg.sender]);  // Check if bidder does not exist or already opened

        // Verify opening
        require(TC.verOpen(auction.bidder_to_comm[msg.sender], opening, bid, TC.publicParams()));

        // Update state
        // balances[msg.sender] += (reward_self_open + reward_force_open);
        incrementDeposit(msg.sender, reward_self_open + reward_force_open);
        auction.bidders[msg.sender] = false;  // TODO: Support multiple bids from single account
        auction.bidder_to_bid[msg.sender] = bid;
        auction.bids_to_open -= 1;
        if (bid > 0) { auction.total_valid_bids += 1; }
    }

    function forceOpenAuction(uint256 id, address bidder, uint256 bid, TC.ForceOpening memory opening) public {
        require(getAuctionPhase(id) == AuctionPhase.BidForceOpening);
        Auction storage auction = active_auctions[id];
        require(auction.bidders[bidder]);  // Check if bidder does not exist or already opened

        // Verify opening
        require(TC.verForceOpen(auction.bidder_to_comm[bidder], opening, bid, TC.publicParams()));

        // Update state
        // balances[msg.sender] += reward_force_open;
        incrementDeposit(msg.sender, reward_force_open);
        auction.bidders[bidder] = false;  // TODO: Support multiple bids from single account
        auction.bidder_to_bid[bidder] = bid;
        auction.bids_to_open -= 1;
        if (bid > 0) { auction.total_valid_bids += 1; }
    }

    // TODO: Provide compensation to user that completes auction
    // TODO: Ties are awarded to first bidder
    function completeAuction(uint256 id) public {
        require(getAuctionPhase(id) == AuctionPhase.Complete);
        Auction storage auction = active_auctions[id];

        address winner;
        uint256 price;

        if (auction.total_valid_bids == 0) {
            // Return token to owner
            auction.token.transferFrom(address(this), auction.owner, auction.token_id);
            return;
        } else if (auction.total_valid_bids == 1) {
            for (uint i; i < auction.bidders_list.length; i++) {
                address bidder = auction.bidders_list[i];
                if (auction.bidder_to_bid[bidder] > 0) {
                    winner = bidder;
                    price = auction.bidder_to_bid[bidder];
                }
            }
        } else {
            address high_bidder = auction.bidders_list[0];
            address second_bidder = auction.bidders_list[1];
            if (auction.bidder_to_bid[second_bidder] > auction.bidder_to_bid[high_bidder]) {
                high_bidder = auction.bidders_list[1];
                second_bidder = auction.bidders_list[0];
            }
            for (uint i = 2; i < auction.bidders_list.length; i++) {
                address bidder = auction.bidders_list[i];
                uint256 bid = auction.bidder_to_bid[bidder];
                if (bid > auction.bidder_to_bid[high_bidder]) {
                    second_bidder = high_bidder;
                    high_bidder = bidder;
                } else if (bid > auction.bidder_to_bid[second_bidder]) {
                    second_bidder = bidder;
                }
            }
            winner = high_bidder;
            price = auction.bidder_to_bid[second_bidder];
        }

        // Update state
        for (uint i; i < auction.bidders_list.length; i++) {  // Remove bid commitment from active bids
            address bidder = auction.bidders_list[i];
            BN254.G1Point storage active_bids_comm = active_bid_comms[bidder];
            active_bid_comms[bidder] = BN254.g1add(active_bids_comm, BN254.g1negate(auction.bidder_to_comm[bidder].ped));
        }
        // balances[winner] -= price;
        // balances[auction.owner] += price;
        decrementDeposit(winner, price);
        incrementDeposit(auction.owner, price);
        auction.token.transferFrom(address(this), winner, auction.token_id);
        auction.start_block = 0;
    }

}
