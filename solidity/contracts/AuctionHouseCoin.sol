// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./BN254.sol";
import "./Pedersen.sol";
import "./BulletproofsVerifier.sol";
import "./IERC20.sol";
import "./IERC721.sol";

contract AuctionHouseCoin is IERC165, IERC20, IERC20Metadata, IERC721Receiver {

    mapping(address => uint256) balances;

    // ERC-20
    string public constant erc20_name = "AuctionHouseCoin";
    string public constant erc20_symbol = "AHC";
    uint8 public constant erc20_decimals = 18;
    mapping(address => uint256) erc20_balances;
    mapping(address => mapping (address => uint256)) erc20_allowed;
    uint256 erc20_total_supply;

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

    function exchangeAHCFromEther() payable public {
        uint256 amt = msg.value;
        require(amt > 0, "You need to send some ether");
        erc20_total_supply += amt;
        erc20_balances[msg.sender] += amt;
    }

    function exchangeAHCToEther(uint256 amt) public {
        require(erc20_balances[msg.sender] >= amt, "Insufficient balance");
        require(address(this).balance >= amt, "Contract has insufficient balance"); // Should not occur
        erc20_balances[msg.sender] -= amt;
        payable(msg.sender).transfer(amt);
    }

    function deposit(uint256 amt) public {
        this.transferFrom(msg.sender, address(this), amt);
        balances[msg.sender] += amt;
    }

    // // TODO: Optimization: Shouldn't need to provide range proof if no active bids
    // function withdraw(uint256 amt, BulletproofsVerifier.Proof memory proof) public {
    //     uint256 balance_less_amt = balances[msg.sender] - amt;
    //     BN254.G1Point storage active_bids_comm = active_bid_comms[msg.sender];
    //     BN254.G1Point memory ped_g = Pedersen.publicParams().G;
    //     BN254.G1Point memory balance_comm = BN254.g1add(BN254.g1mul(ped_g, balance_less_amt), BN254.g1negate(active_bids_comm));
    //     require(BulletproofsVerifier.verify(balance_comm, proof));
    //     this.transfer(msg.sender, amt);
    //     balances[msg.sender] = balance_less_amt;
    // }

    function queryDeposit(address user) external view returns (uint256) {
      return balances[msg.sender];
    }

    function setDeposit(address user, uint256 amount) public {
      balances[msg.sender] = amount;
    }

    function incrementDeposit(address user, uint256 amount) public {
      balances[msg.sender] += amount;
    }

    function decrementDeposit(address user, uint256 amount) public {
      balances[msg.sender] -= amount;
    }

}
