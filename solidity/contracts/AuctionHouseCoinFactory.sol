// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./AuctionHouseCoin.sol";

contract AuctionHouseCoinFactory {
    function newAHCoin() public returns (address) {
        return address(new AuctionHouseCoin(msg.sender));
    }
}