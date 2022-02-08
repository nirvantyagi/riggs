pragma solidity 0.8.11;


import "./BigNumber.sol";

library RSA2048 {
  using BigNumber for *; 

  struct Element {
    BigNumber.instance bn;
  }

  function _new(bytes memory val) 
  internal pure returns (Element memory) {
      BigNumber.instance memory bni = BigNumber.instance(val, false, 2048);
      Element memory ret = Element(bni);
      return ret;
  }

  function as_bytes(Element memory a) 
  internal pure returns (bytes memory) {
      return a.bn.val;
  }

  function mul(Element memory a, uint b, Element memory modulus) 
  internal view returns (Element memory) {
      Element memory b_elem = _new(abi.encodePacked(b));
      return Element((a.bn).modmul(b_elem.bn, modulus.bn));
  }

  function mul(Element memory a, Element memory b, Element memory modulus) 
  internal view returns (Element memory) {
      return Element((a.bn).modmul(b.bn, modulus.bn));
  }

  function power(Element memory base, uint e, Element memory modulus) 
  internal view returns (Element memory) {
      Element memory e_elem = _new(abi.encodePacked(e));
      return Element((base.bn).prepare_modexp(e_elem.bn, modulus.bn));
  }

  function power(Element memory base, Element memory exponent, Element memory modulus) 
  internal view returns (Element memory) {
      return Element((base.bn).prepare_modexp(exponent.bn, modulus.bn));
  }

  function cmp(Element memory a, Element memory b) 
  internal pure returns (bool) {
      return (a.bn).cmp((b.bn),false) == 0;
  }

}