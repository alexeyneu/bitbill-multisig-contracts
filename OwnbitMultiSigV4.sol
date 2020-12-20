pragma solidity ^0.5.3;
pragma experimental ABIEncoderV2;
// This is the ETH/ERC20 multisig contract for Ownbit.
//
// For 2-of-3 multisig, to authorize a spend, two signtures must be provided by 2 of the 3 owners.
// To generate the message to be signed, provide the destination address and
// spend amount (in wei) to the generateMessageToSign method.
// The signatures must be provided as the (v, r, s) hex-encoded coordinates.
// The S coordinate must be 0x00 or 0x01 corresponding to 0x1b and 0x1c, respectively.
//
// WARNING: The generated message is only valid until the next spend is executed.
//          after that, a new message will need to be calculated.
//
//
// INFO: This contract is ERC20 compatible.
// This contract can both receive ETH and ERC20 tokens.
// Notice that NFT (ERC721/ERC1155) is not supported. But can be transferred out throught spendAny.
// Last update time: 2020-12-12.

interface Erc20 {
  function approve(address, uint256) external;

  function transfer(address, uint256) external;
    
  //function balanceOf(address) view public returns (uint256);
}

contract MultiSig_with_mew {
    
  uint constant public MAX_OWNER_COUNT = 9;
  // The N addresses which control the funds in this contract. The
  // owners of M of these addresses will need to both sign a message
  // allowing the funds in this contract to be spent.
  mapping(address => bool) private isOwner;
  address[] private owners;
  uint private required;

  // The contract nonce is not accessible to the contract so we
  // implement a nonce-like variable for replay protection.
  uint256 private spendNonce = 0;
  
  // An event sent when funds are received.
  event Funded(address from, uint value);
  
  // An event sent when a spend is triggered to the given address.
  event Spent(address to, uint transfer);
  
  // An event sent when a spendERC20 is triggered to the given address.
  event SpentERC20(address erc20contract, address to, uint transfer);
  
  // An event sent when an spendAny is executed.
  event SpentAny(address to, uint transfer);

  modifier validRequirement(uint ownerCount, uint _required) {
    require (ownerCount <= MAX_OWNER_COUNT
            && _required <= ownerCount
            && _required >= 1);
    _;
  }
  
  /// @dev Contract constructor sets initial owners and required number of confirmations.
  /// @param _owners List of initial owners.
  /// @param _required Number of required confirmations.
  constructor(address[] memory _owners, uint _required) public validRequirement(_owners.length, _required) {
    for (uint i = 0; i < _owners.length; i++) {
        //onwer should be distinct, and non-zero
        if (isOwner[_owners[i]] || _owners[i] == address(0x0)) {
            revert();
        }
        isOwner[_owners[i]] = true;
    }
    owners = _owners;
    required = _required;
  }


  // The fallback function for this contract.
  function() external payable {
    if (msg.value > 0) {
        emit Funded(msg.sender, msg.value);
    }
  }
  
  // @dev Returns list of owners.
  // @return List of owner addresses.
  function getOwners() public view returns (address[] memory) {
    return owners;
  }
    
  function getSpendNonce() public view returns (uint256) {
    return spendNonce;
  }
    
  function getRequired() public view returns (uint) {
    return required;
  }

int8[256] p_util_hexdigit =
[ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1 ];

  function stringh(bytes memory x) private view returns(bytes32 fc) {
    bytes memory f = new bytes(32);
    for(uint k = 0; k < 32; k++) {
        int8 b = p_util_hexdigit[uint8(x[2*k])];
        f[k] =  byte(b << 4);
        b = p_util_hexdigit[uint8(x[2*k + 1])];
        f[k] |= byte(b);
    }

    assembly {
          fc := mload(add(f, 32))
    }

    return fc;
  }

  function hexbyte(bytes memory x) private view returns(uint8 fb) {
        int8 b = p_util_hexdigit[uint8(x[0])];
        fb =  uint8(b << 4);
        b = p_util_hexdigit[uint8(x[1])];
        fb = fb | uint8(b);
        return fb;
  }


function bytes32_to_hstring(bytes32 _bytes) private pure returns(bytes memory) {
    bytes memory HEX = "0123456789abcdef";
    bytes memory _string = new bytes(64);
    for(uint k = 0; k < 32; k++) {
        _string[k*2] = HEX[uint8(_bytes[k] >> 4)];
        _string[k*2 + 1] = HEX[uint8(_bytes[k] & 0x0f)];
    }
    return _string;
}


  function stringtosend(address destination, uint256 value) public view returns (string memory) {
    bytes32 hashedUnsignedMessage = generateMessageToSign(address(0x0), destination, value);
    bytes memory message = bytes32_to_hstring(hashedUnsignedMessage);
    return string(message);
  }
  // Generates the message to sign given the output destination address and amount.
  // includes this contract's address and a nonce for replay protection.
  // One option to independently verify: https://leventozturk.com/engineering/sha3/ and select keccak
  function generateMessageToSign(address erc20Contract, address destination, uint256 value) private view returns (bytes32) {
    //the sequence should match generateMultiSigV2 in JS
    // addr addr addr uint256 uint256
    bytes32 message = keccak256(abi.encodePacked(address(this), erc20Contract, destination, value, spendNonce));
    return message;
  }
  
  function _messageToRecover(address erc20Contract, address destination, uint256 value) private view returns (bytes32) {
    bytes32 hashedUnsignedMessage = generateMessageToSign(erc20Contract, destination, value);
    bytes memory message = bytes32_to_hstring(hashedUnsignedMessage);
    bytes memory prefix = "\x19Ethereum Signed Message:\n64";
    return keccak256(abi.encodePacked(prefix, message));
  }
  

 function splitSignaturehex(string memory sig)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s) {
        bytes memory k = bytes(sig);
        require(k.length == 130);
        delete k;       

        bytes32 rc1;
        bytes32 rc2;
        bytes32 sc1;
        bytes32 sc2;
        uint8 vc1;
        uint8 vc2;

        assembly {
            rc1 := mload(add(sig, 32))
            rc2 := mload(add(sig, 64))
            sc1 := mload(add(sig, 96))
            sc2 := mload(add(sig, 128))
            vc1 := byte(0, mload(add(sig, 160)))
            vc2 := byte(1, mload(add(sig, 160)))
        }
       r = stringh(abi.encodePacked(rc1,rc2));
       s = stringh(abi.encodePacked(sc1,sc2));
       v = hexbyte(abi.encodePacked(vc1,vc2));
        return (v, r, s);
    }


  // @destination: the ether receiver address.
  // @value: the ether value, in wei.
  // @vs, rs, ss: the signatures
  function spend(address destination, uint256 value, string[] memory signs) public {
    require(destination != address(this), "Not allow sending to yourself");
    require(address(this).balance >= value && value > 0, "balance or spend value invalid");
    uint8[] memory vs = new uint8[](signs.length);
    bytes32[] memory ss = new bytes32[](signs.length);
    bytes32[] memory rs = new bytes32[](signs.length);
    for(uint k = 0; k < vs.length; k++) { 
      (vs[k], rs[k], ss[k]) = splitSignaturehex(signs[k]);
    }

    require(_validSignature(address(0x0), destination, value, vs, rs, ss), "invalid signatures");
    spendNonce = spendNonce + 1;
    //transfer will throw if fails
    (bool success, ) = destination.call.value(value)("");
    require(success, "Transfer failed.");
    emit Spent(destination, value);
  }
  
  // @erc20contract: the erc20 contract address.
  // @destination: the token receiver address.
  // @value: the token value, in token minimum unit.
  // @vs, rs, ss: the signatures
  function spendERC20(address destination, address erc20contract, uint256 value, uint8[] memory vs, bytes32[] memory rs, bytes32[] memory ss) public {
    require(destination != address(this), "Not allow sending to yourself");
    //transfer erc20 token
    //uint256 tokenValue = Erc20(erc20contract).balanceOf(address(this));
    require(value > 0, "Erc20 spend value invalid");
    require(_validSignature(erc20contract, destination, value, vs, rs, ss), "invalid signatures");
    spendNonce = spendNonce + 1;
    // transfer tokens from this contract to the destination address
    Erc20(erc20contract).transfer(destination, value);
    emit SpentERC20(erc20contract, destination, value);
  }
  
  //0x9 is used for spendAny
  //be careful with any action, data is not included into signature computation. So any data can be included in spendAny.
  //This is usually for some emergent recovery, for example, recovery of NTFs, etc.
  //Owners should not generate 0x9 based signatures in normal cases.
  function spendAny(address destination, uint256 value, uint8[] memory vs, bytes32[] memory rs, bytes32[] memory ss, bytes memory data) public {
    require(destination != address(this), "Not allow sending to yourself");
    require(_validSignature(address(0x9), destination, value, vs, rs, ss), "invalid signatures");
    spendNonce = spendNonce + 1;
    //transfer tokens from this contract to the destination address
    (bool success, ) = destination.call.value(value)(data);
    require(success, "Transfer failed."); 
    emit SpentAny(destination, value);
  }

  // Confirm that the signature triplets (v1, r1, s1) (v2, r2, s2) ...
  // authorize a spend of this contract's funds to the given destination address.
  function _validSignature(address erc20Contract, address destination, uint256 value, uint8[] memory vs, bytes32[] memory rs, bytes32[] memory ss) private view returns (bool) {
    require(vs.length == rs.length);
    require(rs.length == ss.length);
    require(vs.length <= owners.length);
    require(vs.length >= required);
    bytes32 message = _messageToRecover(erc20Contract, destination, value);
    address[] memory addrs = new address[](vs.length);
    for (uint i = 0; i < vs.length; i++) {
        //recover the address associated with the public key from elliptic curve signature or return zero on error 
        addrs[i] = ecrecover(message, vs[i], rs[i], ss[i]);
    }
    require(_distinctOwners(addrs));
    return true;
  }
  
  // Confirm the addresses as distinct owners of this contract.
  function _distinctOwners(address[] memory addrs) private view returns (bool) {
    if (addrs.length > owners.length) {
        return false;
    }
    for (uint i = 0; i < addrs.length; i++) {
        if (!isOwner[addrs[i]]) {
            return false;
        }
        //address should be distinct
        for (uint j = 0; j < i; j++) {
            if (addrs[i] == addrs[j]) {
                return false;
            }
        }
    }
    return true;
  }
  
}
