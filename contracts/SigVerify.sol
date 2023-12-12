pragma solidity >=0.8.0 <0.9.0;

import "hardhat/console.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

//SPDX-License-Identifier: MIT
contract SigVerify {
    // the version header of the eip191
    bytes25 constant EIP191_VERSION_E_HEADER = "Ethereum Signed Message:\n";

    // the prefix of did, which is 'did::zk'
    bytes7 constant DID_ZK_PREFIX = bytes7("did:zk:");

    // the length of the CredentialVersionedDigest, which likes 0x1b32b6e54e4420cfaf2feecdc0a15dc3fc0a7681687123a0f8cb348b451c2989
    // length 32
    bytes2 constant EIP191_CRE_VERSION_DIGEST_LEN_V1 = 0x3332;

    struct PublicVC {
        address userDID;
        bytes32 ctype;
        bytes issuanceDate;
        bytes expirationDate;
        uint256 amount;
        address onChainAddr;
        bytes vcProof;
        address attesterAssertionMethod;
    }

    struct PrivateVC {
        address userDID;
        bytes32 ctype;
        bytes issuanceDate;
        bytes expirationDate;
        uint256 amount;
        bytes32 amountNonce;
        address onChainAddr;
        bytes32 onChainAddrNonce;
        bytes vcProof;
        address attesterAssertionMethod;
    }

    function verifyPublicVC(
         PublicVC calldata publicVC
    ) external view returns (bool, address, uint256) {
        (bool verifyVC, address onChainAddr, uint256 amount) = verifyPublicVCAttesterSignature(
            publicVC.attesterAssertionMethod,
            publicVC.vcProof,
            publicVC.issuanceDate,
            publicVC.expirationDate,
            publicVC.onChainAddr,
            publicVC.userDID,
            publicVC.ctype,
            publicVC.amount);

        return (verifyVC, onChainAddr, amount);
    }

    function verifyPrivateVC(
         PrivateVC calldata privateVC
    ) external view returns (bool, address, uint256) {
        (bool verifyVC, address onChainAddr, uint256 amount) = verifyPrivateVCAttesterSignature(
            privateVC.attesterAssertionMethod,
            privateVC.vcProof,
            privateVC.issuanceDate,
            privateVC.expirationDate,
            privateVC.onChainAddr,
            privateVC.userDID,
            privateVC.ctype,
            privateVC.amount,
            privateVC.amountNonce,
            privateVC.onChainAddrNonce
        );

        return (verifyVC, onChainAddr, amount);
    }

    // 验证 PublicVC 的数据项及签名
    function verifyPublicVCAttesterSignature(
        address  attesterAssertionMethod,
        bytes calldata attesterSignature,
        bytes calldata issuanceDate,
        bytes calldata expirationDate,
        address on_chain_addr,
        address holder_addr,
        bytes32  ctypeHash,
        uint256  amount
    ) internal view returns (bool, address, uint256) {
            uint256 expire = uint256(bytes32(expirationDate));
            require(expire >= block.timestamp * 1000 || expire == 0, 'VC Already expired');

            // amount 叶子结点哈希
            bytes32 amountHash = keccak256(abi.encode(keccak256(abi.encodePacked(amount))));
            
            // 链上地址 叶子节点哈希
            string memory on_chain_addr_without_pre = _getChecksum(on_chain_addr);
            bytes32 addressHash = keccak256(abi.encode(keccak256(abi.encodePacked('0x', on_chain_addr_without_pre))));

            // MerkleTree 哈希
            bytes32 rootHash = keccak256(abi.encodePacked(amountHash, addressHash));
            
            // 构建 Digest 哈希
            bytes32 digest = keccak256(abi.encodePacked(
                rootHash, 
                DID_ZK_PREFIX, 
                abi.encodePacked(holder_addr),
                issuanceDate,
                expirationDate,
                ctypeHash
                ));
            bytes32 ethSignedMessageHash = keccak256(
                abi.encodePacked(
                    bytes1(0x19),
                    EIP191_VERSION_E_HEADER,
                    EIP191_CRE_VERSION_DIGEST_LEN_V1,
                    digest
                )
            );
        return
            (_recover(ethSignedMessageHash, attesterSignature) == attesterAssertionMethod, on_chain_addr, amount);
    }

    function verifyPrivateVCAttesterSignature(
        address  attesterAssertionMethod,
        bytes calldata attesterSignature,
        bytes calldata issuanceDate,
        bytes calldata expirationDate,
        address on_chain_addr,
        address holder_addr,
        bytes32  ctypeHash,
        uint256  amount,
        bytes32 amountNonce,
        bytes32 onChainAddrNonce
    ) internal view returns (bool, address, uint256) {
            uint256 expire = uint256(bytes32(expirationDate));
            require(expire >= block.timestamp * 1000 || expire == 0, 'VC Already expired');

            // amount 叶子结点哈希
            bytes32 amountHash = keccak256(abi.encodePacked(amount));
            
            // 链上地址叶子节点哈希
            string memory on_chain_addr_without_pre = _getChecksum(on_chain_addr);
            bytes32 addressHash = keccak256(abi.encodePacked('0x', on_chain_addr_without_pre));

            // amount 叶子结点加盐
            bytes32 amountNoncedHash = keccak256(abi.encodePacked(amountHash, amountNonce));

            // 链上地址叶子结点加盐
            bytes32 addressNoncedHash = keccak256(abi.encodePacked(addressHash, onChainAddrNonce));

            // MerkleTree roothash
            bytes32 rootHash = keccak256(abi.encodePacked(amountNoncedHash, addressNoncedHash));
            
            // 构建 Digest
            bytes32 digest = keccak256(abi.encodePacked(
                rootHash, 
                DID_ZK_PREFIX, 
                abi.encodePacked(holder_addr),
                issuanceDate,
                expirationDate,
                ctypeHash
                ));
            bytes32 ethSignedMessageHash = keccak256(
                abi.encodePacked(
                    bytes1(0x19),
                    EIP191_VERSION_E_HEADER,
                    EIP191_CRE_VERSION_DIGEST_LEN_V1,
                    digest
                )
            );
        return
            (_recover(ethSignedMessageHash, attesterSignature) == attesterAssertionMethod, on_chain_addr, amount);
    }

    /**
     * @dev parse the signature, and recover the signer address
     * @param hash, the messageHash which the signer signed
     * @param sig, the signature
     */
    function _recover(
        bytes32 hash,
        bytes memory sig
    ) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        // Check the signature length
        if (sig.length != 65) {
            return (address(0));
        }

        // Divide the signature in r, s and v variables
        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
        if (v < 27) {
            v += 27;
        }

        // If the version is correct return the signer address
        if (v != 27 && v != 28) {
            return (address(0));
        } else {
            // solium-disable-next-line arg-overflow
            return ecrecover(hash, v, r, s);
        }
    }
    
/**
     * @dev Get a checksummed string hex representation of an account address.
     * @param account address The account to get the checksum for.
     */
    function _getChecksum(
        address account
    ) internal pure returns (string memory accountChecksum) {
        // call internal function for converting an account to a checksummed string.
        return _toChecksumString(account);
    }

    function _toChecksumString(
        address account
    ) internal pure returns (string memory asciiString) {
        // convert the account argument from address to bytes.
        bytes20 data = bytes20(account);

        // create an in-memory fixed-size bytes array.
        bytes memory asciiBytes = new bytes(40);

        // declare variable types.
        uint8 b;
        uint8 leftNibble;
        uint8 rightNibble;
        bool leftCaps;
        bool rightCaps;
        uint8 asciiOffset;

        // get the capitalized characters in the actual checksum.
        bool[40] memory caps = _toChecksumCapsFlags(account);

        // iterate over bytes, processing left and right nibble in each iteration.
        for (uint256 i = 0; i < data.length; i++) {
            // locate the byte and extract each nibble.
            b = uint8(uint160(data) / (2 ** (8 * (19 - i))));
            leftNibble = b / 16;
            rightNibble = b - 16 * leftNibble;

            // locate and extract each capitalization status.
            leftCaps = caps[2 * i];
            rightCaps = caps[2 * i + 1];

            // get the offset from nibble value to ascii character for left nibble.
            asciiOffset = _getAsciiOffset(leftNibble, leftCaps);

            // add the converted character to the byte array.
            asciiBytes[2 * i] = bytes1(leftNibble + asciiOffset);

            // get the offset from nibble value to ascii character for right nibble.
            asciiOffset = _getAsciiOffset(rightNibble, rightCaps);

            // add the converted character to the byte array.
            asciiBytes[2 * i + 1] = bytes1(rightNibble + asciiOffset);
        }

        return string(asciiBytes);
    }

    function _toChecksumCapsFlags(
        address account
    ) internal pure returns (bool[40] memory characterCapitalized) {
        // convert the address to bytes.
        bytes20 a = bytes20(account);

        // hash the address (used to calculate checksum).
        bytes32 b = keccak256(abi.encodePacked(_toAsciiString(a)));

        // declare variable types.
        uint8 leftNibbleAddress;
        uint8 rightNibbleAddress;
        uint8 leftNibbleHash;
        uint8 rightNibbleHash;

        // iterate over bytes, processing left and right nibble in each iteration.
        for (uint256 i; i < a.length; i++) {
            // locate the byte and extract each nibble for the address and the hash.
            rightNibbleAddress = uint8(a[i]) % 16;
            leftNibbleAddress = (uint8(a[i]) - rightNibbleAddress) / 16;
            rightNibbleHash = uint8(b[i]) % 16;
            leftNibbleHash = (uint8(b[i]) - rightNibbleHash) / 16;

            characterCapitalized[2 * i] = (leftNibbleAddress > 9 &&
                leftNibbleHash > 7);
            characterCapitalized[2 * i + 1] = (rightNibbleAddress > 9 &&
                rightNibbleHash > 7);
        }
    }

    function _getAsciiOffset(
        uint8 nibble,
        bool caps
    ) internal pure returns (uint8 offset) {
        // to convert to ascii characters, add 48 to 0-9, 55 to A-F, & 87 to a-f.
        if (nibble < 10) {
            offset = 48;
        } else if (caps) {
            offset = 55;
        } else {
            offset = 87;
        }
    }

    // based on https://ethereum.stackexchange.com/a/56499/48410
    function _toAsciiString(
        bytes20 data
    ) internal pure returns (string memory asciiString) {
        // create an in-memory fixed-size bytes array.
        bytes memory asciiBytes = new bytes(40);

        // declare variable types.
        uint8 b;
        uint8 leftNibble;
        uint8 rightNibble;

        // iterate over bytes, processing left and right nibble in each iteration.
        for (uint256 i = 0; i < data.length; i++) {
            // locate the byte and extract each nibble.
            b = uint8(uint160(data) / (2 ** (8 * (19 - i))));
            leftNibble = b / 16;
            rightNibble = b - 16 * leftNibble;

            // to convert to ascii characters, add 48 to 0-9 and 87 to a-f.
            asciiBytes[2 * i] = bytes1(
                leftNibble + (leftNibble < 10 ? 48 : 87)
            );
            asciiBytes[2 * i + 1] = bytes1(
                rightNibble + (rightNibble < 10 ? 48 : 87)
            );
        }

        return string(asciiBytes);
    }
}
