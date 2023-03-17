// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import "@chainlink/contracts/src/v0.8/ConfirmedOwner.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import "./sismo-protocol/zkConnect.sol";
import "./BaseAccount.sol";

/**
  * minimal account.
  *  this is sample minimal account.
  *  has execute, eth handling methods
  *  has a single signer that can send requests through the entryPoint.
  */
contract SimpleAccount is 
    BaseAccount, 
    UUPSUpgradeable,
    Initializable
    { 
    // ChainlinkClient would be used to make requests to an oracle which would verify a proof offchain.
    
    using ECDSA for bytes32;
    using Chainlink for Chainlink.Request; 

    // bytes32 private jobId;
    // uint256 private fee;

    //filler member, to push the nonce and owner to the same slot
    // the "Initializable" class takes 2 bytes in the first slot
    bytes28 private _filler;

    //explicit sizes of nonce, to fit a single storage cell with "owner"
    uint96 private _nonce;
    address public owner;
    bytes32 public vaultID;

    uint256 public volume;

    event RequestVolume(bytes32 indexed requestId, uint256 volume);

    // event TransactionFullfilled(
    //     address dest,
    //     uint256 value,
    //     bytes func
    // );

    IEntryPoint private immutable _entryPoint;

    event SimpleAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);

    /// @inheritdoc BaseAccount
    function nonce() public view virtual override returns (uint256) {
        return _nonce;
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    constructor(IEntryPoint anEntryPoint, bytes32 _vaultID) {
        // setChainlinkToken(0x326C977E6efc84E512bB9C30f76E30c160eD06FB);
        // setChainlinkOracle(0xCC79157eb46F5624204f47AB42b3906cAA40eaB7);
        // jobId = "ca98366cc7314957b8c012c72f05aeeb";
        // fee = (1 * LINK_DIVISIBILITY) / 10; // 0,1 * 10**18 (Varies by network and job)
        _entryPoint = anEntryPoint;
        _disableInitializers();

        // Initialize our vaultID 
        vaultID = _vaultID;
    }

    function _onlyOwner() internal view {
        //directly from EOA owner, or through the account itself (which gets redirected through execute())
        require(msg.sender == owner || msg.sender == address(this), "only owner");
    }

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func)
        public
        /**  returns (bytes32 requestId)  */
    {
        _requireFromEntryPointOrOwner();
        
        // Sismo zkConnect on-cain proof verification
        bool verified = zkConnect.verify('myProofID goes here');
        require(verified, "zkConnect proof verification failed");

        _call(dest, value, func);

        // Chainlink.Request memory req = buildChainlinkRequest(
        //     jobId,
        //     address(this),
        //     this.fulfill.selector
        // );

        // // Set the URL to perform the GET request on
        // req.add(
        //     "get",
        //     "https://api.bundler.fi/latestTransaction/10"
        // );
        // req.add("path", "response"); // Chainlink nodes 1.0.0 and later support this format

        // // Sends the request
        // return sendChainlinkRequest(req, fee);
    }

    /**
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func) external {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    /**
     * Receive the response in the form of uint256
     */
    // function fulfill(
    //     bytes32 _requestId,
    //     uint256 _volume
    // ) public recordChainlinkFulfillment(_requestId) {
    //     emit RequestVolume(_requestId, _volume);
    //     volume = _volume;
    // }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of SimpleAccount must be deployed with the new EntryPoint address, then upgrading
      * the implementation by calling `upgradeTo()`
     */
    function initialize(address anOwner) public virtual initializer {
        _initialize(anOwner);
    }

    function _initialize(address anOwner) internal virtual {
        owner = anOwner;
        emit SimpleAccountInitialized(_entryPoint, owner);
    }

    // Require the function call went through EntryPoint or owner
    function _requireFromEntryPointOrOwner() internal view {
        require(msg.sender == address(entryPoint()) || msg.sender == owner, "account: not Owner or EntryPoint");
    }

    /// implement template method of BaseAccount
    function _validateAndUpdateNonce(UserOperation calldata userOp) internal override {
        require(_nonce++ == userOp.nonce, "account: invalid nonce");
    }

    /// implement template method of BaseAccount
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
    internal override virtual returns (uint256 validationData) {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        if (owner != hash.recover(userOp.signature))
            return SIG_VALIDATION_FAILED;
        return 0;
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value : value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value : msg.value}(address(this));
    }

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlyOwner();
    }
}
