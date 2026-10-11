// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

/// Hash time-locked contract for TRC-20 and ERC-20 tokens: the other side of a Requant HTLC swap
/// (SWAPS.md). A lock pays `receiver` against the 32-byte SHA-256 preimage of `hash` before `timeout`
/// (unix seconds), and goes back to `sender` from `timeout` on. Anyone may submit the secret or ask for
/// the refund; the tokens only ever go to the receiver or back to the sender.
///
/// Token movements are checked by the contract's balance, not by the token's return value: some tokens,
/// USDT among them, do not return one reliably. Fee-on-transfer tokens are refused.
contract RequantHtlc {
    enum State {
        None,
        Open,
        Claimed,
        Refunded
    }

    struct Lock {
        address token;
        address sender;
        address receiver;
        uint256 amount;
        bytes32 hash;
        uint64 timeout;
        State state;
    }

    mapping(bytes32 => Lock) public locks;
    bool private entered;

    event Locked(
        bytes32 indexed id,
        address indexed token,
        address indexed sender,
        address receiver,
        uint256 amount,
        bytes32 hash,
        uint64 timeout
    );
    event Claimed(bytes32 indexed id, bytes32 secret);
    event Refunded(bytes32 indexed id);

    modifier guarded() {
        require(!entered, "reentrant");
        entered = true;
        _;
        entered = false;
    }

    /// The id of a lock is a hash of all its terms, so nobody can take an id another sender wants.
    function lockId(address token, address sender, address receiver, uint256 amount, bytes32 hash, uint64 timeout)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(token, sender, receiver, amount, hash, timeout));
    }

    /// Locks `amount` of `token` from the caller, who must have approved this contract for it.
    function lock(address token, address receiver, uint256 amount, bytes32 hash, uint64 timeout)
        external
        guarded
        returns (bytes32 id)
    {
        require(amount > 0, "amount");
        require(receiver != address(0), "receiver");
        require(timeout > block.timestamp, "timeout");
        require(token.code.length > 0, "token");
        id = lockId(token, msg.sender, receiver, amount, hash, timeout);
        require(locks[id].state == State.None, "exists");
        uint256 before = balance(token);
        tokenCall(token, abi.encodeWithSelector(0x23b872dd, msg.sender, address(this), amount));
        require(balance(token) - before == amount, "transfer");
        locks[id] = Lock(token, msg.sender, receiver, amount, hash, timeout, State.Open);
        emit Locked(id, token, msg.sender, receiver, amount, hash, timeout);
    }

    /// Pays the receiver against the secret, before the timeout.
    function claim(bytes32 id, bytes32 secret) external guarded {
        Lock storage l = locks[id];
        require(l.state == State.Open, "state");
        require(block.timestamp < l.timeout, "expired");
        require(sha256(abi.encodePacked(secret)) == l.hash, "secret");
        l.state = State.Claimed;
        pay(l.token, l.receiver, l.amount);
        emit Claimed(id, secret);
    }

    /// Returns the tokens to the sender, from the timeout on.
    function refund(bytes32 id) external guarded {
        Lock storage l = locks[id];
        require(l.state == State.Open, "state");
        require(block.timestamp >= l.timeout, "early");
        l.state = State.Refunded;
        pay(l.token, l.sender, l.amount);
        emit Refunded(id);
    }

    function pay(address token, address to, uint256 amount) private {
        uint256 before = balance(token);
        tokenCall(token, abi.encodeWithSelector(0xa9059cbb, to, amount));
        require(before - balance(token) == amount, "transfer");
    }

    function tokenCall(address token, bytes memory data) private {
        (bool ok,) = token.call(data);
        require(ok, "token");
    }

    function balance(address token) private view returns (uint256) {
        (bool ok, bytes memory data) = token.staticcall(abi.encodeWithSelector(0x70a08231, address(this)));
        require(ok && data.length >= 32, "balance");
        return abi.decode(data, (uint256));
    }
}
