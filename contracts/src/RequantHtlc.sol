// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

/// Hash time-locked contract for TRC-20 and ERC-20 tokens: the other side of a Requant HTLC swap
/// (SWAPS.md). A lock pays `receiver` against the 32-byte SHA-256 preimage of `hash` before `timeout`
/// (unix seconds), and goes back to `sender` from `timeout` on. Anyone may submit the secret or ask for
/// the refund; the tokens only ever go to the receiver or back to the sender.
///
/// Only the state of a lock is stored, under an id that hashes all its terms; claim and refund pass the
/// terms again (they are in the Locked event). One storage slot per lock keeps a lock cheap in energy.
///
/// Token movements are checked by the contract's balance, not by the token's return value: some tokens,
/// USDT among them, do not return one reliably. Fee-on-transfer tokens are refused. States change before
/// any token call, and the balance checks fail if a token calls back to move other locks' tokens.
contract RequantHtlc {
    enum State {
        None,
        Open,
        Claimed,
        Refunded
    }

    mapping(bytes32 => State) public states;

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
        returns (bytes32 id)
    {
        require(amount > 0, "amount");
        require(receiver != address(0), "receiver");
        require(timeout > block.timestamp, "timeout");
        require(token.code.length > 0, "token");
        id = lockId(token, msg.sender, receiver, amount, hash, timeout);
        require(states[id] == State.None, "exists");
        states[id] = State.Open;
        uint256 before = balance(token);
        tokenCall(token, abi.encodeWithSelector(0x23b872dd, msg.sender, address(this), amount));
        require(balance(token) - before == amount, "transfer");
        emit Locked(id, token, msg.sender, receiver, amount, hash, timeout);
    }

    /// Pays the receiver against the secret, before the timeout.
    function claim(
        address token,
        address sender,
        address receiver,
        uint256 amount,
        bytes32 hash,
        uint64 timeout,
        bytes32 secret
    ) external {
        bytes32 id = lockId(token, sender, receiver, amount, hash, timeout);
        require(states[id] == State.Open, "state");
        require(block.timestamp < timeout, "expired");
        require(sha256(abi.encodePacked(secret)) == hash, "secret");
        states[id] = State.Claimed;
        pay(token, receiver, amount);
        emit Claimed(id, secret);
    }

    /// Returns the tokens to the sender, from the timeout on.
    function refund(address token, address sender, address receiver, uint256 amount, bytes32 hash, uint64 timeout)
        external
    {
        bytes32 id = lockId(token, sender, receiver, amount, hash, timeout);
        require(states[id] == State.Open, "state");
        require(block.timestamp >= timeout, "early");
        states[id] = State.Refunded;
        pay(token, sender, amount);
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
