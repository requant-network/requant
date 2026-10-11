// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;

import {RequantHtlc} from "../src/RequantHtlc.sol";

/// The subset of Foundry's cheat codes these tests use (no forge-std dependency).
interface Vm {
    function warp(uint256) external;
    function prank(address) external;
    function expectRevert(bytes calldata) external;
}

/// A plain token. The variants below change only how transfers report or behave.
contract Token {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function move(address from, address to, uint256 amount) internal virtual {
        require(balanceOf[from] >= amount, "funds");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external virtual returns (bool) {
        move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external virtual returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        move(from, to, amount);
        return true;
    }
}

/// Moves the tokens but reports failure, as some USDT deployments do.
contract FalseToken is Token {
    function transfer(address to, uint256 amount) external override returns (bool) {
        move(msg.sender, to, amount);
        return false;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        allowance[from][msg.sender] -= amount;
        move(from, to, amount);
        return false;
    }
}

/// Keeps 1% of every transfer.
contract FeeToken is Token {
    function move(address from, address to, uint256 amount) internal override {
        require(balanceOf[from] >= amount, "funds");
        balanceOf[from] -= amount;
        balanceOf[to] += amount - amount / 100;
    }
}

/// Tries to refund a lock again from inside its own payout.
contract ReentrantToken is Token {
    RequantHtlc htlc;
    address sender;
    address receiver;
    uint256 amount;
    bytes32 hash;
    uint64 timeout;
    bool armed;

    function arm(RequantHtlc h, address s, address r, uint256 a, bytes32 x, uint64 t) external {
        (htlc, sender, receiver, amount, hash, timeout, armed) = (h, s, r, a, x, t, true);
    }

    function move(address from, address to, uint256 value) internal override {
        super.move(from, to, value);
        if (armed) {
            armed = false;
            htlc.refund(address(this), sender, receiver, amount, hash, timeout);
        }
    }
}

contract RequantHtlcTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    RequantHtlc htlc;
    Token token;
    // Computed once: a sha256 precompile call between prank and the call under test would use the prank.
    bytes32 H;
    address constant TAKER = address(0x7A);
    address constant MAKER = address(0x3A);
    address constant STRANGER = address(0x99);
    bytes32 constant SECRET = bytes32(uint256(0x5ec2e7));
    uint256 constant AMOUNT = 25_000_000; // 25 USDT, 6 decimals
    uint64 constant T0 = 1_800_000_000;
    uint64 constant TIMEOUT = T0 + 12 hours;

    function setUp() public {
        vm.warp(T0);
        H = sha256(abi.encodePacked(SECRET));
        htlc = new RequantHtlc();
        token = new Token();
        token.mint(TAKER, 100_000_000);
        vm.prank(TAKER);
        token.approve(address(htlc), type(uint256).max);
    }

    function lock(Token t) internal returns (bytes32) {
        vm.prank(TAKER);
        return htlc.lock(address(t), MAKER, AMOUNT, H, TIMEOUT);
    }

    function state(bytes32 id) internal view returns (RequantHtlc.State) {
        return htlc.states(id);
    }

    function claim(Token t, bytes32 secret) internal {
        htlc.claim(address(t), TAKER, MAKER, AMOUNT, H, TIMEOUT, secret);
    }

    function refund(Token t) internal {
        htlc.refund(address(t), TAKER, MAKER, AMOUNT, H, TIMEOUT);
    }

    function test_lock_records_terms_and_takes_tokens() public {
        bytes32 id = lock(token);
        require(id == htlc.lockId(address(token), TAKER, MAKER, AMOUNT, H, TIMEOUT), "id");
        require(state(id) == RequantHtlc.State.Open, "open");
        require(token.balanceOf(address(htlc)) == AMOUNT && token.balanceOf(TAKER) == 100_000_000 - AMOUNT, "moved");
    }

    function test_the_secret_pays_the_receiver_whoever_submits_it() public {
        bytes32 id = lock(token);
        vm.prank(STRANGER);
        claim(token, SECRET);
        require(token.balanceOf(MAKER) == AMOUNT && token.balanceOf(address(htlc)) == 0, "paid");
        require(token.balanceOf(STRANGER) == 0, "stranger");
        require(state(id) == RequantHtlc.State.Claimed, "claimed");
    }

    function test_the_hash_is_plain_sha256_of_32_bytes() public pure {
        // The same vector as the Requant side: SHA-256 of 32 zero bytes.
        require(
            sha256(abi.encodePacked(bytes32(0))) == 0x66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925,
            "sha256"
        );
    }

    function test_a_wrong_secret_is_refused() public {
        bytes32 id = lock(token);
        vm.expectRevert(bytes("secret"));
        claim(token, bytes32(uint256(1)));
    }

    function test_no_claim_from_the_timeout_on() public {
        bytes32 id = lock(token);
        vm.warp(TIMEOUT);
        vm.expectRevert(bytes("expired"));
        claim(token, SECRET);
    }

    function test_no_refund_before_the_timeout() public {
        bytes32 id = lock(token);
        vm.warp(TIMEOUT - 1);
        vm.expectRevert(bytes("early"));
        refund(token);
    }

    function test_the_refund_goes_to_the_sender_whoever_asks() public {
        bytes32 id = lock(token);
        vm.warp(TIMEOUT);
        vm.prank(STRANGER);
        refund(token);
        require(token.balanceOf(TAKER) == 100_000_000 && token.balanceOf(address(htlc)) == 0, "refunded");
        require(state(id) == RequantHtlc.State.Refunded, "state");
    }

    function test_a_lock_settles_once() public {
        bytes32 id = lock(token);
        claim(token, SECRET);
        vm.expectRevert(bytes("state"));
        claim(token, SECRET);
        vm.warp(TIMEOUT);
        vm.expectRevert(bytes("state"));
        refund(token);
    }

    function test_refunded_cannot_be_claimed() public {
        bytes32 id = lock(token);
        vm.warp(TIMEOUT);
        refund(token);
        vm.expectRevert(bytes("state"));
        claim(token, SECRET);
    }

    function test_unknown_lock_is_refused() public {
        vm.expectRevert(bytes("state"));
        claim(token, SECRET);
        vm.warp(TIMEOUT);
        vm.expectRevert(bytes("state"));
        refund(token);
    }

    function test_changed_terms_name_no_lock() public {
        lock(token);
        vm.expectRevert(bytes("state"));
        htlc.claim(address(token), TAKER, STRANGER, AMOUNT, H, TIMEOUT, SECRET);
        vm.expectRevert(bytes("state"));
        htlc.claim(address(token), TAKER, MAKER, AMOUNT + 1, H, TIMEOUT, SECRET);
        vm.warp(TIMEOUT + 1 days);
        vm.expectRevert(bytes("state"));
        htlc.refund(address(token), STRANGER, MAKER, AMOUNT, H, TIMEOUT);
    }

    function test_the_same_terms_twice_are_refused() public {
        lock(token);
        vm.prank(TAKER);
        vm.expectRevert(bytes("exists"));
        htlc.lock(address(token), MAKER, AMOUNT, H, TIMEOUT);
    }

    function test_bad_terms_are_refused() public {
        vm.prank(TAKER);
        vm.expectRevert(bytes("amount"));
        htlc.lock(address(token), MAKER, 0, H, TIMEOUT);
        vm.prank(TAKER);
        vm.expectRevert(bytes("receiver"));
        htlc.lock(address(token), address(0), AMOUNT, H, TIMEOUT);
        vm.prank(TAKER);
        vm.expectRevert(bytes("timeout"));
        htlc.lock(address(token), MAKER, AMOUNT, H, T0);
        vm.prank(TAKER);
        vm.expectRevert(bytes("token"));
        htlc.lock(STRANGER, MAKER, AMOUNT, H, TIMEOUT);
    }

    function test_a_token_that_reports_false_still_works() public {
        FalseToken t = new FalseToken();
        t.mint(TAKER, AMOUNT);
        vm.prank(TAKER);
        t.approve(address(htlc), AMOUNT);
        bytes32 id = lock(t);
        claim(t, SECRET);
        require(t.balanceOf(MAKER) == AMOUNT, "paid");
    }

    function test_a_fee_on_transfer_token_is_refused() public {
        FeeToken t = new FeeToken();
        t.mint(TAKER, AMOUNT);
        vm.prank(TAKER);
        t.approve(address(htlc), AMOUNT);
        vm.prank(TAKER);
        vm.expectRevert(bytes("transfer"));
        htlc.lock(address(t), MAKER, AMOUNT, H, TIMEOUT);
    }

    function test_a_payout_cannot_reenter() public {
        ReentrantToken t = new ReentrantToken();
        t.mint(TAKER, AMOUNT);
        vm.prank(TAKER);
        t.approve(address(htlc), AMOUNT);
        bytes32 id = lock(t);
        vm.warp(TIMEOUT);
        t.arm(htlc, TAKER, MAKER, AMOUNT, H, TIMEOUT);
        vm.expectRevert(bytes("token"));
        refund(t);
        require(state(id) == RequantHtlc.State.Open && t.balanceOf(address(htlc)) == AMOUNT, "untouched");
    }
}
