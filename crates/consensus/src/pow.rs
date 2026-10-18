//! Difficulty (CHAIN.md §7) and emission (CHAIN.md §8).

use crate::params::{Network, ATOMS_PER_RQT};
use crate::u256::U256;

/// Target of the block after `parent` (CHAIN.md §7). `prev_time` is the timestamp of the parent's parent
/// (`None` for genesis).
///
/// Below `net.relative_height`: BCH aserti3-2d anchored at genesis. A stall there leaves the whole lag
/// in the schedule: once a block ends it, the target jumps toward `pow_limit` and thousands of nearly
/// free blocks follow until the height catches up (the test network after a four-day stall, 2026-10-18).
/// From `net.relative_height` on: the same exponential step from the parent's own target by the parent's
/// solve time, counted up to one half-life, and never easier than the genesis target. A stall of any
/// length then halves the difficulty at most once.
pub fn next_target(
    net: &Network,
    parent_height: u64,
    parent_time: u64,
    parent_target: U256,
    prev_time: Option<u64>,
) -> U256 {
    if parent_height + 1 < net.relative_height {
        let lag = (parent_time as i128 - net.genesis_time as i128) - net.spacing as i128 * parent_height as i128;
        return scaled(net, net.genesis_target, lag);
    }
    let solve = prev_time.map_or(net.spacing as i128, |t| parent_time as i128 - t as i128).min(net.half_life as i128);
    scaled(net, parent_target, solve - net.spacing as i128).min(net.genesis_target)
}

/// `base * 2^(lag / tau)` with BCH's fixed-point approximation, `0` becoming `1`, at most `pow_limit`.
fn scaled(net: &Network, base: U256, lag: i128) -> U256 {
    let exponent = (lag * 65536) / net.half_life as i128; // truncates toward zero
    let shifts = exponent >> 16; // floor
    let frac = (exponent & 0xffff) as u128;
    let poly = (195_766_423_245_049u128 * frac
        + 971_821_376u128 * frac * frac
        + 5127u128 * frac * frac * frac
        + (1u128 << 47))
        >> 48;
    let factor = 65536 + poly as u64;
    let shift = (shifts - 16).clamp(-1024, 1024) as i64;
    let t = match base.mul_shift(factor, shift) {
        Some(t) if t.is_zero() => U256::ONE,
        Some(t) => t,
        None => net.pow_limit,
    };
    t.min(net.pow_limit)
}

/// `S = 2^24 RQT` in atoms.
pub const MAIN_EMISSION: u64 = (1 << 24) * ATOMS_PER_RQT;
/// 0.25 RQT per block.
pub const TAIL_REWARD: u64 = ATOMS_PER_RQT / 4;

/// The development fund's share of a block reward (CHAIN.md §8), due at heights `1..=dev_fund_last`.
pub fn dev_fund_share(net: &Network, height: u64, reward: u64) -> u64 {
    if (1..=net.dev_fund_last).contains(&height) {
        reward * crate::params::DEV_FUND_PERCENT / 100
    } else {
        0
    }
}

/// Block reward given the amount issued by all earlier blocks.
pub fn reward(generated: u64) -> u64 {
    (MAIN_EMISSION.saturating_sub(generated) >> 22).max(TAIL_REWARD)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A network still on the genesis-anchored rule (before `relative_height`).
    fn net_with_target(bits: u32) -> Network {
        let mut n = Network::regtest();
        n.genesis_target = U256::low_mask(bits);
        n.relative_height = u64::MAX;
        n
    }

    /// The anchored rule: the parent's own target and its parent's time do not matter.
    fn anchored(net: &Network, parent_height: u64, parent_time: u64) -> U256 {
        next_target(net, parent_height, parent_time, U256::ONE, None)
    }

    #[test]
    fn on_schedule_keeps_the_target() {
        let net = net_with_target(200);
        for h in [0u64, 1, 10, 100_000] {
            assert_eq!(anchored(&net, h, net.genesis_time + 60 * h), net.genesis_target);
        }
    }

    #[test]
    fn one_half_life_doubles_or_halves() {
        let net = net_with_target(200);
        let g = net.genesis_time;
        let t = net.genesis_target;
        // 2 hours behind schedule: target doubles (easier); ahead: halves.
        assert_eq!(anchored(&net, 100, g + 6000 + 7200), t.mul_shift(1, 1).unwrap());
        assert_eq!(anchored(&net, 100, g + 6000 - 7200), t.mul_shift(1, -1).unwrap());
        assert_eq!(anchored(&net, 0, g + 2 * 7200), t.mul_shift(1, 2).unwrap());
    }

    #[test]
    fn fractional_steps_follow_the_bch_polynomial() {
        let net = net_with_target(200);
        let g = net.genesis_time;
        // half a half-life late: factor 65536 + poly(32768) = 92674 (2^0.5 * 65536 = 92681.9)
        let half = anchored(&net, 0, g + 3600);
        let ratio = half.div(&net.genesis_target.mul_shift(1, -16).unwrap());
        assert!((92673..=92674).contains(&ratio.0[0]), "{}", ratio.0[0]);
        // monotone in time
        let mut last = U256::ZERO;
        for dt in (0..20_000).step_by(37) {
            let t = anchored(&net, 0, g + dt);
            assert!(t >= last);
            last = t;
        }
    }

    #[test]
    fn clamps() {
        let net = net_with_target(250);
        assert_eq!(anchored(&net, 0, net.genesis_time + 100 * 7200), net.pow_limit);
        let net = net_with_target(8);
        assert_eq!(anchored(&net, 1_000_000, net.genesis_time), U256::ONE);
    }

    /// The test network's parameters with the relative rule from `from`.
    fn test_net(from: u64) -> Network {
        let mut n = Network::test();
        n.relative_height = from;
        n
    }

    #[test]
    fn relative_rule_steps_from_the_parent() {
        let net = test_net(0);
        let parent = net.genesis_target.mul_shift(1, -3).unwrap(); // 8 times the genesis difficulty
        let t = 1_000_000;
        // on time: unchanged; half a half-life slow: the BCH factor for 2^0.5; a half-life fast: twice harder
        assert_eq!(next_target(&net, 500, t, parent, Some(t - 60)), parent);
        assert_eq!(next_target(&net, 500, t, parent, Some(t - 60 - 3600)), parent.mul_shift(92674, -16).unwrap());
        assert_eq!(next_target(&net, 500, t, parent, Some(t + 7200 - 60)), parent.mul_shift(1, -1).unwrap());
        // the genesis block has no solve time: its child keeps its target
        assert_eq!(next_target(&net, 0, net.genesis_time, net.genesis_target, None), net.genesis_target);
    }

    #[test]
    fn a_stall_of_any_length_counts_one_half_life() {
        let net = test_net(0);
        let parent = net.genesis_target.mul_shift(1, -4).unwrap();
        let t = 1_000_000_000;
        let one = next_target(&net, 500, t, parent, Some(t - 7200));
        for stall in [7200u64, 86_400, 4 * 86_400, 365 * 86_400] {
            assert_eq!(next_target(&net, 500, t, parent, Some(t - stall)), one);
        }
        assert!(one < parent.mul_shift(1, 1).unwrap());
    }

    #[test]
    fn never_easier_than_genesis_after_the_switch() {
        let net = test_net(1000);
        let t = 1_000_000_000;
        // a block of the flood at the old rule's ceiling: its child is back at the genesis target
        assert_eq!(next_target(&net, 999, t, net.pow_limit, Some(t - 1)), net.genesis_target);
        // slow blocks at the genesis target do not go below it
        assert_eq!(next_target(&net, 2000, t, net.genesis_target, Some(t - 7200)), net.genesis_target);
        // below the switch the anchored rule still applies to the same inputs
        let lagging = net.genesis_time + 60 * 998 + 40 * 7200;
        assert_eq!(next_target(&net, 998, lagging, net.genesis_target, Some(lagging - 60)), net.pow_limit);
    }

    /// Expected solve time of a target for a miner producing `rate` tickets per second.
    fn solve_secs(target: U256, rate: u64) -> u64 {
        U256::work(&target).div(&U256([rate, 0, 0, 0])).0[0].max(1)
    }

    /// Blocks found within `window` seconds after a single miner (`rate` tickets/s) returns from `stall`
    /// seconds away, each block at its expected solve time.
    fn blocks_after_stall(net: &Network, rate: u64, stall: u64, window: u64) -> u64 {
        // start on schedule, settle at the miner's rate, then stall, then count
        let (mut height, mut target) = (2000u64, net.genesis_target);
        let (mut time, mut prev) = (net.genesis_time + 60 * height, net.genesis_time + 60 * (height - 1));
        for _ in 0..3000 {
            let next = next_target(net, height, time, target, Some(prev));
            prev = time;
            time += solve_secs(next, rate);
            (height, target) = (height + 1, next);
        }
        let back = time + stall;
        let mut found = 0;
        let mut now = back;
        loop {
            let next = next_target(net, height, time, target, Some(prev));
            now += solve_secs(next, rate);
            if now > back + window {
                return found;
            }
            (prev, time, height, target, found) = (time, now, height + 1, next, found + 1);
        }
    }

    #[test]
    fn a_returning_miner_does_not_flood_the_chain() {
        // one Turing GPU (about 4 M tickets/s), four days away, then one hour of mining
        let relative = blocks_after_stall(&test_net(0), 4_000_000, 4 * 86_400, 3600);
        let anchored = blocks_after_stall(&test_net(u64::MAX), 4_000_000, 4 * 86_400, 3600);
        // about 60 blocks an hour at the settled difficulty; one halving of it at most doubles that
        assert!(relative <= 150, "relative rule: {relative} blocks in an hour");
        assert!(anchored > 1000, "anchored rule: {anchored} blocks in an hour");
    }

    #[test]
    fn emission_schedule() {
        assert_eq!(reward(0), 4 * ATOMS_PER_RQT);
        let mut generated = 0u64;
        let mut h = 0u64;
        let mut half_at = None;
        while reward(generated) > TAIL_REWARD {
            generated += reward(generated);
            h += 1;
            if half_at.is_none() && generated >= MAIN_EMISSION / 2 {
                half_at = Some(h);
            }
        }
        let years = |blocks: u64| blocks as f64 / (525_600.0);
        assert!((5.0..6.0).contains(&years(half_at.unwrap())), "{}", years(half_at.unwrap()));
        assert!((21.0..23.5).contains(&years(h)), "tail after {} years", years(h));
        assert!(generated < MAIN_EMISSION);
        assert_eq!(reward(MAIN_EMISSION + 1), TAIL_REWARD);
    }
}
