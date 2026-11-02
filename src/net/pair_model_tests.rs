//! A man in the middle of pairing, in every order the protocol lets it act. It runs one session
//! with each device, so the two connections differ and it needs the words to match anyway.
//!
//! Each schedule uses the real `commitment` and `comparison_words`, cut to a few bits so a win is
//! common enough to count. At each value it chooses, the attacker tries as many candidates as it
//! likes against everything it has seen so far. The control below drops the commitment, and proves
//! this harness can see a broken protocol. Rejected: Tamarin, for a model nothing ties to this code.

use super::*;

const BITS: u32 = 6;
const TRIALS: u32 = 3000;
/// How many candidates the attacker tries for each value it picks. More than enough to find any
/// match the protocol lets it check.
const GRIND: usize = 300;

fn short(words: &[String; 3]) -> u32 {
    let hash = crypto::hash(&[words[0].as_bytes(), words[1].as_bytes(), words[2].as_bytes()]);
    u32::from(hash[0]) >> (8 - BITS)
}

/// What each honest side and the attacker hold during one run.
#[derive(Default)]
struct Run {
    adder_nonce: [u8; 32],
    joiner_nonce: Option<[u8; 32]>,
    adder_revealed: bool,
    /// What the adder takes as the joiner's value.
    to_adder: Option<[u8; 32]>,
    /// What the attacker will reveal to the joiner.
    to_joiner: Option<[u8; 32]>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Step {
    /// The attacker gives the adder a value, which makes the adder reveal its own.
    ToAdder,
    /// The attacker settles what the joiner will be told, by committing to it or by sending it.
    ToJoiner,
    /// The joiner has been committed to, and sends its value.
    JoinerSends,
}

fn matched(connection: (&[u8; 32], &[u8; 32]), adder: (&[u8; 32], &[u8; 32]), joiner: (&[u8; 32], &[u8; 32])) -> bool {
    short(&comparison_words(connection.0, adder.0, adder.1)) == short(&comparison_words(connection.1, joiner.0, joiner.1))
}

/// Plays one schedule, with the attacker picking each value as well as it can.
fn attack(schedule: &[Step]) -> bool {
    let (to_adder_side, to_joiner_side): ([u8; 32], [u8; 32]) = (crypto::random(), crypto::random());
    let mut run = Run { adder_nonce: crypto::random(), ..Run::default() };
    let wins = |run: &Run, to_adder: &[u8; 32], to_joiner: &[u8; 32], joiner: &[u8; 32]| {
        matched((&to_adder_side, &to_joiner_side), (&run.adder_nonce, to_adder), (to_joiner, joiner))
    };

    for step in schedule {
        match step {
            Step::ToAdder => {
                // It can only aim when it already knows everything else that goes into both words.
                let known = run.adder_revealed.then_some(()).and(run.joiner_nonce).zip(run.to_joiner);
                let pick = known.and_then(|(joiner, to_joiner)| {
                    (0..GRIND).map(|_| crypto::random::<32>()).find(|candidate| wins(&run, candidate, &to_joiner, &joiner))
                });
                run.to_adder = Some(pick.or(run.joiner_nonce).unwrap_or_else(crypto::random));
                run.adder_revealed = true;
            }
            Step::ToJoiner => {
                let known = run.joiner_nonce.zip(run.to_adder).filter(|_| run.adder_revealed);
                let pick = known.and_then(|(joiner, to_adder)| {
                    (0..GRIND).map(|_| crypto::random::<32>()).find(|candidate| wins(&run, &to_adder, candidate, &joiner))
                });
                // Forwarding the adder's own value, once seen, is the other thing it can try.
                run.to_joiner = Some(pick.or(run.adder_revealed.then_some(run.adder_nonce)).unwrap_or_else(crypto::random));
            }
            Step::JoinerSends => run.joiner_nonce = Some(crypto::random()),
        }
    }
    let (Some(to_adder), Some(to_joiner), Some(joiner)) = (run.to_adder, run.to_joiner, run.joiner_nonce) else { return false };
    wins(&run, &to_adder, &to_joiner, &joiner)
}

/// Every order of the attacker's moves that the protocol allows.
fn schedules(committed: bool) -> Vec<Vec<Step>> {
    use Step::{JoinerSends, ToAdder, ToJoiner};
    let all = [
        [ToAdder, ToJoiner, JoinerSends],
        [ToAdder, JoinerSends, ToJoiner],
        [ToJoiner, ToAdder, JoinerSends],
        [ToJoiner, JoinerSends, ToAdder],
        [JoinerSends, ToAdder, ToJoiner],
        [JoinerSends, ToJoiner, ToAdder],
    ];
    let allowed = |schedule: &&[Step; 3]| {
        let at = |step| schedule.iter().position(|other| *other == step).expect("every step is in a schedule");
        // The joiner sends only once it holds a commitment, and the real `commitment` binds, so the
        // attacker's value for it is settled first. That one ordering is all the commitment does.
        !committed || at(ToJoiner) < at(JoinerSends)
    };
    all.iter().filter(allowed).map(|schedule| schedule.to_vec()).collect()
}

fn best_rate(committed: bool) -> f64 {
    let wins = |schedule: &Vec<Step>| (0..TRIALS).map(|_| u32::from(attack(schedule))).sum::<u32>();
    schedules(committed).iter().map(|schedule| f64::from(wins(schedule)) / f64::from(TRIALS)).fold(0.0, f64::max)
}

#[test]
fn no_order_of_moves_beats_one_guess() {
    let guess = 1.0 / f64::from(1u32 << BITS);
    let best = best_rate(true);
    assert!(best < 2.0 * guess, "an attacker won {best} of the time, against {guess} for a guess");
}

#[test]
fn without_the_commitment_the_same_attacker_always_wins() {
    assert!(best_rate(false) > 0.9, "if this fails, the test above proves nothing");
}
