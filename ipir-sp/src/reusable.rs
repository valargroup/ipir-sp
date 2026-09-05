//! Experimental bounded evaluation-key reuse. Not a production security claim.
//!
//! A batch consumes each independently derived query matrix at most once.
//! Neither the batch nor its secret can be cloned, serialized, or restored.
//! Callers may retry only the immutable bytes returned by `next_query`.
//! Public setup must be authenticated/pinned by a future transport integration.

use super::*;

/// Immutable public query matrices, reusable across clients and fresh batches.
pub struct QueryPool {
    client: IPIRClient,
    sets: Vec<Vec<Vec<u64>>>,
}

impl QueryPool {
    /// Derive 4, 8, or 16 independent sets with a domain-separated ChaCha stream.
    /// The seed is public; no client secret is derived from it.
    pub fn new(
        client: IPIRClient,
        public_seed: IPIRSeed,
        count: usize,
    ) -> Result<Self, &'static str> {
        if !matches!(count, 4 | 8 | 16) {
            return Err("experimental pool size must be 4, 8, or 16");
        }
        let mut rng = ChaCha20Rng::from_seed(public_seed);
        rng.set_stream(u64::from_le_bytes(*b"IPIRpool"));
        let sets = (0..count)
            .map(|_| {
                let mut seed = [0; 32];
                rng.fill_bytes(&mut seed);
                client.generate_public_query_setup_simplepir_from_seed(seed)
            })
            .collect();
        Ok(Self { client, sets })
    }

    pub fn client(&self) -> &IPIRClient {
        &self.client
    }
    pub fn sets(&self) -> &[Vec<Vec<u64>>] {
        &self.sets
    }

    /// Create a new, process-local batch. Dropping it permanently abandons slots.
    pub fn start_batch(&self) -> ReusableBatch<'_> {
        let mut client_seed = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_seed);
        let mut rng = ChaCha20Rng::from_seed(client_seed);
        let secret = ClientSecret::sample_ternary(&self.client.rlwe, &mut rng);
        let keys = PackingKeys::generate_full(
            &self.client.rlwe,
            &secret.to_ntt(&self.client.rlwe),
            &mut rng,
        );
        ReusableBatch {
            pool: self,
            client_seed,
            secret,
            rng,
            keys,
            next: 0,
        }
    }
}

/// One ephemeral secret and evaluation-key pair; exclusive mutation allocates slots.
pub struct ReusableBatch<'a> {
    pool: &'a QueryPool,
    client_seed: IPIRSeed,
    secret: ClientSecret,
    rng: ChaCha20Rng,
    keys: PackingKeys<'a>,
    next: usize,
}

/// Immutable query body. Retrying `bytes()` does not draw new randomness.
pub struct SlotQuery {
    slot: usize,
    bytes: Vec<u8>,
}

impl SlotQuery {
    pub fn slot(&self) -> usize {
        self.slot
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl ReusableBatch<'_> {
    /// Public evaluation keys: upload once per batch in the prototype transport.
    pub fn keys(&self) -> &PackingKeys<'_> {
        &self.keys
    }

    /// Consume a slot before encryption. An error never wraps the counter.
    pub fn next_query(&mut self, row: usize) -> Result<SlotQuery, &'static str> {
        let client = &self.pool.client;
        if row >= client.ypir.db_rows {
            return Err("row out of range");
        }
        if self.next == self.pool.sets.len() {
            return Err("batch exhausted");
        }
        let slot = self.next;
        self.next += 1;
        let query = encrypted_selection_query(
            &client.rlwe,
            &self.pool.sets[slot],
            &self.secret.coeffs,
            row,
            client.ypir.db_rows,
            &mut self.rng,
        );
        Ok(SlotQuery {
            slot,
            bytes: IPIRSimpleQuery::new(query)
                .to_switched_bytes(client.rlwe.q, client.ypir.query_bits),
        })
    }

    /// Decode with the public `c1` for this query's slot and database snapshot.
    /// The in-process harness binds slot and snapshot; no network API is provided.
    pub fn decode_with_margin(&self, c1: &[Vec<u64>], response: &[u8]) -> (Vec<u64>, u64) {
        self.pool
            .client
            .decode_response_simplepir_with_margin(self.client_seed, c1, response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_slots_are_unique_bounded_and_retries_are_immutable() {
        let (r, y) = params_for_simplepir(2048, 2048 * 14).unwrap();
        for count in [4, 8, 16] {
            let pool = QueryPool::new(IPIRClient::new(&r, &y), [7; 32], count).unwrap();
            let same = QueryPool::new(IPIRClient::new(&r, &y), [7; 32], count).unwrap();
            assert_eq!(pool.sets(), same.sets());
            assert_eq!(
                &pool.sets()[0][0][..4],
                &[
                    9_164_527_206_802_959,
                    5_084_643_010_587_079,
                    51_932_877_172_136_113,
                    33_393_100_479_081_743,
                ]
            );
            for i in 0..count {
                for j in 0..i {
                    assert_ne!(pool.sets()[i], pool.sets()[j]);
                }
            }
            assert!(QueryPool::new(IPIRClient::new(&r, &y), [7; 32], 3).is_err());
            let mut batch = pool.start_batch();
            assert!(batch.next_query(2048).is_err());
            for slot in 0..count {
                let q = batch.next_query(slot).unwrap();
                assert_eq!(q.slot(), slot);
                let retry = q.bytes().to_vec();
                assert_eq!(q.bytes(), retry);
            }
            assert!(batch.next_query(0).is_err());
            assert!(batch.next_query(1).is_err());
            let mut fresh = pool.start_batch();
            assert_eq!(fresh.next_query(0).unwrap().slot(), 0);
            assert_ne!(
                crate::serialize::serialize_packing_keys(&r, batch.keys()).unwrap(),
                crate::serialize::serialize_packing_keys(&r, fresh.keys()).unwrap()
            );
        }
    }

    #[test]
    fn same_matrix_same_secret_exposes_selector_difference() {
        let (r, y) = params_for_simplepir(2048, 2048 * 14).unwrap();
        let client = IPIRClient::new(&r, &y);
        let a = client.generate_public_query_setup_simplepir_from_seed([9; 32]);
        let mut rng = ChaCha20Rng::from_seed([11; 32]);
        let secret = ClientSecret::sample_ternary(&r, &mut rng);
        let x = encrypted_selection_query(&r, &a, &secret.coeffs, 0, y.db_rows, &mut rng);
        let z = encrypted_selection_query(&r, &a, &secret.coeffs, 2047, y.db_rows, &mut rng);
        // Attack the actual switched wire representation, including rounding.
        let wire = |v| {
            IPIRSimpleQuery::from_switched_bytes(
                &IPIRSimpleQuery::new(v).to_switched_bytes(r.q, y.query_bits),
                y.db_rows,
                r.q,
                y.query_bits,
            )
            .unwrap()
            .into_first_dim()
        };
        let (x, z) = (wire(x), wire(z));
        let exposed: Vec<_> = x
            .iter()
            .zip(z)
            .enumerate()
            .filter_map(|(i, (a, b))| {
                let d = sub_mod(*a, b, r.q);
                (d.min(r.q - d) > r.delta / 2).then_some(i)
            })
            .collect();
        assert_eq!(exposed, vec![0, 2047]);
    }
}
