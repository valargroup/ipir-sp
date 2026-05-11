//! Backend abstraction for nullifier PIR servers.

use anyhow::{Context, Result};
use ipir_sp::client::IPIRClient;
use ipir_sp::modulus_switch::modulus_bits;
use ipir_sp::params_for_simplepir;
use ipir_sp::serialize::deserialize_packing_keys;
use ipir_sp::server::{build_pack_preprocessed_blocks, IPIRServer};
use ipir_sp::YpirSchemeParams;
use serde::{Deserialize, Serialize};

use crate::encoding::ITEM_SIZE_BITS;
use crate::snapshot::NullifierSnapshot;

#[derive(Debug, Clone, Copy, Default)]
pub struct ServerBreakdown {
    pub setup_deserialize_us: u128,
    pub pack_preprocess_us: u128,
    pub online_deserialize_us: u128,
    pub matrix_vector_us: u128,
    pub packing_us: u128,
    pub serialization_us: u128,
}

pub struct QueryAnswer {
    pub body: Vec<u8>,
    pub breakdown: ServerBreakdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    LocalIpir,
    YpirArtifact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendMetadata {
    pub backend: BackendKind,
    pub record_count: usize,
    pub pir_item_count: usize,
    pub db_rows: usize,
    pub db_cols: usize,
    pub item_size_bits: u64,
    pub setup_seed: u64,
}

pub trait PirBackend: Send + Sync {
    fn meta(&self) -> BackendMetadata;
    fn answer_query(&self, query: &[u8]) -> Result<QueryAnswer>;
}

pub fn seed_from_u64(value: u64) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&value.to_le_bytes());
    seed
}

pub struct LocalIpirBackend {
    /// RLWE parameters used by the underlying homomorphic encryption scheme.
    rlwe: &'static inspiring::RlweParams,
    /// SimplePIR/YPIR dimensions and modulus settings derived for this snapshot.
    ypir: YpirSchemeParams,
    /// Number of original nullifier records represented by the snapshot.
    record_count: usize,
    /// Number of PIR rows/items exposed to the PIR server, including padding if any.
    pir_item_count: usize,
    /// Seed used to deterministically generate the server-side public setup.
    setup_seed: u64,
    /// In-memory IPIR server containing the encoded database matrix.
    server: IPIRServer<u16>,
    /// Per-block preprocessing used to pack SimplePIR responses efficiently.
    pack_preprocessed: Vec<inspiring::QueryPackPreprocessed<'static>>,
    /// Cached top-level key images used during query response packing.
    top_key_images: inspiring::TopKeyImages<'static>,
}

impl LocalIpirBackend {
    pub fn prepare(snapshot: &NullifierSnapshot, setup_seed: u64) -> Result<Self> {
        let (rlwe, ypir) = params_for_simplepir(snapshot.pir_row_count() as u64, ITEM_SIZE_BITS)
            .context("derive local ipir-sp SimplePIR parameters")?;
        Self::prepare_with_params(snapshot, setup_seed, rlwe, ypir)
    }

    pub fn prepare_with_params(
        snapshot: &NullifierSnapshot,
        setup_seed: u64,
        rlwe: inspiring::RlweParams,
        ypir: YpirSchemeParams,
    ) -> Result<Self> {
        let rlwe = Box::leak(Box::new(rlwe));
        let db = snapshot
            .coeff_iter(ypir.db_rows)
            .context("open snapshot coefficient iterator")?;
        let server = IPIRServer::<u16>::new(ypir.clone(), db, false, true);
        let client = IPIRClient::new(rlwe, &ypir);
        let offline_query_polys =
            client.generate_public_query_setup_simplepir_from_seed(seed_from_u64(setup_seed));
        let offline = server.perform_offline_precomputation_simplepir(rlwe, &offline_query_polys);
        let pack_preprocessed = build_pack_preprocessed_blocks(rlwe, &offline.crs_blocks)
            .context("build local ipir-sp pack preprocessing")?;
        let top_key_images = inspiring::TopKeyImages::build(rlwe);

        Ok(Self {
            rlwe,
            ypir,
            record_count: snapshot.record_count(),
            pir_item_count: snapshot.pir_row_count(),
            setup_seed,
            server,
            pack_preprocessed,
            top_key_images,
        })
    }

    fn parse_fresh_query(
        &self,
        query: &[u8],
    ) -> Result<(inspiring::PackingKeys<'static>, Vec<u8>)> {
        let packing_keys_len = ipir_sp::serialize::serialized_packing_keys_len(self.rlwe);
        let online_query_bytes_len = (self.ypir.db_rows * modulus_bits(self.rlwe.q)).div_ceil(8);
        let expected_len = packing_keys_len + online_query_bytes_len;
        if query.len() != expected_len {
            anyhow::bail!(
                "local-ipir reference query must be {expected_len} bytes, got {}",
                query.len()
            );
        }

        let packing_keys = deserialize_packing_keys(self.rlwe, &query[..packing_keys_len])
            .context("deserialize local-ipir packing keys")?;
        let online_query = query[packing_keys_len..].to_vec();

        Ok((packing_keys, online_query))
    }
}

impl PirBackend for LocalIpirBackend {
    fn meta(&self) -> BackendMetadata {
        BackendMetadata {
            backend: BackendKind::LocalIpir,
            record_count: self.record_count,
            pir_item_count: self.pir_item_count,
            db_rows: self.ypir.db_rows,
            db_cols: self.ypir.db_cols,
            item_size_bits: self.ypir.item_size_bits,
            setup_seed: self.setup_seed,
        }
    }

    fn answer_query(&self, query: &[u8]) -> Result<QueryAnswer> {
        let setup_deserialize_started = std::time::Instant::now();
        let (packing_keys, online_query) = self.parse_fresh_query(query)?;
        let setup_deserialize_us = setup_deserialize_started.elapsed().as_micros();

        let preprocess_started = std::time::Instant::now();
        let pack_preprocess_us = preprocess_started.elapsed().as_micros();

        let (body, timing) = self
            .server
            .perform_full_online_computation_simplepir_measured(
                self.rlwe,
                &online_query,
                &packing_keys,
                &self.top_key_images,
                &self.pack_preprocessed,
            )
            .context("local ipir-sp query failed")?;
        Ok(QueryAnswer {
            body,
            breakdown: ServerBreakdown {
                setup_deserialize_us,
                pack_preprocess_us,
                online_deserialize_us: timing.deserialize.as_micros(),
                matrix_vector_us: timing.matrix_vector.as_micros(),
                packing_us: timing.packing.as_micros(),
                serialization_us: timing.serialization.as_micros(),
            },
        })
    }
}

pub enum Backend {
    Local(LocalIpirBackend),
    #[cfg(feature = "ypir-artifact")]
    YpirArtifact(ypir_artifact::YpirArtifactBackend),
}

impl Backend {
    pub fn prepare(
        kind: BackendKind,
        snapshot: &NullifierSnapshot,
        setup_seed: u64,
    ) -> Result<Self> {
        match kind {
            BackendKind::LocalIpir => Ok(Self::Local(LocalIpirBackend::prepare(
                snapshot, setup_seed,
            )?)),
            BackendKind::YpirArtifact => {
                #[cfg(feature = "ypir-artifact")]
                {
                    Ok(Self::YpirArtifact(
                        ypir_artifact::YpirArtifactBackend::prepare(snapshot, setup_seed)?,
                    ))
                }
                #[cfg(not(feature = "ypir-artifact"))]
                {
                    anyhow::bail!(
                        "backend ypir-artifact requires building with --features ypir-artifact"
                    )
                }
            }
        }
    }
}

impl PirBackend for Backend {
    fn meta(&self) -> BackendMetadata {
        match self {
            Self::Local(backend) => backend.meta(),
            #[cfg(feature = "ypir-artifact")]
            Self::YpirArtifact(backend) => backend.meta(),
        }
    }

    fn answer_query(&self, query: &[u8]) -> Result<QueryAnswer> {
        match self {
            Self::Local(backend) => backend.answer_query(query),
            #[cfg(feature = "ypir-artifact")]
            Self::YpirArtifact(backend) => backend.answer_query(query),
        }
    }
}

#[cfg(feature = "ypir-artifact")]
mod ypir_artifact {
    use super::*;
    use std::sync::Mutex;
    use ypir::params::{params_for_scenario_simplepir, DbRowsCols};
    use ypir::serialize::{FromBytes, OfflinePrecomputedValues};
    use ypir::server::YServer;

    pub struct YpirArtifactBackend {
        params: &'static ypir_spiral::params::Params,
        record_count: usize,
        pir_item_count: usize,
        setup_seed: u64,
        server: YServer<'static, u16>,
        offline: Mutex<OfflinePrecomputedValues<'static>>,
    }

    impl YpirArtifactBackend {
        pub fn prepare(snapshot: &NullifierSnapshot, setup_seed: u64) -> Result<Self> {
            let params = Box::leak(Box::new(params_for_scenario_simplepir(
                snapshot.pir_row_count() as u64,
                ITEM_SIZE_BITS,
            )));
            let db = snapshot
                .coeff_iter(params.db_rows())
                .context("open snapshot coefficient iterator")?;
            let server = YServer::<u16>::new(params, db, false, true);
            let offline = server.perform_offline_precomputation_simplepir(None, None, None);

            Ok(Self {
                params,
                record_count: snapshot.record_count(),
                pir_item_count: snapshot.pir_row_count(),
                setup_seed,
                server,
                offline: Mutex::new(offline),
            })
        }
    }

    impl PirBackend for YpirArtifactBackend {
        fn meta(&self) -> BackendMetadata {
            BackendMetadata {
                backend: BackendKind::YpirArtifact,
                record_count: self.record_count,
                pir_item_count: self.pir_item_count,
                db_rows: self.params.db_rows(),
                db_cols: self.params.db_cols_simplepir(),
                item_size_bits: ITEM_SIZE_BITS,
                setup_seed: self.setup_seed,
            }
        }

        fn answer_query(&self, query: &[u8]) -> Result<QueryAnswer> {
            let first_dim_bytes_sz = self.params.db_rows() * std::mem::size_of::<u64>();
            let pub_param_bytes_sz = self.params.poly_len_log2
                * self.params.t_exp_left
                * self.params.poly_len
                * std::mem::size_of::<u64>();
            if query.len() != first_dim_bytes_sz + pub_param_bytes_sz {
                anyhow::bail!(
                    "YPIR query must be {} bytes, got {}",
                    first_dim_bytes_sz + pub_param_bytes_sz,
                    query.len()
                );
            }

            let deserialize_started = std::time::Instant::now();
            let first_dim = ypir_spiral::aligned_memory::AlignedMemory64::from_bytes(
                &query[..first_dim_bytes_sz],
            );
            let pub_params = ypir_spiral::aligned_memory::AlignedMemory64::from_bytes(
                &query[first_dim_bytes_sz..],
            );
            let deserialize_us = deserialize_started.elapsed().as_micros();

            let offline = self
                .offline
                .lock()
                .map_err(|_| anyhow::anyhow!("YPIR offline cache mutex poisoned"))?;
            let mut measurement = ypir::measurement::Measurement::default();
            let server_started = std::time::Instant::now();
            let body = self.server.perform_online_computation_simplepir(
                first_dim.as_slice(),
                &offline,
                &[pub_params.as_slice()],
                Some(&mut measurement),
            );
            let server_us = server_started.elapsed().as_micros();
            let matrix_vector_us = measurement.online.first_pass_time_ms as u128 * 1_000;
            let packing_us = measurement.online.ring_packing_time_ms as u128 * 1_000;
            let serialization_us = server_us
                .saturating_sub(matrix_vector_us)
                .saturating_sub(packing_us);

            Ok(QueryAnswer {
                body,
                breakdown: ServerBreakdown {
                    setup_deserialize_us: 0,
                    pack_preprocess_us: 0,
                    online_deserialize_us: deserialize_us,
                    matrix_vector_us,
                    packing_us,
                    serialization_us,
                },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use inspiring::{GadgetParams, RlweParams};
    use tempfile::NamedTempFile;

    use super::*;

    fn tiny_ypir(db_rows: usize, db_cols: usize) -> YpirSchemeParams {
        YpirSchemeParams {
            num_items: db_rows as u64,
            item_size_bits: (db_cols * 2) as u64,
            poly_len: 8,
            db_dim_1: 0,
            db_dim_2: 1,
            instances: db_cols / 8,
            db_rows,
            db_cols,
            p: 4,
            q_prime_1: 16,
            q_prime_2: 257,
            q2_bits: 8,
            t_exp_left: 3,
            t_exp_right: 2,
        }
    }

    #[test]
    fn local_backend_reports_snapshot_shape_with_tiny_params() {
        let mut file = NamedTempFile::new().expect("temp file");
        file.write_all(&[9u8; 32]).expect("write snapshot");
        let snapshot = NullifierSnapshot::open(file.path()).expect("open snapshot");
        let rlwe = RlweParams::new(
            8,
            12289,
            4,
            3.2,
            GadgetParams {
                bits_per: 3,
                ell: 5,
            },
        )
        .expect("valid params");

        let backend = LocalIpirBackend::prepare_with_params(&snapshot, 7, rlwe, tiny_ypir(8, 8))
            .expect("prepare backend");
        let meta = backend.meta();

        assert_eq!(meta.backend, BackendKind::LocalIpir);
        assert_eq!(meta.record_count, 1);
        assert_eq!(meta.pir_item_count, 1);
        assert_eq!(meta.db_rows, 8);
        assert_eq!(meta.db_cols, 8);
    }

    #[test]
    fn local_backend_rejects_noncanonical_query_body() {
        let mut file = NamedTempFile::new().expect("temp file");
        file.write_all(&[9u8; 32]).expect("write snapshot");
        let snapshot = NullifierSnapshot::open(file.path()).expect("open snapshot");
        let rlwe = RlweParams::new(
            8,
            12289,
            4,
            3.2,
            GadgetParams {
                bits_per: 3,
                ell: 5,
            },
        )
        .expect("valid params");

        let backend = LocalIpirBackend::prepare_with_params(&snapshot, 7, rlwe, tiny_ypir(8, 8))
            .expect("prepare backend");
        let old_key_pair_len = 4 * backend.rlwe.gadget.ell * backend.rlwe.d * 8;
        let online_query_len = (backend.ypir.db_rows * modulus_bits(backend.rlwe.q)).div_ceil(8);
        let old_body = vec![0u8; old_key_pair_len + online_query_len];

        let err = match backend.parse_fresh_query(&old_body) {
            Ok(_) => panic!("old compact key-pair body must be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("reference query"));
    }
}
