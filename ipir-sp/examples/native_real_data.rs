//! Short native-profile sanity check on a frozen Enhance record stream.
use ipir_sp::native::*;
use reinspiring::native::*;
use sha2::{Digest, Sha256};
use std::{fs, time::Instant};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let path = &args[1];
    let rows: usize = args[2].parse().unwrap();
    let samples: usize = args[3].parse().unwrap();
    let ell: usize = args.get(4).map(|x| x.parse().unwrap()).unwrap_or(2);
    let first_record: usize = args.get(5).map(|x| x.parse().unwrap()).unwrap_or(0);
    const ROW_BYTES: usize = 653 * 33;
    const COLS: usize = 12288;
    let raw = fs::read(path).unwrap();
    assert_eq!(raw.len() % 653, 0);
    let start = first_record.checked_mul(653).unwrap();
    assert!(start < raw.len());
    assert_eq!(first_record % 33, 0, "production rows must stay aligned");
    let available = (raw.len() - start).min(rows * ROW_BYTES);
    let mut records = vec![0; rows * ROW_BYTES];
    records[..available].copy_from_slice(&raw[start..start + available]);
    let used_rows = available.div_ceil(ROW_BYTES);
    let mut db = vec![0u16; rows * COLS];
    for row in 0..rows {
        for (col, pair) in records[row * ROW_BYTES..(row + 1) * ROW_BYTES]
            .chunks(2)
            .enumerate()
        {
            db[col * rows + row] = u16::from_le_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        }
    }
    let snapshot: [u8; 32] = Sha256::digest(&records).into();
    let params = NativeParams::new(2048, 54, 16, 19, ell, SecretDistribution::Gaussian).unwrap();
    let profile = NativeProfile::new(params, rows, COLS).unwrap();
    let setup = NativePublicSetup::new(profile, [73; 32], snapshot);
    let began = Instant::now();
    let server = NativeServer::build(setup, db).unwrap();
    println!(
        "{}",
        serde_json::json!({"kind":"setup", "native_revision":"96572f026da31ad4c4bc53b9a1ce08b9268a1f40", "d":2048,"q":1u64<<54,"p":65536,"gadget_bits":19,"sampler":"Gaussian", "rows":rows,"cols":COLS,"first_record":first_record,"records":available/653,"limbs":ell,"threads":rayon::current_num_threads(),"seconds":began.elapsed().as_secs_f64(),"coefficient_bytes":server.coefficient_bytes(),"snapshot_sha256":format!("{:x}",Sha256::digest(&records))})
    );
    let published =
        NativePublished::from_bytes(server.setup(), &server.published().to_bytes()).unwrap();
    let mut bad = 0;
    for i in 0..samples {
        let row = match i {
            0 => 0,
            1 => used_rows / 2,
            2 => used_rows - 1,
            3 => rows - 1,
            _ => ((i as u64 * 2654435761) % used_rows as u64) as usize,
        };
        let request = NativeRequest::generate(server.setup(), row).unwrap();
        let began = Instant::now();
        let (response, timing) = server.respond(request.bytes()).unwrap();
        let elapsed = began.elapsed();
        let mut expected = vec![0u64; COLS];
        for (col, pair) in records[row * ROW_BYTES..(row + 1) * ROW_BYTES]
            .chunks(2)
            .enumerate()
        {
            expected[col] = u16::from_le_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u64;
        }
        let (decoded, phase_error) = request
            .decode_with_error(&published, &response, &expected)
            .unwrap();
        let decoded_bytes: Vec<u8> = decoded
            .iter()
            .flat_map(|x| (*x as u16).to_le_bytes())
            .collect();
        assert_eq!(
            &decoded_bytes[..ROW_BYTES],
            &records[row * ROW_BYTES..(row + 1) * ROW_BYTES],
            "record bytes differ"
        );
        let wrong = decoded
            .iter()
            .zip(&expected)
            .filter(|(a, b)| a != b)
            .count();
        bad += usize::from(wrong != 0);
        println!(
            "{}",
            serde_json::json!({"kind":"query","sample":i,"row":row,"correct":wrong==0,"wrong_coefficients":wrong,"phase_error":phase_error,"decode_half_interval":(1u64<<54)/(2*65536),"packing_ms":timing.packing.as_secs_f64()*1000.,"worker_ms":timing.matrix_vector.as_secs_f64()*1000.,"server_ms":elapsed.as_secs_f64()*1000.,"upload_bytes":request.bytes().len(),"download_bytes":response.len()})
        );
    }
    println!(
        "{}",
        serde_json::json!({"kind":"summary","samples":samples,"incorrect":bad})
    );
    if bad > 0 {
        std::process::exit(1);
    }
}
