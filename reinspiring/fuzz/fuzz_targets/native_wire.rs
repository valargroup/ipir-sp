#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use ipir_sp::native::*;
use reinspiring::native::*;
use rand_chacha::{ChaCha20Rng,rand_core::SeedableRng};
struct Fixture { server:NativeServer, request:NativeRequest, valid:Vec<u8>, response:Vec<u8> }
fn fixture()->&'static Fixture {
 static F:OnceLock<Fixture>=OnceLock::new();
 F.get_or_init(|| {
  let p=NativeParams::new(8,54,14,19,2,SecretDistribution::Gaussian).unwrap();
  let setup=NativePublicSetup::new(NativeProfile::new(p,8,8).unwrap(),[1;32],[2;32]);
  let server=NativeServer::build(setup,vec![1;64]).unwrap();
  let request=NativeRequest::generate_with_rng(server.setup(),0,&mut ChaCha20Rng::seed_from_u64(9)).unwrap();
  let valid=request.bytes().to_vec();let response=server.respond(&valid).unwrap().0;
  Fixture{server,request,valid,response}
 })
}
fuzz_target!(|data:&[u8]| {
 let f=fixture();
 let _=f.server.respond(data);
 let _=NativePublished::from_bytes(f.server.setup(),data);
 let _=f.request.decode(&f.server.published(),data);
 // Keep lengths/headers valid often enough to exercise arithmetic, not only parsers.
 let mut request=f.valid.clone();let mut response=f.response.clone();
 for pair in data.chunks_exact(2) {
  let idx=36+usize::from(pair[0])%(request.len()-36);request[idx]^=pair[1];
  let idx=68+usize::from(pair[0])%(response.len()-68);response[idx]^=pair[1];
 }
 let _=f.server.respond(&request);
 let _=f.request.decode(&f.server.published(),&response);
});
