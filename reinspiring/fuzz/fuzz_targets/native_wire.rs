#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use ipir_sp::native::*;
use reinspiring::native::*;
use rand_chacha::{ChaCha20Rng,rand_core::SeedableRng};
struct Fixture { server:NativeServer, request:NativeRequest, valid:Vec<u8>, response:Vec<u8> }
fn fixtures()->&'static [Fixture;5] {
 static F:OnceLock<[Fixture;5]>=OnceLock::new();
 F.get_or_init(|| [54,47,0,29,32].map(|bits| {
  let p=NativeParams::new(8,54,14,19,2,SecretDistribution::Gaussian).unwrap();
  let profile=NativeProfile::new(p,8,8).unwrap();
  let profile=if bits==0 {profile.with_two_mask_output().unwrap()} else if bits<40 {profile.with_two_mask_output().unwrap().with_published_mask_bits(bits).unwrap()} else {profile.with_kh_bits(bits).unwrap()};
  let setup=NativePublicSetup::new(profile,[1;32],[2;32]);
  let server=NativeServer::build(setup,vec![1;64]).unwrap();
  let request=NativeRequest::generate_with_rng(server.setup(),0,&mut ChaCha20Rng::seed_from_u64(9)).unwrap();
  let valid=request.bytes().to_vec();let response=server.respond(&valid).unwrap().0;
  Fixture{server,request,valid,response}
 }))
}
fuzz_target!(|data:&[u8]| {
 for f in fixtures() {
 let _=f.server.respond(data);
 let _=NativePublished::from_bytes(f.server.setup(),data);
 let mut published=f.server.published().to_bytes();
 for pair in data.chunks_exact(2) { let idx=usize::from(pair[0])%published.len();published[idx]^=pair[1]; }
 if let Ok(p)=NativePublished::from_bytes(f.server.setup(),&published) {
  if let Ok(prepared)=p.prepare(f.server.setup()) { let _=f.request.decode_prepared(&prepared,&f.response); }
 }
 let _=f.request.decode(&f.server.published(),data);
 // Keep lengths/headers valid often enough to exercise arithmetic, not only parsers.
 let mut request=f.valid.clone();let mut response=f.response.clone();
 for pair in data.chunks_exact(2) {
  let idx=36+usize::from(pair[0])%(request.len()-36);request[idx]^=pair[1];
  let idx=68+usize::from(pair[0])%(response.len()-68);response[idx]^=pair[1];
 }
 let _=f.server.respond(&request);
 let _=f.request.decode(&f.server.published(),&response);
 }
});
