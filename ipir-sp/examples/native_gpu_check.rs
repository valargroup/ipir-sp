//! Bounded CUDA/native-modulus differential against independent u128 sums.
use simplepir_kernel::{cuda::CudaKernel,FirstDimKernel};
fn main(){
    let (rows,cols)=(4096,16);let q=1u64<<54;
    let db:Vec<u16>=(0..rows*cols).map(|i|((i*171+65535)%65536) as u16).collect();
    let mut kernel=CudaKernel::new(0).unwrap();kernel.try_prepare(&db,rows,cols).unwrap();
    for case in 0..3 {
        let query:Vec<u64>=(0..rows).map(|i|match case{0=>0,1=>q-1,_=>(i as u64*1234567891011)&(q-1)}).collect();
        let mut out=vec![0;cols];kernel.try_multiply_power_of_two(q,&db,rows,cols,&query,&mut out).unwrap();
        let expected:Vec<u64>=db.chunks_exact(rows).map(|col|(col.iter().zip(&query).map(|(&a,&b)|a as u128*b as u128).sum::<u128>()%q as u128)as u64).collect();
        assert_eq!(out,expected);println!("case={case} exact=true rows={rows} cols={cols} q={q}");
    }
    assert!(kernel.try_multiply_power_of_two(q,&db,rows,cols,&vec![q;rows],&mut vec![0;cols]).is_err());
    println!("native CUDA differential passed");
}
