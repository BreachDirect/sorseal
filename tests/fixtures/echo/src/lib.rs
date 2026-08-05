// A deliberately tiny, dependency-free contract-like crate used to exercise
// sorseal's record/verify e2e path. Any change here must break `sorseal verify`.

pub fn ping() -> u32 {
    42
}
