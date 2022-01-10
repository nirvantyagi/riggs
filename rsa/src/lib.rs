use std::error::Error as ErrorTrait;

pub mod bigint;

pub type Error = Box<dyn ErrorTrait>;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
