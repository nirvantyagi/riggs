# Installation
```bash
sudo apt install libclang-dev
```

# Running Tests

PARI initialization allocates a large amount of space on the stack, and so will segfault when run in multiple threads.
To run the tests, specify single-threaded execution:
```bash
cargo test -- --test-threads=1
```
