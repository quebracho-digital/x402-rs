# x402-rs

x402 payments in Rust for embedded and real-time devices, starting with QNX 8.0.
A port of [quebracho/x402](https://github.com/quebracho-digital/x402) (PHP).

**Status:** design. No code yet.

The first crate will be `quebracho-x402`: a `no_std` core that lets a device
charge for a resource with x402 (verify the payment, claim it once, settle,
screen addresses).

## License

MIT. See [LICENSE](LICENSE).
