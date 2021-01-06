all: build test

test: test_geth_purego test_geth_goasm test_evmone

build: build_bls12381 build_pairing_test_nondegen

build_bls12381:
	python3 generator/generate.py > bls12_381.huff

build_bls12381_final_exp_test:
	node compile.js FINAL_EXPONENTIATION_TEST_HARD_CODED > bls12381_final_exp_test.hex

build_pairing_test_nondegen:
	node compile.js PAIRING_EQ1_TEST > bls12381_pairing_eq2_test.hex

build_pairing_eq2_test:
	node compile.js PAIRING_EQ2_TEST > bls12381_pairing_eq2_test.hex

# test miller loop with G1/G2 identity elements as inputs, expect to match output from blst
test_evmone_evm384_bls12381_miller_loop:
	./run_evmone_bench.sh bls12381_miller_loop_test.hex a0fed68de3a467a0cae848e36c4a17ce3ea97ff6db64e95388a7553453ad145e0d77e60d6ef811be718d706e042ea20331074a1078325ca9772f8f3d6058185dfed13ea77f75281596167a2e691b6310cff1650c64c8b91897bf092964acb10037e4411bfe4f081b3054e9e81b8db408ea2a31350ccf38345c3368089f96827aca6c1cf59296d1fb5677aa689bcba706890db803f231375fe3ef7c781aa543970ed1c7a5befc902181a7d46bee57da4863e452a28aef6a52000e69f25fae6114fb682cdf2eba4e06f9dcb52f20178a2cb48ae5c18cb9c2ae7a55a803936f43d60f7e89bfd26b3cb3ca04114c214bd20f6a8f23cdde89fcc44433a38ab5bc7486973d7d30b48023a3ff53c07e13ba6d5453bfd66cd3a8910cf1505dfa75043103511ca9fb4d1d953537556b21107f3caa319e50938ca7190ab314670608db7a52faf89c4d079f4d8976881813579b3e072829993f000daf1492576d4eaaf52fb8a8c7414ea56d567e72c54537326004c7c1b3f8da49ed7f0a1f9670438a68b903642a4ff7f323563c492cc67cf70abf8eb96123eb634229a2a7ce1ef9765fb634cb4b08f06d845a59e3106b2febb1711218ec3b452f237098361dd829e83e89f960d97292654a131b118bf29af86e258f9cff8b19766530a5005d1b8fb2b26c15bfb8ca27327f5b3dfbb7b08e4bc2646f510df8127466d48c43be0f0b24e5c47b741ef9f7a87b2455e310b4493ae56b0bdcd282df328346129a5f5aa2d032f5b28ae5a70e37ff7f1a1da7131579bbc806c4c3b32b47ed107cec0180f5774cd40e

test_evmone:
	./run_evmone_bench.sh bls12381_pairing_eq2_test.hex 0000000000000000000000000000000000000000000000000000000000000001

test_geth_goasm:
	./go-ethereum/build/bin/evm --statdump --input 0x120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c160bbc3efc5008a26a0e1c8c3fad0059c051ac582950405194dd595f13570725ce8c22631a7918fd8ebaac93d50ce72271058191924350bcd76f67b7631863366b9894999d1a3caee9a1a893b53e2ae580b3f5fb2687b4961af5f28fa202940a1011922a097360edf3c2b6ed0ef21585471b1ab6cc8541b3673bb17e18e2867806aaa0c59dbccd60c3a5a9c0759e23f6067e80dae507d3a975f0ef25a2bbefb5e96e0d495fe7e6856caa0a635a597cfa1f5e369c5a4c730af860494c4a11922a0963de1bf2e7175850a43ccaed79495c4ec93da33a86adac6a3be4eba018aa270a2b1461dcadc0fc92df64b05d0083fd8e --codefile bls12381_pairing_eq2_test.hex run

test_geth_purego:
	./go-ethereum-purego/build/bin/evm --statdump --input 0x120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c160bbc3efc5008a26a0e1c8c3fad0059c051ac582950405194dd595f13570725ce8c22631a7918fd8ebaac93d50ce72271058191924350bcd76f67b7631863366b9894999d1a3caee9a1a893b53e2ae580b3f5fb2687b4961af5f28fa202940a1011922a097360edf3c2b6ed0ef21585471b1ab6cc8541b3673bb17e18e2867806aaa0c59dbccd60c3a5a9c0759e23f6067e80dae507d3a975f0ef25a2bbefb5e96e0d495fe7e6856caa0a635a597cfa1f5e369c5a4c730af860494c4a11922a0963de1bf2e7175850a43ccaed79495c4ec93da33a86adac6a3be4eba018aa270a2b1461dcadc0fc92df64b05d0083fd8e --codefile bls12381_pairing_eq2_test.hex run
