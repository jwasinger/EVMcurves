
We use engines which implement EVM384v7, our current working version EVM384.


### evmone

Build evmone. Warning: when building evmone, it will download a bunch of stuff, including to hidden directory `.hunter` in your home directory and maybe other places. I don't know of any way around this.

```
git clone --recursive https://github.com/jwasinger/evmone
cd evmone
git checkout evm384-v7
git checkout 60092fc9aaf592b6f1ad4081795c067bbd90d2d1   # maybe more recent versions work too
mkdir build
cd build
cmake .. -DEVMONE_TESTING=ON
cmake --build . -- -j
cd ../..
```

Run tests in evmone. This also runs a benchmark.

First we run tests with inputs/outputs from command line. The command is `evmone-bench <bytecode_filename>.hex <hex input>` `<hex output>`.

```
# test 1
./evmone/build/bin/evmone-bench ../miller_loop.hex 160c53fd9087b35cf5ff769967fc1778c1a13b14c7954f1547e7d0f3cd6aaef040f4db21cc6eceed75fb0b9e417701123a8818f32a6c52ff70023b38e49c899255d0a99f8d73d7892ac144a35bf3ca1217534b96761bff3c304477e9edd2440e100a9402a28ff2f51a96b48726fbf5b380e52a3eb593a8a1e9ae3c1a9d9994986b36631863b7676fd7bc50439291810506f6239e75c0a9a5c360cdbc9dc5a0aa067886e2187eb13b67b34185ccb61a1b478515f20eedb6c2f3ed6073092a9211615eb69f07f58b6da5631d53df052fc5c992a64c344d4a7f5fc977859b9587a834875c5240fe4743b50bffba5b147d194efa9a206d033e0c239e3f86f4d80106840accba362683e0846f472a36ef2debe9e10e9f654f0464a7caa1d5484fd50e a0fed68de3a467a0cae848e36c4a17ce3ea97ff6db64e95388a7553453ad145e0d77e60d6ef811be718d706e042ea20331074a1078325ca9772f8f3d6058185dfed13ea77f75281596167a2e691b6310cff1650c64c8b91897bf092964acb10037e4411bfe4f081b3054e9e81b8db408ea2a31350ccf38345c3368089f96827aca6c1cf59296d1fb5677aa689bcba706890db803f231375fe3ef7c781aa543970ed1c7a5befc902181a7d46bee57da4863e452a28aef6a52000e69f25fae6114fb682cdf2eba4e06f9dcb52f20178a2cb48ae5c18cb9c2ae7a55a803936f43d60f7e89bfd26b3cb3ca04114c214bd20f6a8f23cdde89fcc44433a38ab5bc7486973d7d30b48023a3ff53c07e13ba6d5453bfd66cd3a8910cf1505dfa75043103511ca9fb4d1d953537556b21107f3caa319e50938ca7190ab314670608db7a52faf89c4d079f4d8976881813579b3e072829993f000daf1492576d4eaaf52fb8a8c7414ea56d567e72c54537326004c7c1b3f8da49ed7f0a1f9670438a68b903642a4ff7f323563c492cc67cf70abf8eb96123eb634229a2a7ce1ef9765fb634cb4b08f06d845a59e3106b2febb1711218ec3b452f237098361dd829e83e89f960d97292654a131b118bf29af86e258f9cff8b19766530a5005d1b8fb2b26c15bfb8ca27327f5b3dfbb7b08e4bc2646f510df8127466d48c43be0f0b24e5c47b741ef9f7a87b2455e310b4493ae56b0bdcd282df328346129a5f5aa2d032f5b28ae5a70e37ff7f1a1da7131579bbc806c4c3b32b47ed107cec0180f5774cd40e
./evmone/build/bin/evmone-bench ../final_exponentiation.hex a0fed68de3a467a0cae848e36c4a17ce3ea97ff6db64e95388a7553453ad145e0d77e60d6ef811be718d706e042ea20331074a1078325ca9772f8f3d6058185dfed13ea77f75281596167a2e691b6310cff1650c64c8b91897bf092964acb10037e4411bfe4f081b3054e9e81b8db408ea2a31350ccf38345c3368089f96827aca6c1cf59296d1fb5677aa689bcba706890db803f231375fe3ef7c781aa543970ed1c7a5befc902181a7d46bee57da4863e452a28aef6a52000e69f25fae6114fb682cdf2eba4e06f9dcb52f20178a2cb48ae5c18cb9c2ae7a55a803936f43d60f7e89bfd26b3cb3ca04114c214bd20f6a8f23cdde89fcc44433a38ab5bc7486973d7d30b48023a3ff53c07e13ba6d5453bfd66cd3a8910cf1505dfa75043103511ca9fb4d1d953537556b21107f3caa319e50938ca7190ab314670608db7a52faf89c4d079f4d8976881813579b3e072829993f000daf1492576d4eaaf52fb8a8c7414ea56d567e72c54537326004c7c1b3f8da49ed7f0a1f9670438a68b903642a4ff7f323563c492cc67cf70abf8eb96123eb634229a2a7ce1ef9765fb634cb4b08f06d845a59e3106b2febb1711218ec3b452f237098361dd829e83e89f960d97292654a131b118bf29af86e258f9cff8b19766530a5005d1b8fb2b26c15bfb8ca27327f5b3dfbb7b08e4bc2646f510df8127466d48c43be0f0b24e5c47b741ef9f7a87b2455e310b4493ae56b0bdcd282df328346129a5f5aa2d032f5b28ae5a70e37ff7f1a1da7131579bbc806c4c3b32b47ed107cec0180f5774cd40e c5851fa033e47219382577fd762bd397f9cd6bc96f54cec81406d466733ef6ce80378481273411a625d8c63f8a44f31395699d2eb03163d27d7e79f782a4689d92ea398d24299b9caa0731e1a21c80f466b0bcbd32076ca1780436baafa43c0841b61609db61e2590d963eb2f4b61627459cbda0105be5c8a8ed4d9cd90bdb0bc5aafd57bf9ef88c5e7a779e92b7d612355fe1b08851c85f6563098f3a6ea0342cd62ae0a62631db0b999a7da95a6ffc10c289ebf5552fa189886f923a70231778878271298f58938575ab11865bf643df9f27ecf5aa8331f69dc98ae1d773fab0994ca6a676e1641f8f38588ca79f1712ef2aca110a2a676bf1a32ab5b9110d6e059d69d01244a4a55b1a2277011dc02955736cdecee06639c3dd9f1ea7f50579c662b0a1880ad30483fc355d6ac55a0d291fa8a634c8d0c70737dac23054cdf00a5080f77fc2f0ae2ed7e2a65d240956511b7976062e9f13fe184923c8d1e2f41b563c9f459e4cc1e3d3b9535ee8a32000a7211e120a82cc9ac5418361af15b13a99248c65957cb986a81c7238eb73bc34744749d756528b4a50ea0219a48b6dce860cf8d3a304aa6e68fb874aa61826cf20b91be783bb4539a792ac77522aa046f0949fe50efcf7586078f3cd5871f645f9821b06c17c67e5db9faa47f80357e63461a5db78806e8a99439aecd71c6637991a9a59aab144ee42082ff6a0c9fadf05b6e39b158ec23ff14a0dba860cb1ff526aa0f20fe86c901a7248ca94761485b0033e188375e2e4ce40ddaf67f5fca526e5d2966d9a42221f86499f7e19

# test 2
./evmone/build/bin/evmone-bench ../miller_loop.hex efe91bb26eb1b9ea4e39cdff121548d55ccb37bdc8828218bb419daa2c1e958554ff87bf2562fcc8670a74fede488800a68e9c5555de82fd1a59a934363dfec20523b84fd42a186dd9523eca48b37fbdc4eeaf305d4f671fff2e10c5694a91019651007c8fe4e374025453bb529f88719b6bdb57f501a57e31503e2071f065c5011d84a3a23096c8fe85c771be808401fe6aa16efafe6bb2e66ff7bf8499f85cdec99907ce3e22e7cbce5166ee772753d540b1b1515adc70314000e74060ea00df4dfd09440994f02e7c8c6d8888cff204d232f882c258e4589ab47472ed03deb4efb2cb6b7360d97b6f445d660d6900938feb85d1cda1d90b27525e3fb87942c204e3ce1ab06324f11b593dac11ef61aa701a15a39d549e185583d29f16f800 7289fbe57480548c2a4ee690af9fbe0f997d94c0ba7c8cabc7c96de505861e00a736bb242dbb15f10e7f401ec5c27a0bf86c9a32f9dcb7b3d5bd800743d2c24957dadf059d8c125f04408a3b9d5444bb6090abb07a403b5c92fb48a7b965551195b5d5187138bbd0c87ff7bf91df43b049ee9408198358b272dbc41879e8bcb761e921af8273d0eb2e93d9dc7343950748c81469d37d02e13b6bf27d81dee42181cf5feb9cf7325d324d8c320a8a90558d74eda73228fb7f276c7495af07760f0308a3f6ebde7ead61c0ce1539d22fef1cad48deb2bdbf423f5919e60b92b62b3083847b772581f949a44087e2c8270d72a309861ce128b0c93dd4aaa8a6ecc1dd5df7ff0c518f70ce648b5b7ff7e94db66c3ae2333ca2a4a2de25732828510e5382eebb28c5e8d4030672f418b86ed67656343ad53d04a819853b5120587d3aea0e7fe5ce9dbdde7fa5248cf2fbaf1568a73e5a7ca2156ad951e6fe288e71582284d00b1ecb4b25e2d5be953beae1223a12a672a4bfb759adc17ca135e6d70459105cb49aeabc69858d29aaa06e94d5d9e0f1debe188cdfbd6753cdf99cf7a2c14aeaf7c71dd678f2c620e77a364d0805cad58f08c9b6c9104c206704e912c306df8bce4c54cdb7adc3f0a695f13273439455aa3d52c03cd3a9e34c0ee1b604cbd547ffadb5e4cc10ead2c8a82e86b2db3df039bae368fb5c1d36275526c8896c09746bd56906c4653ebde42672c7115bdde0d5c24457fd4159aa71d1665242e22af2b7aac89e8d13e4758dcfffa1aa675df2b49993dfbd030270b98b061719
./evmone/build/bin/evmone-bench ../final_exponentiation.hex 7289fbe57480548c2a4ee690af9fbe0f997d94c0ba7c8cabc7c96de505861e00a736bb242dbb15f10e7f401ec5c27a0bf86c9a32f9dcb7b3d5bd800743d2c24957dadf059d8c125f04408a3b9d5444bb6090abb07a403b5c92fb48a7b965551195b5d5187138bbd0c87ff7bf91df43b049ee9408198358b272dbc41879e8bcb761e921af8273d0eb2e93d9dc7343950748c81469d37d02e13b6bf27d81dee42181cf5feb9cf7325d324d8c320a8a90558d74eda73228fb7f276c7495af07760f0308a3f6ebde7ead61c0ce1539d22fef1cad48deb2bdbf423f5919e60b92b62b3083847b772581f949a44087e2c8270d72a309861ce128b0c93dd4aaa8a6ecc1dd5df7ff0c518f70ce648b5b7ff7e94db66c3ae2333ca2a4a2de25732828510e5382eebb28c5e8d4030672f418b86ed67656343ad53d04a819853b5120587d3aea0e7fe5ce9dbdde7fa5248cf2fbaf1568a73e5a7ca2156ad951e6fe288e71582284d00b1ecb4b25e2d5be953beae1223a12a672a4bfb759adc17ca135e6d70459105cb49aeabc69858d29aaa06e94d5d9e0f1debe188cdfbd6753cdf99cf7a2c14aeaf7c71dd678f2c620e77a364d0805cad58f08c9b6c9104c206704e912c306df8bce4c54cdb7adc3f0a695f13273439455aa3d52c03cd3a9e34c0ee1b604cbd547ffadb5e4cc10ead2c8a82e86b2db3df039bae368fb5c1d36275526c8896c09746bd56906c4653ebde42672c7115bdde0d5c24457fd4159aa71d1665242e22af2b7aac89e8d13e4758dcfffa1aa675df2b49993dfbd030270b98b061719 5700d5fd5a7867670dbda880ce7fd4ebaf52cb63962c2fafcc31a9a0dbc315fa834c903d2b36f90cd71df0458f61280fc79398bad0d352ea5344e4c04d747ea9ad281132f774344548aad12e61e3f4a1e1f43b6e32fe62c67e2dd537c3dd4a09a71d0481c6fa1baa4f1b211273292c4e19068218e997d0f2f34da46f0bafa1fcc6f8fa83175d37f692f0fdff342403133b42b8d7b18e7ad1abe50ce1d90b509125746bb53a08542822ccce71fe2d05eb2f9bebb547ea3c3c864c900e9fbe7d12e70c03c4b719c780a01c438ac00aea2200c36a6e7ee505dd764aa1e938a4fed4c00a00dd9735b0a48c04db477f14830fad4f35f720f7967216aadea6e3275afe83959cdf380acfe2043aab9c467938189c8688f2486f8c94c455e92573898a05554ea1fe339fb204a6010b364703d68a7bba39e4fb3029d88f2a2ae2eb26c97903a82262205fe7192c8fc75800996b187e4a58b4f10f6d61a2e7bd962d0227a04b3b7485e2af9cb79f04efffe9980b24cbac71c8ac28158c14b58dff316f58156f2272059af41e25e16638b2efbb013fc2116599bdefcdfaf750d45e474c2a5781df39cb2e6eae8664911a3223c1cb0eab8ed9e2df420133521b5df3a53e87222670cf05174800df045e5e54f6324f0c8dd5234a436e5bbb85558183d297f608ba68b40d2203f34bb9acf15dfdab488ac02bd9adfa2e44ad848e78d4fa7ce8bf049ddbec5a43fa25924400fe0a9e5a18c38870897a488527a03cc1a04a2b8d04cfffebaeba6d188e3decaadd53ab23bbb40cc738ad12f6318829275b7822be13

# test 3
./evmone/build/bin/evmone-bench ../miller_loop.hex edae919853b05e124b0df9d0eb00bb861ce4007fb66a592b5b010403b043dc817a0761ddbeef7f574bc8f1ec25da810f199ebd34b2dee439b771301cd36f80cd8131b0471cfdf71d6c994711f63a9a20fe43b77778e36c6d9186ec919562af11b8bd21c1c85680d4efbb05a82603ac0b77d1e37a640b51b4023b40fad47ae4c65110c52d27050826910a8ff0b2a24a027e2b045d057dace5575d941312f14c3349507fdcbb61dab51ab62099d0d06b59654f2788a0d3ac7d609f7152602be0130128b808865493e189a2ac3bccc93a922cd16051699a426da7d3bd8caa9bfdad1a352edac6cdc98c116e7d7227d5e50cbe795ff05f07a9aaa11dec5c270d373fab992e57ab927426af63a7857e283ecb998bc22bb0d2ac32cc34a72ea0c40606 3cf8fe6aba6061de70638196991c6c245ccc8d011108841a2d19eecc877c3fbcb1cc9a694c0aac2903c8c41520526a0016a3242ef581eb5bc185108cbde497bc21150576fd77b2c9166fb392a444e0503c54caed9cba054d3851c6fd588219171d364d5982bdece58c3d9ff500fd25ae4589ca4d3c2d81391ce1a3afbc4c5ffaab909e5e2f03b4e690a4b7677dd39102a5a6a20f4e3d0702b4dc8f8dab2dbd3e5b769c5116bc3889502ced4f6efd1f5e344b1f6299bb1e7c9508f465a64da515e9f8ce46f6dd5883b4342c56af2ffcf89088ccd992bb4b707824d3ad74d569b07f9ce69c0c7c38907ff41b57c0ce190c925dd857f1ef631f083592773a02acb2c93e1dd2940cf0d29bed0d3710c2128811267eba6d19202807de48bb426991082d0bc7f84f68520c8cd47622db80eb306e1dc84ba817c63539ac4455c4284efcb18301782b2100096e01840ae3dfe3027f67af26013c4bbf335e878f66312c5c645fb5418ba855c6bac3324fbda16158c4c87246767192c372029e9e9b0c3b0c2c57f559fdd03dc9a9443633bf4a1f0b5306341fbf67d47ef5bef488a82f5adb75e860182004899f9ad9ad48a5c36d08b2e7a310546da097a4f53d663c875fea9cf99e7e6a1c607d23004c368f1f4955c00c2352f10484e582115d83cb5cd019f6aed3544c28c8b9efda117c0b8241adc55ed0ee88c6bce0a06f41a11a1ddb939ddba145345d9e78854c55455435741415a66fbe62fa646a72f15b3ffdccdae69abfc78c290cebb24fbb96b781375f87fbdb4168ccc04f245f02531b38e1400a
./evmone/build/bin/evmone-bench ../final_exponentiation.hex 3cf8fe6aba6061de70638196991c6c245ccc8d011108841a2d19eecc877c3fbcb1cc9a694c0aac2903c8c41520526a0016a3242ef581eb5bc185108cbde497bc21150576fd77b2c9166fb392a444e0503c54caed9cba054d3851c6fd588219171d364d5982bdece58c3d9ff500fd25ae4589ca4d3c2d81391ce1a3afbc4c5ffaab909e5e2f03b4e690a4b7677dd39102a5a6a20f4e3d0702b4dc8f8dab2dbd3e5b769c5116bc3889502ced4f6efd1f5e344b1f6299bb1e7c9508f465a64da515e9f8ce46f6dd5883b4342c56af2ffcf89088ccd992bb4b707824d3ad74d569b07f9ce69c0c7c38907ff41b57c0ce190c925dd857f1ef631f083592773a02acb2c93e1dd2940cf0d29bed0d3710c2128811267eba6d19202807de48bb426991082d0bc7f84f68520c8cd47622db80eb306e1dc84ba817c63539ac4455c4284efcb18301782b2100096e01840ae3dfe3027f67af26013c4bbf335e878f66312c5c645fb5418ba855c6bac3324fbda16158c4c87246767192c372029e9e9b0c3b0c2c57f559fdd03dc9a9443633bf4a1f0b5306341fbf67d47ef5bef488a82f5adb75e860182004899f9ad9ad48a5c36d08b2e7a310546da097a4f53d663c875fea9cf99e7e6a1c607d23004c368f1f4955c00c2352f10484e582115d83cb5cd019f6aed3544c28c8b9efda117c0b8241adc55ed0ee88c6bce0a06f41a11a1ddb939ddba145345d9e78854c55455435741415a66fbe62fa646a72f15b3ffdccdae69abfc78c290cebb24fbb96b781375f87fbdb4168ccc04f245f02531b38e1400a 8fab923b890c35efc077ed40d3b2cb325d4be5815c43cfd6c2b10a0feae3edea11a0a045eff2c8295c4300cf1836c309baea39810f668ee96a6f35b5ad6df34e7fbd6bdd3a95cc3d0a5fd82e5b0e185643b7d161838e5b1f2bdfd57547b9070c7947896ab74019c7015af1b3c74103af66dbdf8b47d31f9994f3a868ded7238fa53a0b1fab1b29f8c7e1fcad09f1f9139e87f0cdba8e9c7e32cf42011a64d5f6cafda0bae683c17d5874f8566739cdb494b6165aceb74d1aa1028a604d4bb30399f5bca6281d7f6f6fce01bf4553bf2824f9ccde763aaac5c78cd9baf0461dca2a61c93e7eb06011ecaa6816cbb7cd10c3aca79bce6fc3f38d81d62bf24016763995473ed5c7043e94cb457e432715bdf4a69861e5759a4d610dfc6064987e06e80f0acecef1d843e14169e078bed777fda666119e3179230189b209a29cb849d73cc5413f59b17c3b25aec65b0a510f3e2d1cee9993f40c3efa60fe9c18a074bf5acd64ad53db5066b83f6c4eaa142017df174a94735fc2b12a7cc7447b6c0d162e9a44998607abc3a5378369c33ced1c655948aa61aef92bf6c25cd5d66455a7b9b74dbc96a1f707652c3be96859053815021419d36bcb9a9daefe96d01270ddf76e8f31b3bfd5b2298445df03b89486afa7cf8e7b3879e90e0241ed575a042aee578b228d06c013953075af8ebcd3483288f38ef375de1d2651c3dfd8d2ce8766965641e8e6458d874d48bfc72e074242b8ad15b718d261587b19656865c5e5481d902ba66e17c4e1f942e222d3b629260c099372517ead4f7c0425c4290c

# test 4
./evmone/build/bin/evmone-bench ../miller_loop.hex bbc622db0af03afbef1a7af93fe8556c58ac1b173f3a4ea105b974974f8c68c30faca94f8c63952694d79731a7d3f117e1e7c5462923aa0ce48a88a244c73cd0edb3042ccb18db00f60ad0d595e0f5fce48a1d74ed309ea0f1a0aae381f4b308b8bd21c1c85680d4efbb05a82603ac0b77d1e37a640b51b4023b40fad47ae4c65110c52d27050826910a8ff0b2a24a027e2b045d057dace5575d941312f14c3349507fdcbb61dab51ab62099d0d06b59654f2788a0d3ac7d609f7152602be0130128b808865493e189a2ac3bccc93a922cd16051699a426da7d3bd8caa9bfdad1a352edac6cdc98c116e7d7227d5e50cbe795ff05f07a9aaa11dec5c270d373fab992e57ab927426af63a7857e283ecb998bc22bb0d2ac32cc34a72ea0c40606 655d5c4e12ed5d6c2720db7eb6d4227b35d0d95174abc53d80ec1e4d9424d4bb2860cb5c7a6f3b95b3e14aaca2388103a9be8f355d67a0651bb5fe8e312f7d9a17ac6815b9a0ecc737c48ce5129785481afbcaa715c6770a0c818f9d82957501afa274688d0438afe36d4631113c266ecc548264d03afb7fe4aa80301fb03649732e1eeabbc93074a0fe0ab434d1c402e6acc739b503a59b333be9a5cb9c968a121267d858e1fb8f6b5e24df3594686a51e853103957fac192692c55f09bc113304ad4734cad3d4a33d75713a80b140fe7b2aa6c00417d233c2d1736d4202f7a06dba5434934039015f9fb9b4e372a0240450f8260f4b6e8e54ccddf16f7dbfca736f1a2758b0a8428b0af949183164591f7cdea93d3c87fc0317b4610a01b101aa880943a3cd1c6a4f79d26aa3c967f86c1d8765d85a2635f2759deacd8933983722fa79900c25294909522d875aa19df7c4c5296c2c1d1af7723ba9a51468161d7c6ff1ad56b1dcf8cb82a99e34015b114458f2e6ff6e19530eced6bc0d005326b58dd8ed44a5ee1a7bb703e938f09705fa610dd5fd983dab132c98f318077ab242f9339e03e1f4233413073f8fb19a86ddc94c707ed60c771ba7f380f8a5ca24681f688b337b375decd907926494991e4e70f32022e4d87e8ed537622dd1628a9186e406ba7481d3e2de860144299b278a68ffe04b90a221bdeb0db0e3cbe85cb9f982a5638b6999d5cef77d501171b3945edd8f983dfaf9be3fc3a1c8cd02a98521a3e83a453b7a831b5d3dbb5909d999f29109975fb9cc1da9daf83bf19
./evmone/build/bin/evmone-bench ../final_exponentiation.hex 655d5c4e12ed5d6c2720db7eb6d4227b35d0d95174abc53d80ec1e4d9424d4bb2860cb5c7a6f3b95b3e14aaca2388103a9be8f355d67a0651bb5fe8e312f7d9a17ac6815b9a0ecc737c48ce5129785481afbcaa715c6770a0c818f9d82957501afa274688d0438afe36d4631113c266ecc548264d03afb7fe4aa80301fb03649732e1eeabbc93074a0fe0ab434d1c402e6acc739b503a59b333be9a5cb9c968a121267d858e1fb8f6b5e24df3594686a51e853103957fac192692c55f09bc113304ad4734cad3d4a33d75713a80b140fe7b2aa6c00417d233c2d1736d4202f7a06dba5434934039015f9fb9b4e372a0240450f8260f4b6e8e54ccddf16f7dbfca736f1a2758b0a8428b0af949183164591f7cdea93d3c87fc0317b4610a01b101aa880943a3cd1c6a4f79d26aa3c967f86c1d8765d85a2635f2759deacd8933983722fa79900c25294909522d875aa19df7c4c5296c2c1d1af7723ba9a51468161d7c6ff1ad56b1dcf8cb82a99e34015b114458f2e6ff6e19530eced6bc0d005326b58dd8ed44a5ee1a7bb703e938f09705fa610dd5fd983dab132c98f318077ab242f9339e03e1f4233413073f8fb19a86ddc94c707ed60c771ba7f380f8a5ca24681f688b337b375decd907926494991e4e70f32022e4d87e8ed537622dd1628a9186e406ba7481d3e2de860144299b278a68ffe04b90a221bdeb0db0e3cbe85cb9f982a5638b6999d5cef77d501171b3945edd8f983dfaf9be3fc3a1c8cd02a98521a3e83a453b7a831b5d3dbb5909d999f29109975fb9cc1da9daf83bf19 2da9b2b120246b2c7a99a1fbf1348c033d24f6f83f339ab84ad283314cd82f0af7c3dd92dbfeb2183c45f6efb2e9320955169c107be4a0bd866f801e3ba2948274721bb2901e90b5feb5f83bb01984a2cf895e87d225e76253cf9e00a815080fbfc310f7b29a172b5476c0ada805c5f5c56c394f14ece1770c65f2b2e5abdb4921bb37c0385938ed41be7959b6387205bedd7514d6697aab923e11d594f15efa4628133865f8e2ebd6e444abecc0f1b2a6d980c979b6a62f6bad6873526c9b0a35a7b056dff828dee05ef58921d774f7664df637ee06923f50d885acdbd72ce4b6a1f4e818dc3ddf8d1a642f980f9c065fb8d91ccea05aced8316342025d611ff6520a3b4187a41e3001a37389a79f16cd9e216afba9b8a10226790d4a4a2c0396c41c90583a475320b606d7324be5a739b34d85895b8a2d234f1d967f13905e342fda1089a98ff00c7c4f1d25492312ed349dad807ae0fef4c38eb55d479772b4d99e31ced35859e2d41ea8123b23c86d2405459af8d4df05327a586894241132851f8548be2de7abfa7af8e68d1b17190a4f4b44a23421865b4491270f6537b1a168959990d3fb3863a020d64bd0176895430b7bcd19692489875c065bf530425f05f42255a06dd661778660756f834b2b1e82817958de22f217c8b122f101d8bf9ed77c36f2b7e00ede5cdb7ba5260129a4e89dc790c607d555dd4d3ee24d103195ba53fd5cd6041c987c1b286d04dd22b89437a3edf66d518eca6405ef52565815da7e35fb8c51e0e086912ea175eaf10a768355612aaaee913a5179240f
```

Change any part of the input or output to see that there is an error.



## Compare to a BLS Implementation

We compare our inputs and outputs against third-party implementations.

For BLS12-381 operations, we use Supranational's blst.

```
git clone https://github.com/supranational/blst
cd blst
git checkout v0.3.2	# maybe a newer version will work too
bash build.sh
cd ..
cc blst_tests.c blst/libblst.a -static -o blst_tests
./blst_tests
```

The final command will print four tests, including all inputs and outputs, as little-endian hex strings. You can manually compare them to the inputs and outputs used above. We actually generated the above inputs/outputs using this blst code.

