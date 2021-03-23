Code to accompany our paper ["Arun, V., Kate, A., Garg, D., Druschel, P., & Bhattacharjee, B. (2018). Finding Safety in Numbers with Secure Allegation Escrows. arXiv preprint arXiv:1810.10123."](https://arxiv.org/abs/1810.10123)

# Usage

First install openjdk

`sudo apt install openjdk-14-jdk`

To make initial installation easy, this repository has many requisite prebuilt binaries in the `assets` directory. You may wish to build these yourself instead. Make a note of the commit hash in the git submodule, since the library has changed considerably since this code was written.

To build, `cd` to the `src` directory and run `./compile`. 

To run a quick local test of the system, you'll need to run `n` processes. Use `./printSocketParties.sh [n]` to create configuration files for `n` parties. A real deployment will also need to create authenticated channels which are supported by the `scapi` cryptography library. Now `./runTest` will run integration tests with 3 parties (set `n=3` in the previous step).

Use `src/pederson/Profile.java` to profile the performance of the code (though this implementation is not optimized for performance). `src/pederson/Client.java` runs the client

# Disclaimer

This was written purely to establish that the protocol specified in our paper can run quickly enough to be practical. It was not optimized for performance or tested for security. I am sure there are several vulnerabilities in the implementation, and *this should not be used in production without significant effort in hardening the implementation.* We have only proved the protocol correct, not tested it :)

I've misspelt Pedersen in the code, but it is too late to change now :)
