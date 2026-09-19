
# Achievement

We were able to solve all versions (32/48/64). Our implementation have two implementations:
- sequential execution that works relatively fast for 32 and 48 versions
- a parallelized version with OpenMP that works for all 3 bit versions (64 bit attack will take anywhere from 1 to 4 hours)

> Disclaimer: The 64 bit attack with OpenMP is very resource heavy, it will require about 28 GB of RAM as we had to do some memory trade-offs for performance.

> Note: In the codebase there is a version that tries to implement the attack with GPU support using AMD HIP (compatible with both AMD ROCm and Nvidia CUDA). Unfortunately we were not able to test it as for the last week of the project we lost access to Gricad Bigfoot computing cluster which we were supposed to use (due to maintenance and security updates). Our AMD GPU on our machine couldn't handle the high VRAM usage and the programs segfaulted (in Bigfoot we had V100 Nvidia cards with 40GB VRAM which should in theory be capable of running the attack). Please ignore this version as it is not confirmed to work.


# Technical Details 

## Project structure

```bash
├── attack.c # Attack functions
├── attack.h # Attack headers 
├── ckpt_collision.bin # Collision binary blob checkpoint
├── ckpt_collision.bin.old # another collision binary blob checkpoint
├── ckpt_linkmsg.bin # Link message binary blob checkpoint
├── ckpt_linkmsg.bin.old # another link message binary blob checkpoint
├── construct_attack_message2.py # a constructor of a valid 2nd pre-image message
├── construct_attack_message.py # another constructor for another valid 2nd pre-image message
├── full_attack.out # example outputs of the attack program with the two versions
├── gpu_linkmsg.hip # HIP implementations of functions for the GPU supported version
├── hash.c # Hash functions
├── hash.h # Hash headers
├── Makefile # Original Makefile
├── Makefile.custom # Custom makefile that supports compiling all versions
├── README.md 
├── test_attack.c # The attack program
├── test_hash.c # hash program PoC
├── test_speck.c # original test_speck program
├── utils.c # original utils
├── utils.h # original utils headers
└── verify_attack.c # a program that verifies 2nd pre-iamge attack on H(0^32)
```

## Compiling the project

> Note: Since we were late to find out how to submit the project, we had to redefine some macros so clang will complain with warnings about thatbut that's not an issue.

> Note: The OpenMP version requires an extension to clang, on debian the package is libomp-dev.

> Note: The GPU version is not worth trying since it is not tested at all, but it requires hipcc and nvcc to be present. to compile it use the USE\_HIP=1 flag (it will override USE\OMP=1 flag)

the sequential version can be compiled as specified in the original specification:

```bash
make test_atatck BLOCKSIZE=48
```

the custom make file can be used as so:

```bash
# clean the project
make -f Makefile.custom clean

# compile a sequential version (all programs at once), example:
make -f Makefile.custom BLOCKSIZE=32

# compile OpenMP version (all programs at once), example:
make -f Makefile.custom BLOCKSIZE=48 USE_OMP=1

# compile the 64 bit version with OpenMP
make -f Makefile.custom BLOCKSIZE=64 USE_OMP=1
```

## Attack Description

The attack differs between versions based on the blocksize

### Attack for 32 and 48 bit versions

The attack for these versions will test each step of the attack incrementally (as described by the PDF example). 
A random message will be generated for each step, and then it will be atatcked.

### Attack for 64 bit version

The 64 bit version will attempt to attack the message of 32 bits of zeros. The attack takes a long time, so we implemented a checkpoint system that the attack program can recover from.

When the program is launched it will first enter the collision step, it will check in the current directory for the file `ckpt_collision.bin`, if it is found then it will pull the data from it and use it as a result. Otherwise it will attempt to search for a collision.

When the program enters the `linkmsg` step, it will attempt to read data from checkpoint file `ckpt_linkmsg.bin` and recover data from it. Much like the collision step, if it didn't find it then it will attempt to find the link message. 

These two steps take the most resources and time, so if you wish to skip them you can use the files provided (the .old files correspond to the same attack message, while the ones ending in .bin alone correspond to another attack message).

In case you want to run the attack fully, then rename the files ending in .bin to something else or remove them entirely.

The attack program will output a python script that will print to stdin the attack message (since it is huge, around 4GB, this is a more efficient way to generate it on demand).

The scripts `construct_attack_message.py` and `construct_attack_message2.py` are two outputs from our program that generate two valid messages.

To confirm the validity of a message:

```bash
# using pipes (needs verify_attack to be compiled)
python3 construct_attack_message2.py | ./verify_attack

# or use a file if you wish to have the actual message saved
python3 construct_attack_message2.py > m2.bin
./verify_attack m2.bin
```



# AI

For the sequential part (The main part of the TP) we didn't use AI, we only used it once to understand the signature of the functions as the parameter names were ambigeous for us (for example we asked it what is the meaning of hf in linkmsg).

For the OpenMP version we initially ddin't use it, but when we starting to run into a lot of concurrency issues especially with memorry accesses, then we asked it to help us build it (but the base is still the sequential version)

For the HIP (GPU supported) version we asked it to build it from the ground up as we didn't know how to write HIP code. We just wanted to see the performance difference between a pure CPU and GPU version but unfortunately the GPU cluster went down when we wanted to test it.


## AI disclaimer

For the HIP version we gave the AI (in our case we used Claude Sonnet 4.6) the code of the attack and told it:
We wish to implement a version of the code that uses HIP so it supports Nvidia and AMD GPUs

For OpenMP development process, whenever we ran into something that looks like a deadlock or a performance bottleneck, we would spread print debug statements to know where exactly the problem is, and then we give it the code and the current output of the program at the deadlock. We would also give it suggestions when we suspect the problem ourselves but we wanted to confirm. Example:

```text
<output of the program>
<current code>

It seems stuck at building the LUT of the linkmsg. For 48 bit version it works fine and fast but with 64 bit version it takes forever. I noticed that the hash size is currently 3 bytes or 24 bits, but I suspect that it should be 32 bits (4 bytes) for the 64 bit version to cover its birthday bound. Is my assumption correct and what are the suggested fixes?
```

Although we sometimes had ideas we couldn't afford to make a change and test immediately, as each execution was taking hours so AI have us a better assumption to base our tests on.

