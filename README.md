# Hardware attacks / State of the art

<p align="center">
  <img src="main.jpg">
</p>

### Microarchitectural exploitation and other hardware attacks.

#### Contributing:
Contributions, comments and corrections are welcome, please do PR.

#### Flaws:
* [TPM-FAIL / TPM meets Timing and Lattice Attacks](https://tpm.fail/)
    * __[CVE-2019-11090]__ For Intel fTPM
    * __[CVE-2019-16863]__ For STMicroelectronics TPM

* [__[CVE-2015-0565]__ Rowhammer based](https://users.ece.cmu.edu/~yoonguk/papers/kim-isca14.pdf):
    * [__[CVE-2016-6728]__ DRAMMER](https://vvdveen.com/publications/drammer.pdf)
    * [__[CVE-2018-9442]__ RAMPage](https://rampageattack.com/)
    * [__[CVE-2019-0174]__ RAMBleed](https://rambleed.com/)
    * [__[CVE-2019-0162]__ SPOILER / Speculative Load Hazards Boost Rowhammer and Cache Attacks](https://arxiv.org/abs/1903.00446)
    * [DRAMA/DRAM Addressing](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/pessl)
    * [Flip Feng Shui (FFS)](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/razavi)
    * [SGX-Bomb](https://www.microsoft.com/en-us/research/publication/sgx-bomb-locking-down-the-processor-via-rowhammer-attack/)
    * [Nethammer](https://arxiv.org/abs/1805.04956)
    * [JackHammer](https://arxiv.org/abs/1912.11523)
     
* __Spectre__:
    * [__[CVE-2017-5753]__ Spectre-V1 / Spectre v1 / Spectre-PHT / Bounds Check Bypass (BCB)](https://meltdownattack.com/)
        * [SGXPectre](https://arxiv.org/abs/1802.09085)
        * [NetSpectre](https://arxiv.org/abs/1807.10535)
        
    * [__[CVE-2018-3693]__ Spectre 1.2 / Meltdown-RW / Read-only protection bypass (RPB)](https://arxiv.org/abs/1807.03757) 	
    * [__[CVE-2017-5715]__ Spectre-V2 / Spectre v2 / Spectre-BTB / Branch Target Injection (BTI)](https://arxiv.org/abs/1807.03757)
    * [__[CVE-2018-9056]__ BranchScope](https://www.researchgate.net/publication/323951622_BranchScope_A_New_Side-Channel_Attack_on_Directional_Branch_Predictor)
    * __SpectreNG class__:
        * [__[CVE-2018-3640]__ Spectre v3a / Meltdown-GP / Rogue System Register Read (RSRR)]()
        * [__[CVE-2018-3639]__ Spectre v4 / Spectre-STL / Speculative Store Bypass (SSB)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1528)
        * [__[CVE-2018-3665]__ LazyFP / Meltdown-NM / Spectre-NG 3 / Lazy FP State Save-Restore](https://arxiv.org/abs/1806.07480)
        * [__[CVE-2018-3693]__ Spectre 1.1 / Spectre-PHT / Bounds Check Bypass Store (BCBS)]()
        * [__[CVE-2019-1125]__ Spectre SWAPGS]()
        
    * [__Foreshadow class__](https://foreshadowattack.eu/):
        * __[CVE-2018-3615]__ Foreshadow / Spectre v5 / L1TF / Meltdown-P / L1 Terminal Fault in SGX
        * __[CVE-2018-3620]__ Foreshadow-NG / Foreshadow-OS
        * __[CVE-2018-3646]__ Foreshadow-NG / Foreshadow-VMM
        
    * __Spectre RSB (Return Mispredict / Return Stack Buffer (RSB)) based__:
        * [__[CVE-2018-15572]__ SpectreRSB](https://arxiv.org/abs/1807.07940)
        * [ret2spec](https://arxiv.org/pdf/1807.10364.pdf)
        
    * __Meltdown (Rogue Data Cache Load (RDCL))__:
        * [__[CVE-2017-5754]__ Meltdown v3 / Spectre v3 / Spectre-V3 / Meltdown-US](https://arxiv.org/abs/1811.05441):
            * Meltdown-BR / Bounds Check Bypass
            * Meltdown-NM / FPU Register Bypass
            * Meltdown-P / Virtual Translation Bypass
            * Meltdown-PK / Protection Key Bypass
            
    * [__Microarchitectural Data Sampling (MDS)__](https://mdsattacks.com/):
        * __[CVE-2018-12126]__ Fallout / Microarchitectural Store Buffer Data Sampling (MSBDS)
        * Rogue In-Flight Data Load (RIDL):
            * [__[CVE-2018-12130]__ ZombieLoad / Microarchitectural Fill Buffer Data Sampling (MFBDS)](https://zombieloadattack.com/)
            * __[CVE-2018-12127]__ Microarchitectural Load Port Data Sampling (MLPDS)
            * __[CVE-2019-11091]__ Microarchitectural Data Sampling Uncacheable Memory (MDSUM)
            * [__[CVE-2019-11135]__ ZombieLoad v2 / TSX Asynchronous Abort (TAA)](https://zombieloadattack.com/)
            * __[CVE-2020-0548]__ Vector Register Sampling (VRS)
            * [__[CVE-2020-0549]__ CacheOut / L1D Eviction Sampling (L1DES)](https://cacheoutattack.com/)
    * [__[CVE-2020-0551]__ Hijacking Transient Execution with Load Value Injection (LVI)](https://lviattack.eu)
    * [__[CVE-2020-0543]__ Crosstalk / Special Register Buffer Data Sampling (SRBDS)](https://download.vusec.net/papers/crosstalk_sp21.pdf)

            
* [__[CVE-2018-5407]__ PortSmash]()
* [ARMageddon](https://arxiv.org/abs/1511.04897v1)
* [Nemesis](https://distrinet.cs.kuleuven.be/software/sancus/publications/ccs18.pdf)

#### Proof of concepts:
* TPM-Fail: https://github.com/VernamLab/TPM-Fail
* Rowhammer (Google): https://github.com/google/rowhammer-test
* Rowhammer (IAIK): https://github.com/IAIK/rowhammerjs
* DRAMMER: https://github.com/vusec/drammer
* SGX-Bomb: https://github.com/sslab-gatech/sgx-bomb
* SWAPGS: https://github.com/bitdefender/swapgs-attack-poc

#### Resources:
* [Linux Kernel Defence Map](https://github.com/a13xp0p0v/linux-kernel-defence-map)
* [Linux Kernel Hardware Vulnerabilities](https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html)
* [Transient Execution Attacks](https://transient.fail)
* [Interactive guide to speculative execution attacks:](https://mdsattacks.com/diagram.html)
![](https://mdsattacks.com/images/skylake.svg)

#### Tools:
* [sandsifter](https://github.com/xoreaxeaxeax/sandsifter): The x86 processor fuzzer
* [OpcodeTester](https://github.com/cattius/opcodetester): Analyse Undocumented Instructions on Intel x86/x86-64 and RISC-V
* [evsets](https://github.com/cgvwzq/evsets): Tool for testing and finding minimal eviction sets
* [cachequery](https://github.com/cgvwzq/cachequery): A tool for interacting with hardware memory caches in modern Intel CPUs.

#### Blog posts:
* [CPU Introspection: Intel Load Port Snooping](https://gamozolabs.github.io/metrology/2019/12/30/load-port-monitor.html)
* [Sushi Roll: A CPU research kernel with minimal noise for cycle-by-cycle micro-architectural introspection](https://gamozolabs.github.io/metrology/2019/08/19/sushi_roll.html)

#### Others:
> $ cat /sys/devices/system/cpu/vulnerabilities/*