# Silhouette 

By [Gabriel Landau](https://twitter.com/GabrielLandau) and [Mark Mager](https://twitter.com/magerbomb) at [Elastic Security](https://www.elastic.co/security-labs/).

From _Hide Your Valuables — Mitigating Physical Credential Dumping Attacks_ presented at [Shmoocon 2023](https://shmoocon.org/).

### Keeping LSA secrets out of physical memory

Silhouette is a POC that mitigates the use of physical memory to dump credentials from LSASS.  It does this in three ways:

  1. Aggressively flush LSASS's pages from RAM to disk
  2. Block raw disk access within the boot volume, preventing raw copy attacks against `pagefile.sys` and `hiberfil.sys` (e.g. [Invoke-NinjaCopy](https://www.powershellgallery.com/packages/PowerSploit/1.0.0.0/Content/Exfiltration%5CInvoke-NinjaCopy.ps1))
  3. Block `FILE_READ_DATA` for `pagefile.sys` in all Volume Shadow Copy snapshots

It is highly recommended to enable RunAsPPL before using Silhouette.

## Building and running it

**This is a proof of concept. Use it at your own risk.**

1. Compile Silhouette.sln with Visual Studio 2019.
2. Enable [Test Signing](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option).
3. Register the service:
```
sc create Silhouette type= filesys start= demand binpath= %CD%\Silhouette.sys
```
4. Add Minifilter keys:
```
reg import FilterKeys.reg
```
5. Start the service:
```
sc start Silhouette
```


# License

Silhouette is covered by the [ELv2 license](LICENSE.txt).  It uses [phnt](https://github.com/winsiderss/systeminformer/tree/25846070780183848dc8d8f335a54fa6e636e281/phnt) from SystemInformer under the [MIT license](phnt/LICENSE.txt).
