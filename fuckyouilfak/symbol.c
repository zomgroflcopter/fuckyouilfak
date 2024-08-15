/*
 ___________             __     _____.___.
 \_   _____/_ __   ____ |  | __ \__  |   | ____  __ __
  |    __)|  |  \_/ ___\|  |/ /  /   |   |/  _ \|  |  \
  |     \ |  |  /\  \___|    <   \____   (  <_> )  |  /
  \___  / |____/  \___  >__|_ \  / ______|\____/|____/
      \/              \/     \/  \/
 .___.__   _____        __     ._.
 |   |  |_/ ____\____  |  | __ | |
 |   |  |\   __\\__  \ |  |/ / | |
 |   |  |_|  |   / __ \|    <   \|
 |___|____/__|  (____  /__|_ \  __
                     \/     \/  \/
 Fuck You Ilfak!
 IDA Pro 9.0 Beta 2 macOS x64 Fix Loader
 (c) fG! 2024 - reverser@put.as - https://reverse.put.as
 
 macho.c
 
 */

#include "symbol.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/stab.h>
#include <mach-o/dyld_images.h>

#include "log.h"

// all following dyld structures taken from cache-builder/dyld_cache_format.h @ dyld-1162 (macOS 14.5 source code)
// might be incompatible with older versions so check and update it if having problems running this on older macOS
struct dyld_cache_header
{
    char        magic[16];              // e.g. "dyld_v0    i386"
    uint32_t    mappingOffset;          // file offset to first dyld_cache_mapping_info
    uint32_t    mappingCount;           // number of dyld_cache_mapping_info entries
    uint32_t    imagesOffsetOld;        // UNUSED: moved to imagesOffset to prevent older dsc_extarctors from crashing
    uint32_t    imagesCountOld;         // UNUSED: moved to imagesCount to prevent older dsc_extarctors from crashing
    uint64_t    dyldBaseAddress;        // base address of dyld when cache was built
    uint64_t    codeSignatureOffset;    // file offset of code signature blob
    uint64_t    codeSignatureSize;      // size of code signature blob (zero means to end of file)
    uint64_t    slideInfoOffsetUnused;  // unused.  Used to be file offset of kernel slid info
    uint64_t    slideInfoSizeUnused;    // unused.  Used to be size of kernel slid info
    uint64_t    localSymbolsOffset;     // file offset of where local symbols are stored
    uint64_t    localSymbolsSize;       // size of local symbols information
    uint8_t     uuid[16];               // unique value for each shared cache file
    uint64_t    cacheType;              // 0 for development, 1 for production, 2 for multi-cache
    uint32_t    branchPoolsOffset;      // file offset to table of uint64_t pool addresses
    uint32_t    branchPoolsCount;       // number of uint64_t entries
    uint64_t    dyldInCacheMH;          // (unslid) address of mach_header of dyld in cache
    uint64_t    dyldInCacheEntry;       // (unslid) address of entry point (_dyld_start) of dyld in cache
    uint64_t    imagesTextOffset;       // file offset to first dyld_cache_image_text_info
    uint64_t    imagesTextCount;        // number of dyld_cache_image_text_info entries
    uint64_t    patchInfoAddr;          // (unslid) address of dyld_cache_patch_info
    uint64_t    patchInfoSize;          // Size of all of the patch information pointed to via the dyld_cache_patch_info
    uint64_t    otherImageGroupAddrUnused;    // unused
    uint64_t    otherImageGroupSizeUnused;    // unused
    uint64_t    progClosuresAddr;       // (unslid) address of list of program launch closures
    uint64_t    progClosuresSize;       // size of list of program launch closures
    uint64_t    progClosuresTrieAddr;   // (unslid) address of trie of indexes into program launch closures
    uint64_t    progClosuresTrieSize;   // size of trie of indexes into program launch closures
    uint32_t    platform;               // platform number (macOS=1, etc)
    uint32_t    formatVersion          : 8,  // dyld3::closure::kFormatVersion
                dylibsExpectedOnDisk   : 1,  // dyld should expect the dylib exists on disk and to compare inode/mtime to see if cache is valid
                simulator              : 1,  // for simulator of specified platform
                locallyBuiltCache      : 1,  // 0 for B&I built cache, 1 for locally built cache
                builtFromChainedFixups : 1,  // some dylib in cache was built using chained fixups, so patch tables must be used for overrides
                padding                : 20; // TBD
    uint64_t    sharedRegionStart;      // base load address of cache if not slid
    uint64_t    sharedRegionSize;       // overall size required to map the cache and all subCaches, if any
    uint64_t    maxSlide;               // runtime slide of cache can be between zero and this value
    uint64_t    dylibsImageArrayAddr;   // (unslid) address of ImageArray for dylibs in this cache
    uint64_t    dylibsImageArraySize;   // size of ImageArray for dylibs in this cache
    uint64_t    dylibsTrieAddr;         // (unslid) address of trie of indexes of all cached dylibs
    uint64_t    dylibsTrieSize;         // size of trie of cached dylib paths
    uint64_t    otherImageArrayAddr;    // (unslid) address of ImageArray for dylibs and bundles with dlopen closures
    uint64_t    otherImageArraySize;    // size of ImageArray for dylibs and bundles with dlopen closures
    uint64_t    otherTrieAddr;          // (unslid) address of trie of indexes of all dylibs and bundles with dlopen closures
    uint64_t    otherTrieSize;          // size of trie of dylibs and bundles with dlopen closures
    uint32_t    mappingWithSlideOffset; // file offset to first dyld_cache_mapping_and_slide_info
    uint32_t    mappingWithSlideCount;  // number of dyld_cache_mapping_and_slide_info entries
    uint64_t    dylibsPBLStateArrayAddrUnused;    // unused
    uint64_t    dylibsPBLSetAddr;           // (unslid) address of PrebuiltLoaderSet of all cached dylibs
    uint64_t    programsPBLSetPoolAddr;     // (unslid) address of pool of PrebuiltLoaderSet for each program
    uint64_t    programsPBLSetPoolSize;     // size of pool of PrebuiltLoaderSet for each program
    uint64_t    programTrieAddr;            // (unslid) address of trie mapping program path to PrebuiltLoaderSet
    uint32_t    programTrieSize;
    uint32_t    osVersion;                  // OS Version of dylibs in this cache for the main platform
    uint32_t    altPlatform;                // e.g. iOSMac on macOS
    uint32_t    altOsVersion;               // e.g. 14.0 for iOSMac
    uint64_t    swiftOptsOffset;        // VM offset from cache_header* to Swift optimizations header
    uint64_t    swiftOptsSize;          // size of Swift optimizations header
    uint32_t    subCacheArrayOffset;    // file offset to first dyld_subcache_entry
    uint32_t    subCacheArrayCount;     // number of subCache entries
    uint8_t     symbolFileUUID[16];     // unique value for the shared cache file containing unmapped local symbols
    uint64_t    rosettaReadOnlyAddr;    // (unslid) address of the start of where Rosetta can add read-only/executable data
    uint64_t    rosettaReadOnlySize;    // maximum size of the Rosetta read-only/executable region
    uint64_t    rosettaReadWriteAddr;   // (unslid) address of the start of where Rosetta can add read-write data
    uint64_t    rosettaReadWriteSize;   // maximum size of the Rosetta read-write region
    uint32_t    imagesOffset;           // file offset to first dyld_cache_image_info
    uint32_t    imagesCount;            // number of dyld_cache_image_info entries
    uint32_t    cacheSubType;           // 0 for development, 1 for production, when cacheType is multi-cache(2)
    uint64_t    objcOptsOffset;         // VM offset from cache_header* to ObjC optimizations header
    uint64_t    objcOptsSize;           // size of ObjC optimizations header
    uint64_t    cacheAtlasOffset;       // VM offset from cache_header* to embedded cache atlas for process introspection
    uint64_t    cacheAtlasSize;         // size of embedded cache atlas
    uint64_t    dynamicDataOffset;      // VM offset from cache_header* to the location of dyld_cache_dynamic_data_header
    uint64_t    dynamicDataMaxSize;     // maximum size of space reserved from dynamic data
};

struct dyld_cache_mapping_info {
    uint64_t    address;
    uint64_t    size;
    uint64_t    fileOffset;
    uint32_t    maxProt;
    uint32_t    initProt;
};

struct dyld_cache_image_info
{
    uint64_t    address;
    uint64_t    modTime;
    uint64_t    inode;
    uint32_t    pathFileOffset;
    uint32_t    pad;
};

struct dyld_subcache_entry
{
    uint8_t     uuid[16];           // The UUID of the subCache file
    uint64_t    cacheVMOffset;      // The offset of this subcache from the main cache base address
    char        fileSuffix[32];     // The file name suffix of the subCache file e.g. ".25.data", ".03.development"
};

// go over dyld_cache to find the symbol we are interested in
mach_vm_address_t find_dyldcache_symbol(char *symbol_name)
{
    if (symbol_name == NULL) {
        ERROR_MSG("NULL pointers in arguments.");
        return 0;
    }
    
    kern_return_t kret;
    
    // retrieve the dyld all_images_info using the syscall instead of reading from the process
    // this is because of changes between on disk dyld and cache dyld
    // Note: we are retrieving this information from the debugger process and not the target
    //       but they are compatible since the cache isn't (usually!) moving around for each process
    task_dyld_info_data_t info;
    mach_msg_type_number_t size = TASK_DYLD_INFO_COUNT;
    kret = task_info(mach_task_self(), TASK_DYLD_INFO, (void*)&info, &size);
    if (kret != KERN_SUCCESS) {
        ERROR_MSG("task_info failed with error %s", mach_error_string(kret));
        return 0;
    }
    struct dyld_all_image_infos *all_image_infos = (struct dyld_all_image_infos*)(uintptr_t)info.all_image_info_addr;
    DEBUG_MSG("Shared dyld cache base address: 0x%llx", (uint64_t)(uintptr_t)all_image_infos->sharedCacheBaseAddress);
    // check if this is a dyld cache or not
    char *buf = (char*)(uintptr_t)all_image_infos->sharedCacheBaseAddress;
    if (memcmp(buf, "dyld_v1 x86_64h", 16)) {
        ERROR_MSG("Buffer is not a dyld shared cache");
        return 0;
    }
    
    struct dyld_cache_header *ch = (struct dyld_cache_header*)buf;
    DEBUG_MSG("dyld mapping count: %d", ch->mappingCount);
    DEBUG_MSG("dyld mapping count with slide: %d", ch->mappingWithSlideCount);
    DEBUG_MSG("dyld images count: %d", ch->imagesCount);
    DEBUG_MSG("Subcaches: 0x%x %d", ch->subCacheArrayOffset, ch->subCacheArrayCount);
    
    // we need to find the dyld cache LINKEDIT which is where all the symbol information was put together
    // dirty hack here because we just find the READ ONLY segment, which seems to correspond for now to LINKEDIT
    // this definitely needs improvement here
    struct dyld_cache_mapping_info *dcmi = (struct dyld_cache_mapping_info*)(buf + ch->mappingOffset);
    struct dyld_cache_mapping_info *dcmi_linkedit = NULL;
    for (uint32_t i = 0; i < ch->mappingCount; i++) {
        DEBUG_MSG("dyld_cache_mapping_info: 0x%llx -> 0x%llx -> 0x%llx", dcmi->address, dcmi->fileOffset, dcmi->size);
        if (dcmi->initProt == VM_PROT_READ && dcmi->maxProt == VM_PROT_READ) {
            dcmi_linkedit = dcmi;
            break;
        }
        dcmi++;
    }
    
    // usually there are sub cache entries because of mapping and virtual memory optimizations (check dyld documentation!)
    // and in theory we should also iterate over any sub cache entries because it might contain the symbol we want
    // in this case we cheat because we know it's on the first cache
    struct dyld_subcache_entry *dse = (struct dyld_subcache_entry*)(buf + ch->subCacheArrayOffset);
    for (int i = 0; i < ch->subCacheArrayCount; i++) {
        DEBUG_MSG("Dyld sub cache entry #%d: 0x%llx -> %s", i, dse->cacheVMOffset, buf+dse->cacheVMOffset);
        dse++;
    }
    
    // going over all the cache images searching for the one we are interested in
    // we need this so we can find the offset of the symbol we want
    // altough the symbol value and string is located inside the dyld cache LINKEDIT and not here
    struct dyld_cache_image_info *dcii = (struct dyld_cache_image_info *)(buf + ch->imagesOffset);
    unsigned char *analysis_buf = NULL;
    for (uint32_t i = 0; i < ch->imagesCount; i++) {
        char *pathString = buf + dcii->pathFileOffset;
        if (strcmp("/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation", pathString) == 0) {
            DEBUG_MSG("Path offset 0x%x @ 0x%llx -> %s", dcii->pathFileOffset, dcii->address, pathString);
            // the address we get from the header needs the cache ASLR slide
            unsigned char *b0f = (unsigned char*)dcii->address + all_image_infos->sharedCacheSlide;
            analysis_buf = b0f;
            // just debug to make sure we are pointing to at least a Mach-O binary
            for (int x = 0; x < 16; x++) {
                printf("%02x ", b0f[x]);
            }
            printf("\n");
            break;
        }
        dcii++;
    }
    
    // now we parse the Foundation Mach-O header to locate its symbol table
    OUTPUT_MSG("[+] Extracting mach-o header information...");
    struct mach_header_64 *mh = (struct mach_header_64*)analysis_buf;
    uint32_t header_size = sizeof(struct mach_header_64);
    uint32_t symboltable_fileoff = 0; /* LC_SYMTAB */
    uint32_t symboltable_nrsyms = 0;
    uint32_t stringtable_fileoff = 0;
    uint32_t stringtable_size = 0;
    struct load_command *lc = (struct load_command*)(analysis_buf + header_size);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        switch (lc->cmd) {
            case LC_SYMTAB:
            {
                struct symtab_command *symtab_cmd = (struct symtab_command*)lc;
                symboltable_fileoff = symtab_cmd->symoff;
                symboltable_nrsyms = symtab_cmd->nsyms;
                stringtable_fileoff = symtab_cmd->stroff;
                stringtable_size = symtab_cmd->strsize;
                DEBUG_MSG("Found LC_SYMTAB: 0x%x %d 0x%x 0x%x", symboltable_fileoff, symboltable_nrsyms, stringtable_fileoff, stringtable_size);
                break;
            }
            default:
                break;
        }
        lc = (struct load_command*)((unsigned char*)lc + lc->cmdsize);
    }
    // compute the offsets inside dyld cache LINKEDIT otherwise we will be pointing to wrong places
    symboltable_fileoff = symboltable_fileoff - (uint32_t)dcmi_linkedit->fileOffset;
    stringtable_fileoff = stringtable_fileoff - (uint32_t)dcmi_linkedit->fileOffset;
    
    // now we can finally go into dyld cache LINKEDIT and locate the information for the symbol we want
    mach_vm_address_t symbol_address = 0;
    struct nlist_64 *nlist = NULL;
    char *linkedit_base = (char*)(dcmi_linkedit->address + all_image_infos->sharedCacheSlide);
    for (uint32_t i = 0; i < symboltable_nrsyms; i++) {
        // get the pointer to the symbol entry and extract its symbol string
        nlist = (struct nlist_64*)(linkedit_base + symboltable_fileoff + i * sizeof(struct nlist_64));
        char *symbol_string = linkedit_base + stringtable_fileoff + nlist->n_un.n_strx;
//        DEBUG_MSG("Symbol %s 0x%llx", symbol_string, nlist->n_value);
        if (strcmp(symbol_string, symbol_name) == 0) {
            DEBUG_MSG("Found %s symbol #%d @ 0x%llx", symbol_string, i, nlist->n_value + all_image_infos->sharedCacheSlide);
            symbol_address = nlist->n_value + all_image_infos->sharedCacheSlide;
            break;
        }
    }
    return symbol_address;
}
