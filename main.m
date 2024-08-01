#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>

#if DEBUG==1
#define LOG printf
#else
#define LOG
#endif

CC_SHA256_CTX g_hash_ctx;

uint8_t g_macho_hash[CC_SHA256_DIGEST_LENGTH]={0};

int processSlice(int fd, void* slice)
{
    uint32_t magic = *(uint32_t*)slice;
    if(magic != MH_MAGIC_64) {
        fprintf(stderr, "not the 64bit slice: %08x, ignore\n", magic);
        return 0;
    }
    
    struct mach_header_64* header = (struct mach_header_64*)slice;
    
    uint32_t first_section_offset = 0;
    struct segment_command_64* linkedit_segment = NULL;
    
    struct load_command* lc = (struct load_command*)((uint64_t)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *)lc;
            
            LOG("segment: %s file=%llx:%llx vm=%llx:%llx\n", seg->segname, seg->fileoff, seg->filesize, seg->vmaddr, seg->vmsize);
            
            if(strcmp(seg->segname, SEG_LINKEDIT)==0)
                linkedit_segment = seg;
                            
            struct section_64* sec = (struct section_64*)((uint64_t)seg+sizeof(*seg));
            for(int j=0; j<seg->nsects; j++)
            {
                LOG("section[%d] = %s/%s offset=%x vm=%16llx:%16llx\n", j, sec[j].segname, sec[j].sectname,
                      sec[j].offset, sec[j].addr, sec[j].size);
                
                if(sec[j].offset && (first_section_offset==0 || first_section_offset>sec[j].offset)) {
                    LOG("first_section_offset %x => %x\n", first_section_offset, sec[j].offset);
                    first_section_offset = sec[j].offset;
                }
            }
        }
        
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(!first_section_offset) {
        fprintf(stderr, "valid section not found!\n");
        return -1;
    }
    
    if(!linkedit_segment) {
        fprintf(stderr, "linkedit segment not found!\n");
        return -1;
    }
    
    void* start_address = (void*)((uint64_t)header + first_section_offset);
    size_t valid_data_size = linkedit_segment->fileoff - first_section_offset;
    
    LOG("cpusubtype=%X start=%llX size=%lX\n", header->cpusubtype, (uint64_t)start_address-(uint64_t)header, valid_data_size);
    
    CC_SHA256_Update(&g_hash_ctx, start_address, (CC_LONG)valid_data_size);
    
    
#if DEBUG==1
    //test
    uint8_t slice_hash[CC_SHA256_DIGEST_LENGTH]={0};
    CC_SHA256(start_address, (CC_LONG)valid_data_size, slice_hash);
    
    NSMutableString *hashString = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hashString appendFormat:@"%02x", slice_hash[i]];
    }
    
    LOG("*** slice hash:%s\n", hashString.UTF8String);
#endif
    
    return 0;
}

int processMachO(const char* file)
{
    int fd = open(file, O_RDONLY);
    if(fd < 0) {
        fprintf(stderr, "open %s error:%d,%s\n", file, errno, strerror(errno));
        return -1;
    }
    
    struct stat st;
    if(stat(file, &st) < 0) {
        fprintf(stderr, "stat %s error:%d,%s\n", file, errno, strerror(errno));
        return -1;
    }
    
    LOG("file size = %lld\n", st.st_size);
    
    void* macho = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(macho == MAP_FAILED) {
        fprintf(stderr, "map %s error:%d,%s\n", file, errno, strerror(errno));
        close(fd);
        return -1;
    }
    
    uint32_t magic = *(uint32_t*)macho;
    LOG("macho magic=%08x\n", magic);
    if(magic==FAT_MAGIC || magic==FAT_CIGAM) {
        struct fat_header* fathdr = (struct fat_header*)macho;
        struct fat_arch* archdr = (struct fat_arch*)((uint64_t)fathdr + sizeof(*fathdr));
        int count = magic==FAT_MAGIC ? fathdr->nfat_arch : OSSwapInt32(fathdr->nfat_arch);
        for(int i=0; i<count; i++) {
            uint32_t offset = (magic==FAT_MAGIC ? archdr[i].offset : OSSwapInt32(archdr[i].offset));
            if(processSlice(fd, (void*)((uint64_t)macho + offset)) < 0) {
                munmap(macho, st.st_size);
                close(fd);
                return -1;
            }
        }
    } else if(magic==FAT_MAGIC_64 || magic==FAT_CIGAM_64) {
        struct fat_header* fathdr = (struct fat_header*)macho;
        struct fat_arch_64* archdr = (struct fat_arch_64*)((uint64_t)fathdr + sizeof(*fathdr));
        int count = magic==FAT_MAGIC_64 ? fathdr->nfat_arch : OSSwapInt32(fathdr->nfat_arch);
        for(int i=0; i<count; i++) {
            uint64_t offset = (magic==FAT_MAGIC_64 ? archdr[i].offset : OSSwapInt64(archdr[i].offset));
            if(processSlice(fd, (void*)((uint64_t)macho + offset)) < 0) {
                munmap(macho, st.st_size);
                close(fd);
                return -1;
            }
        }
    } else if(magic == MH_MAGIC_64) {
        if(processSlice(fd, (void*)macho) < 0) {
            munmap(macho, st.st_size);
            close(fd);
            return -1;
        }
    } else {
        fprintf(stderr, "unknown macho file: %08x\n", magic);
        return -1;
    }
    
    munmap(macho, st.st_size);
    close(fd);
    
    LOG("finished.\n\n");
    return 0;
}

int main(int argc, const char * argv[]) {
    
    if(argc != 2) {
        printf("Calculate macho file hash (compatible with roothide).\nUsage: %s /path/to/macho\n", getprogname());
        return 0;
    }

    const char* target = argv[1];

    LOG("calc hash for %s\n", target);
    
    CC_SHA256_Init(&g_hash_ctx);
    
    if(processMachO(target) < 0) {
        fprintf(stderr, "processTarget error!\n");
        return -1;
    }
    
    CC_SHA256_Final(g_macho_hash, &g_hash_ctx);

    NSMutableString *hashString = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hashString appendFormat:@"%02x", g_macho_hash[i]];
    }
    
    LOG("****** macho file hash:\n\n");
    
    fprintf(stdout, "%s", hashString.UTF8String);
    
    LOG("\n\n\n");
    
    return 0;
}
