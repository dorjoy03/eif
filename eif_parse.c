#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define EIF_HEADER_SIZE 548
#define EIF_SECTION_HEADER_SIZE 12
#define MAX_SECTIONS 32

#define BIG_ENDIAN_U16(buf) (((uint16_t)buf[0] << 8) | (uint16_t)buf[1])

#define BIG_ENDIAN_U32(buf) \
    (((uint32_t)buf[0] << 24) | \
     ((uint32_t)buf[1] << 16) | \
     ((uint32_t)buf[2] << 8)  | \
     (uint32_t)buf[3])

#define BIG_ENDIAN_U64(buf) \
    (((uint64_t)buf[0] << 56) | \
     ((uint64_t)buf[1] << 48) | \
     ((uint64_t)buf[2] << 40) | \
     ((uint64_t)buf[3] << 32) | \
     ((uint64_t)buf[4] << 24) | \
     ((uint64_t)buf[5] << 16) | \
     ((uint64_t)buf[6] << 8)  | \
     (uint64_t)buf[7])

// members are ordered according to field order in .eif file
typedef struct EifHeader {
    uint8_t  magic[4]; // must be .eif in ascii i.e., [46, 101, 105, 102]
    uint16_t version;
    uint16_t flags;
    uint64_t default_memory;
    uint64_t default_cpus;
    uint16_t reserved;
    uint16_t section_cnt;
    uint64_t section_offsets[MAX_SECTIONS];
    uint64_t section_sizes[MAX_SECTIONS];
    uint32_t unused;
    uint32_t eif_crc32;
} EifHeader;

// members are ordered according to field order in .eif file
typedef struct EifSectionHeader {
    // 0 = invalid, 1 = kernel, 2 = cmdline, 3 = ramdisk, 4 = signature, 5 = metadata
    uint16_t section_type;
    uint16_t flags;
    uint64_t section_size;
} EifSectionHeader;

void parse_eif_header(uint8_t *buf, uint64_t buf_len, EifHeader *header) {
    assert(buf_len >= EIF_HEADER_SIZE);

    header->magic[0] = buf[0];
    header->magic[1] = buf[1];
    header->magic[2] = buf[2];
    header->magic[3] = buf[3];
    buf += 4;

    header->version = BIG_ENDIAN_U16(buf);
    buf += 2;

    header->flags = BIG_ENDIAN_U16(buf);
    buf += 2;

    header->default_memory = BIG_ENDIAN_U64(buf);
    buf += 8;

    header->default_cpus = BIG_ENDIAN_U64(buf);
    buf += 8;

    header->reserved = BIG_ENDIAN_U16(buf);
    buf += 2;

    header->section_cnt = BIG_ENDIAN_U16(buf);
    buf += 2;

    for (int i = 0; i < MAX_SECTIONS; ++i) {
        header->section_offsets[i] = BIG_ENDIAN_U64(buf);
        buf += 8;
    }

    for (int i = 0; i < MAX_SECTIONS; ++i) {
        header->section_sizes[i] = BIG_ENDIAN_U64(buf);
        buf += 8;
    }

    header->unused = BIG_ENDIAN_U32(buf);
    buf += 4;

    header->eif_crc32 = BIG_ENDIAN_U32(buf);
    buf += 4;
}

void parse_eif_section_header(uint8_t *buf, uint64_t buf_len,
                              EifSectionHeader *header) {
    assert(buf_len >= EIF_SECTION_HEADER_SIZE);

    header->section_type = BIG_ENDIAN_U16(buf);
    buf += 2;

    header->flags = BIG_ENDIAN_U16(buf);
    buf += 2;

    header->section_size = BIG_ENDIAN_U64(buf);
    buf += 8;
}

void print_eif_header(EifHeader *header) {
    fprintf(stdout, "------EIF Header------\n");
    fprintf(stdout, "magic           %.4s\n", (char *)header->magic);
    fprintf(stdout, "version         %d\n", header->version);
    fprintf(stdout, "flags           %d\n", header->flags);
    fprintf(stdout, "default memory  %lu\n", header->default_memory);
    fprintf(stdout, "default cpus    %lu\n", header->default_cpus);
    fprintf(stdout, "section count   %d\n", header->section_cnt);
    fprintf(stdout, "crc32           %u\n", header->eif_crc32);
    fprintf(stdout, "------EIF Header------\n\n");
}

const char *section_type_string(uint16_t type) {
    char *str;
    switch(type) {
    case 0:
        str = "invalid";
        break;
    case 1:
        str = "kernel";
        break;
    case 2:
        str = "cmdline";
        break;
    case 3:
        str = "ramdisk";
        break;
    case 4:
        str = "signature";
        break;
    case 5:
        str = "metadata";
        break;
    default:
        str = "unknown";
        break;
    }

    return str;
}

void print_eif_section_header(EifSectionHeader *header) {
    fprintf(stdout, "section type    %s\n", section_type_string(header->section_type));
    fprintf(stdout, "flags           %d\n", header->flags);
    fprintf(stdout, "section size    %lu\n\n", header->section_size);
}

void parse_eif_file(const char *eif_path) {
    EifHeader eif_header;
    uint8_t *metadata = NULL;
    uint8_t *buf = NULL;
    int fd;
    ssize_t got;

    fd = open(eif_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open file %s\n", eif_path);
        exit(1);
    }

    buf = malloc(EIF_HEADER_SIZE);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        exit(1);
    }

    got = read(fd, buf, EIF_HEADER_SIZE);
    if (got != EIF_HEADER_SIZE) {
        fprintf(stderr, "Failed to read eif header\n");
        exit(1);
    }

    parse_eif_header(buf, EIF_HEADER_SIZE, &eif_header);
    print_eif_header(&eif_header);

    assert(eif_header.section_cnt <= MAX_SECTIONS);

    fprintf(stdout, "------EIF Section Headers-----\n\n");
    for (int i = 0; i < eif_header.section_cnt; ++i) {
        EifSectionHeader eif_section_header;
        uint64_t section_offset;
        off_t offset;

        section_offset = eif_header.section_offsets[i];
        offset = lseek(fd, section_offset, SEEK_SET);
        if ((uint64_t) offset != section_offset) {
            fprintf(stderr, "Failed to offset to %lu\n", section_offset);
            exit(1);
        }

        got = read(fd, buf, EIF_SECTION_HEADER_SIZE);
        if (got != EIF_SECTION_HEADER_SIZE) {
            fprintf(stderr, "Failed to read section header\n");
            exit(1);
        }

        parse_eif_section_header(buf, EIF_SECTION_HEADER_SIZE, &eif_section_header);
        print_eif_section_header(&eif_section_header);
        if (eif_header.section_sizes[i] != eif_section_header.section_size) {
            fprintf(stderr, "Warning: section size mismatch between header and "
                    "section header: header %lu, section header %lu\n\n",
                    eif_header.section_sizes[i], eif_section_header.section_size);
        }

        // Store metadata to print at the end. If there are more than one metadata
        // section, the first successfull one will be stored.
        if (metadata == NULL && eif_section_header.section_type == 5) {
            size_t size = eif_section_header.section_size + 1;
            metadata = malloc(size);
            if (metadata == NULL) {
                fprintf(stderr, "Failed to allocate memory for metadata\n");
                exit(1);
            }

            got = read(fd, metadata, size);
            if (got != (ssize_t) size) {
                fprintf(stderr, "Failed to read metadata\n");
                exit(1);
            }

            metadata[size - 1] = '\0';
        }
    }
    fprintf(stdout, "------EIF Section Headers------\n\n");

    if (metadata) {
        fprintf(stdout, "------metadata json------\n");
        fprintf(stdout, "%s\n", metadata);
        fprintf(stdout, "------metadata json------\n");
    }

    free(metadata);
    free(buf);
    close(fd);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Expected EIF file path as argument\n");
        exit(1);
    }

    parse_eif_file(argv[1]);

    return 0;
}
