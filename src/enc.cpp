#include <iostream>
#include <string_view>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <memory>
#include <filesystem>

namespace fs = std::filesystem;

struct mask {
    unsigned char bytes[16];
};

mask incr_mask(mask m)
{
    for(int index = 15; index >= 0; --index) {
        if(m.bytes[index] != 0xff) {
            ++m.bytes[index];
            break;
        }

        m.bytes[index] = 0;
    }

    return m;
}

struct encryption_state {
    mask counter{};
};

mask const prepared_masks[11]{
    {0xc3,0xd2,0xba,0xe7,0xc3,0xf3,0x62,0x9a,0x17,0x53,0x71,0xd6,0xb1,0xf5,0x05,0xaa},
    {0x24,0xb9,0x16,0x2f,0xe7,0x4a,0x74,0xb5,0xf0,0x19,0x05,0x63,0x41,0xec,0x00,0xc9},
    {0xe8,0xda,0xcb,0xac,0x0f,0x90,0xbf,0x19,0xff,0x89,0xba,0x7a,0xbe,0x65,0xba,0xb3},
    {0xa1,0x2e,0xa6,0x02,0xae,0xbe,0x19,0x1b,0x51,0x37,0xa3,0x61,0xef,0x52,0x19,0xd2},
    {0xa9,0xfa,0x13,0xdd,0x07,0x44,0x0a,0xc6,0x56,0x73,0xa9,0xa7,0xb9,0x21,0xb0,0x75},
    {0x44,0x1d,0x8e,0x8b,0x43,0x59,0x84,0x4d,0x15,0x2a,0x2d,0xea,0xac,0x0b,0x9d,0x9f},
    {0x4f,0x43,0x55,0x1a,0x0c,0x1a,0xd1,0x57,0x19,0x30,0xfc,0xbd,0xb5,0x3b,0x61,0x22},
    {0xed,0xac,0xc6,0xcf,0xe1,0xb6,0x17,0x98,0xf8,0x86,0xeb,0x25,0x4d,0xbd,0x8a,0x07},
    {0x17,0xd2,0x03,0x2c,0xf6,0x64,0x14,0xb4,0x0e,0xe2,0xff,0x91,0x43,0x5f,0x75,0x96},
    {0xc3,0x4f,0x93,0x36,0x35,0x2b,0x87,0x82,0x3b,0xc9,0x78,0x13,0x78,0x96,0x0d,0x85},
    {0x65,0x98,0x04,0x8a,0x50,0xb3,0x83,0x08,0x6b,0x7a,0xfb,0x1b,0x13,0xec,0xf6,0x9e},
};

unsigned char translation_table[256] {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

mask arbitrary_translate(mask m)
{
    for(auto& b : m.bytes) {
        b = translation_table[b];
    }

    return m;
}

mask byte_shuffle(mask original)
{
    mask shuffled{original};

    shuffled.bytes[0x1] = original.bytes[0x5];
    shuffled.bytes[0x5] = original.bytes[0x9];
    shuffled.bytes[0x9] = original.bytes[0xd];
    shuffled.bytes[0xd] = original.bytes[0x1];
    shuffled.bytes[0x2] = original.bytes[0xa];
    shuffled.bytes[0xa] = original.bytes[0x2];
    shuffled.bytes[0x6] = original.bytes[0xe];
    shuffled.bytes[0xe] = original.bytes[0x6];
    shuffled.bytes[0x3] = original.bytes[0xf];
    shuffled.bytes[0xf] = original.bytes[0xb];
    shuffled.bytes[0xb] = original.bytes[0x7];
    shuffled.bytes[0x7] = original.bytes[0x3];

    return shuffled;
}

std::uint32_t xorshift(std::uint32_t in)
{
    return ((in & 0xff) >> 7) * 0x1b ^ (in & 0xff) * 2;
}

// I HAVE ANGERED THE GODS
mask xorify(mask original)
{
    auto ptr = original.bytes + 2;
    unsigned char local7;
    unsigned char local6;
    unsigned char local5;
    std::uint32_t localc;
    for(int count = 0; count != 4; ++count) {
        auto al = ptr[0x1];
        auto cl = ptr[-0x2];
        auto bh = ptr[0x0];
        auto bl = ptr[-0x1];

        local7 = al;

        al ^= bh;

        localc = al;

        al ^= cl;
        al ^= bl;

        local6 = cl;
        local5 = al;

        al = cl;
        al ^= bl;

        al = xorshift(al);
        al ^= local6;
        al ^= local5;
        ptr[-0x2] = al;

        al = bl;
        al ^= bh;

        al = xorshift(al);

        al ^= bl;
        bl = local5;
        al ^= bl;

        ptr[-0x1] = al;

        al = xorshift(localc);
        al ^= bh;
        al ^= bl;

        ptr[0] = al;

        al = local7;
        al ^= local6;
        al = xorshift(al);
        al ^= local7;

        ptr += 4;

        al ^= bl;
        ptr[-0x3] = al;
    }

    return original;
}

mask apply_prepared_mask(mask m, unsigned mask_select, encryption_state* t)
{
    auto mask_ptr = prepared_masks[mask_select & 0xff].bytes;
    for(auto& byte : m.bytes) {
        byte ^= *(mask_ptr++);
    }

    return m;
}

mask make_mask(mask counter, encryption_state* t)
{
    mask ret{counter};

    ret = apply_prepared_mask(ret, 0, t);

    // do this nine times for good measure..?
    for(int count = 1; count <= 9; ++count) {
        ret = arbitrary_translate(ret);
        ret = byte_shuffle(ret);
        ret = xorify(ret);
        ret = apply_prepared_mask(ret, count, t);
    }

    ret = arbitrary_translate(ret);
    ret = byte_shuffle(ret);
    ret = apply_prepared_mask(ret, 10, t);

    return ret;
}

void decrypt(encryption_state* t, char* data, std::size_t size)
{
    mask current_mask{};
    std::size_t mask_index{16};

    for(std::size_t index{0}; index < size; ++index) {
        if(mask_index == 16) {
            current_mask = make_mask(t->counter, t);
            t->counter = incr_mask(t->counter);

            mask_index = 0;
        }

        auto mask = current_mask.bytes[mask_index++];
        data[index] ^= mask;
    }
}

std::uint32_t load_le_uint32(const char* const ptr)
{
    std::uint32_t ret{};
    ret |= static_cast<std::uint32_t>((unsigned char)ptr[0]);
    ret |= static_cast<std::uint32_t>((unsigned char)ptr[1]) << 8;
    ret |= static_cast<std::uint32_t>((unsigned char)ptr[2]) << 16;
    ret |= static_cast<std::uint32_t>((unsigned char)ptr[3]) << 24;

    return ret;
}

// this class is based on https://github.com/gummikana/poro
struct rng {
    double seed;

    rng(double s)
    {
        seed = s;
    }

    int next()
    {
        int iseed = (int)seed;
        int hi = iseed / 127773L;                 // integer division
        int lo = iseed - hi * 127773L;            // modulo
        iseed = 16807 * lo - 2836 * hi;
        if (iseed <= 0) iseed += 2147483647L;
        seed = (double)iseed;
        return iseed;
    }
};

mask counter_from_file_index(std::size_t file_index)
{
    auto seed = static_cast<double>(23456911 + file_index);
    if(seed >= 2147483647.00000000)
        seed *= 0.5;
    auto r = rng{seed};
    r.next(); // throw one value away for good luck!

    int numbers[4]{};
    for(auto& n : numbers) {
        n = -r.next();
    }


    mask counter{};

    static_assert(sizeof(numbers) == sizeof(counter));
    std::memcpy(&counter, numbers, sizeof(counter));

    return counter;
}

const encryption_state initial_header{
    counter_from_file_index(1)
};

const encryption_state initial_file_table{
    counter_from_file_index(0x7ffffffe)
};

void create_binary_file(fs::path path, const char* begin, std::size_t size)
{
    std::ofstream of{path, std::ios::binary};
    of.write(begin, size);
}

int main(int argc, char** argv)
{
    if(argc != 3) {
        std::cerr << "error, usage: program filename outputpath.\n";
        return 1;
    }

    const auto output_path = fs::path{argv[2]};
    if(!fs::is_directory(output_path)) {
        std::cerr << output_path << " is not a directory.\n";
        return 2;
    }

    std::ifstream file{argv[1], std::ios::binary};

    if(!file.is_open()) {
        std::cerr << "couldn't open file.\n";
        return 3;
    }

    file.seekg(0, std::ios_base::end);
    const auto wak_size = file.tellg();
    file.seekg(0, std::ios_base::beg);

    const auto memory = std::make_unique<char[]>(wak_size);
    file.read(memory.get(), wak_size);

    const auto header = memory.get();
    const auto header_size = 0x10;
    auto header_state = initial_header;
    decrypt(&header_state, header, header_size);

    std::cout << "Header: ";
    std::cout
        << load_le_uint32(header + 0) << ", "
        << load_le_uint32(header + 4) << ", "
        << load_le_uint32(header + 8) << ", "
        << load_le_uint32(header + 12) << ", ";

    const auto file_count = load_le_uint32(header + 4);

    const auto file_table = header + 0x10;
    const auto file_table_size = load_le_uint32(header + 8) - header_size;

    auto file_table_state = initial_file_table;
    decrypt(&file_table_state, file_table, file_table_size);

    const auto* file_table_entry = file_table;

    for(std::size_t file_index{0}; file_index != file_count; ++file_index) {
        const auto file_offset = load_le_uint32(file_table_entry);
        const auto file_size = load_le_uint32(file_table_entry + 4);

        const auto file_name_start = file_table_entry + 12;
        const auto file_name_size = load_le_uint32(file_table_entry + 8);

        const auto file_name = std::string_view{file_name_start, file_name_size};

        std::cout << "file #" << file_index << '\n';
        std::cout << "file offset = " << file_offset << '\n';
        std::cout << "file size = " << file_size << '\n';
        std::cout << "file name = " << file_name << '\n';

        if(file_offset + file_size > wak_size) {
            std::cerr << "file is out of bounds.\n";
            return 4;
        }
        
        const auto counter = counter_from_file_index(file_index);
        const auto file_contents = header + file_offset;

        encryption_state file_encryption_state{
            counter
        };

        decrypt(&file_encryption_state, file_contents, file_size);

        const auto file_path = output_path / file_name;
        fs::create_directories(file_path.parent_path());
        create_binary_file(file_path, file_contents, file_size);

        file_table_entry = file_name.end();
    }
}
