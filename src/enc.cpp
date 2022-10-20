#include <iostream>
#include <string_view>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <memory>
#include <array>
#include <filesystem>

#include <openssl/evp.h>
#include <openssl/err.h>

namespace fs = std::filesystem;

enum class encrypt_type {
    plain,
    v1,
    v2,
};

encrypt_type type = encrypt_type::plain;

using key_type = std::array<unsigned char, 16>;
key_type counter_from_file_index(std::size_t file_index);

auto const key = counter_from_file_index(0);

void new_decrypt(key_type t, char* data, std::size_t size)
{
    auto cipher = EVP_aes_128_ctr();
    auto context = EVP_CIPHER_CTX_new();
    if (!context) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error{"Couldn't create cipher context."};
    }

    if (EVP_DecryptInit_ex(context, cipher, NULL, &key[0], &t[0]) != 1) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error{"Couldn't initialise context."};
    }

    std::unique_ptr<char[]> encrypted{new char[size]};
    std::copy(data, data + size, encrypted.get());

    int len;
    if (EVP_DecryptUpdate(
            context,
            reinterpret_cast<unsigned char*>(data), &len,
            reinterpret_cast<unsigned char*>(encrypted.get()), size
        ) != 1
    ) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error{"Couldn't decrypt."};
    }

    if(EVP_DecryptFinal_ex(context, reinterpret_cast<unsigned char*>(data + len), &len) != 1) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error{"Couldn't finalise decrypt."};
    }

    EVP_CIPHER_CTX_free(context);
}

void decrypt(key_type t, char* data, std::size_t size)
{
    if (type == encrypt_type::plain)
        return;

    new_decrypt(t, data, size);
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

key_type counter_from_file_index(std::size_t file_index)
{
    auto seed = static_cast<double>(23456911 + file_index);

    if (type == encrypt_type::v2) {
        if(seed >= 2147483647.00000000)
            seed *= 0.5;
    }

    auto r = rng{seed};
    r.next(); // throw one value away for good luck!

    int numbers[4]{};
    for(auto& n : numbers) {
        n = -r.next();
    }

    key_type counter{};

    static_assert(sizeof(numbers) == sizeof(counter));
    std::memcpy(&counter[0], numbers, sizeof(counter));

    return counter;
}

void create_binary_file(fs::path path, const char* begin, std::size_t size)
{
    std::ofstream of{path, std::ios::binary};
    of.write(begin, size);
}

int main(int argc, char** argv)
{
    if(argc != 4) {
        std::cerr << "error, usage: program type filename outputpath.\n";
        return 1;
    }

    auto typev = std::string_view{argv[1]};

    if (typev == "plain") {
        type = encrypt_type::plain;
    } else if (typev == "v1") {
        type = encrypt_type::v1;
    } else if (typev == "v2") {
        type = encrypt_type::v2;
    } else {
        std::cerr << "Unknown type " << typev << "\n";
        return 1;
    }

    const key_type initial_header{
        counter_from_file_index(1)
    };

    const key_type initial_file_table{
        counter_from_file_index(0x7ffffffe)
    };

    const auto output_path = fs::path{argv[3]};
    if(!fs::is_directory(output_path)) {
        std::cerr << output_path << " is not a directory.\n";
        return 2;
    }

    std::ifstream file{argv[2], std::ios::binary};

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
    decrypt(header_state, header, header_size);

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
    decrypt(file_table_state, file_table, file_table_size);

    const auto* file_table_entry = file_table;

    for(std::size_t file_index{0}; file_index != file_count; ++file_index) {
        const auto file_offset = load_le_uint32(file_table_entry);
        const auto file_size = load_le_uint32(file_table_entry + 4);

        const auto file_name_start = file_table_entry + 12;
        const auto file_name_size = load_le_uint32(file_table_entry + 8);

        if (12 + file_name_size > wak_size) {
            std::cerr << "file name is out of bounds.\n";
            return 4;
        }

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

        key_type file_encryption_state{
            counter
        };

        decrypt(file_encryption_state, file_contents, file_size);

        const auto file_path = output_path / file_name;
        fs::create_directories(file_path.parent_path());
        create_binary_file(file_path, file_contents, file_size);

        file_table_entry = file_name.end();
    }
}
