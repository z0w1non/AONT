#include <fstream>
#include <string>
#include <iterator>
#include <vector>
#include <array>
#include <algorithm>
#include <iterator>
#include <functional>
#include <filesystem>
#include <cstring>

// Crypto++
#include "cryptlib.h"
#include "filters.h"
#include "modes.h"
#include "aes.h"
#include "osrng.h"
#include "sha.h"
#include "files.h"
#include "hex.h"

// Boost
#include "boost/program_options.hpp"

constexpr std::size_t key_size = CryptoPP::AES::MAX_KEYLENGTH;
constexpr std::size_t block_size = CryptoPP::AES::BLOCKSIZE;
using byte = unsigned char;
using array_t = std::vector<byte>;
using key_t = std::array<byte, key_size>;
using block_t = std::array<byte, block_size>;

/**
 * @breif バイト列を 16 進数として出力ストリームに出力する。
 * @param data バイト列の先頭
 * @param size バイト数
 * @param out 出力ストリーム
 */
void dump_hex(const byte* data, std::size_t size, std::ostream & out = std::cout)
{
    CryptoPP::ArraySource(data, size, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::FileSink(out)
        )
    );
}

/**
 * @breif バイト列を固定長のブロックに分割する。
 * @param bytes バイト列
 * @return 分割されたブロックを要素とする可変長配列
 */
std::vector<block_t> split_blocks(const array_t& bytes)
{
    std::vector<block_t> result;
    std::size_t offset = 0;
    while (offset < bytes.size())
    {
        block_t temp;
        const std::size_t size = std::min(block_size, static_cast<std::size_t>(bytes.size() - offset));
        std::copy(bytes.data() + offset, bytes.data() + offset + size, temp.data());
        result.push_back(temp);
        offset += block_size;
    }
    return result;
}

/**
 * @breif バイト列を可変長配列に分割する。
 * @param bytes バイト列
 * @return 分割されたバイト列を要素とする可変長配列
 */
std::vector<array_t> split_arrays(const array_t& bytes, unsigned int split_number)
{
    std::vector<array_t> result;
    for (unsigned int i = 0; i < split_number; ++i)
    {
        const std::size_t begin_offset = bytes.size() * i / split_number;
        const std::size_t end_offset = bytes.size() * (i + 1) / split_number;
        array_t temp;
        std::copy(bytes.data() + begin_offset, bytes.data() + end_offset, std::back_inserter(temp));
        result.push_back(std::move(temp));
    }
    return result;
}

/**
 * @breif SHA-256 を使用してハッシュ値を計算する。
 * @param data 入力の先頭
 * @param size 入力のサイズ
 * @param output_hash 出力ハッシュ
 */
void sha256_hash(const byte* data, std::size_t size, key_t& output_hash)
{
    CryptoPP::SHA256{}.CalculateDigest(output_hash.data(), data, size);
}

/**
 * @breif CBC モードを使用して AES で暗号化する。
 * @param input 入力の先頭
 * @param input_size 入力のバイト数
 * @param output 出力の先頭
 * @param encryption Encryption
 */
void aes_encrypt(const byte* input, std::size_t input_size, byte* output, CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption& encryption)
{
    CryptoPP::ArraySource source{ input, input_size, true,
        new CryptoPP::StreamTransformationFilter{
            encryption,
            new CryptoPP::ArraySink{output, input_size}
        }
    };
}

/**
 * @breif 値をバイト列に変換する。
 * @param value 値
 * @param data バイト列の先頭
 * @param size バイト数
 */
void value_to_array(std::size_t value, byte* data, std::size_t size)
{
    for (std::size_t i = 0; i < size; ++i)
    {
        data[i] = value & 0xff;
        value >>= 8;
    }
}

/**
 * @brief バイト列を値に変換する。
 * @param data バイト列
 * @param size バイト数
 * @return 値
 */
std::size_t array_to_value(const byte* data, std::size_t size)
{
    std::size_t result = 0;
    for (std::size_t i = 0; i < size; ++i)
    {
        result |= static_cast<std::size_t>(data[i]) << (i * 8);
    }
    return result;
}

/**
 * @brief 鍵の表現形式を変換する。
 * @param key 鍵
 * @return 鍵
 */
std::vector<block_t> key_to_blocks(const key_t& key)
{
    std::vector<block_t> result;
    for (std::size_t i = 0; i < key_size / block_size; ++i)
    {
        block_t temp;
        std::copy(key.data() + i * block_size, key.data() + (i + 1) * block_size, temp.data());
        result.push_back(temp);
    }
    return result;
}

/**
 * @brief 鍵の表現形式を変換する。
 * @param blocks ブロックの先頭
 * @return block_number ブロック数
 */
key_t blocks_to_key(const block_t* blocks, std::size_t block_number)
{
    key_t result;
    for (std::size_t i = 0; i < block_number; ++i)
    {
        std::copy(blocks[i].begin(), blocks[i].end(), result.data() + i * block_size);
    }
    return result;
}

 /**
  * @breif バイト列同士を XOR 演算した結果を出力する。
  * @param input_a 入力バイト列A
  * @param input_b 入力バイト列B
  * @param size バイト数
  * @param output 出力バイト列
  */
void bytes_xor(const byte* input_a, const byte* input_b, std::size_t size, byte * output)
{
    for (std::size_t i = 0; i < size; ++i)
    {
        output[i] = input_a[i] ^ input_b[i];
    }
}

/**
 * @breif 可変長配列を連結する。
 * @param array 可変長配列
 * @return 連結された可変長配列
 */
template <typename T>
array_t concatenate(const std::vector<T>& array)
{
    array_t result;
    for (const auto& i : array)
    {
        std::copy(i.begin(), i.end(), std::back_inserter(result));
    }
    return result;
}

/**
 * @breif インデックスを暗号化する。
 * @param index インデックス
 * @param encryption Encryption
 * @return 暗号化されたブロック
 */
block_t encrypt_index(std::size_t index, CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption& encryption)
{
    block_t index_arary;
    value_to_array(index, index_arary.data(), index_arary.size());
    block_t encrypted_index;
    aes_encrypt(index_arary.data(), index_arary.size(), encrypted_index.data(), encryption);
    return encrypted_index;
}

/**
 * @breif AONT 方式で入力データを暗号化する。
 * @param input 入力データ
 * @return 暗号文
 */
array_t aont_encrypt(const array_t& input)
{
    CryptoPP::AutoSeededRandomPool random_pool;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;

    // 初期化ベクトルとランダム鍵を設定する。
    CryptoPP::SecByteBlock random_key{ key_size };
    random_pool.GenerateBlock(random_key.data(), random_key.size());

    std::cout << "Random Key: ";
    dump_hex(random_key.data(), random_key.size());
    std::cout << std::endl;

    block_t iv;
    random_pool.GenerateBlock(iv.data(), iv.size());
    e.SetKeyWithIV(random_key.data(), random_key.size(), iv.data(), iv.size());

    std::cout << "iv: ";
    dump_hex(iv.data(), iv.size());
    std::cout << std::endl;

    std::vector<block_t> pseudo_messages = split_blocks(input);

    // 元のファイルサイズを擬似メッセージに追加する。
    {
        std::cout << "Source Size: " << input.size() << std::endl;
        key_t source_size;
        value_to_array(input.size(), source_size.data(), source_size.size());
        std::vector<block_t> source_size_blocks = key_to_blocks(source_size);
        for (const block_t& block : source_size_blocks)
        {
            pseudo_messages.push_back(block);
        }
    }

    // 擬似メッセージの各ブロックをランダムに選択された鍵で暗号化されたそのブロックのインデックスと XOR して前処理する。
    key_t hash;
    std::copy(random_key.begin(), random_key.end(), hash.begin());
    for (std::size_t index = 0; index < pseudo_messages.size(); ++index)
    {
        const block_t encrypted_index = encrypt_index(index, e);
        bytes_xor(encrypted_index.data(), pseudo_messages[index].data(), block_size, pseudo_messages[index].data());

        // ランダム鍵と「前処理されたすべてのブロックのハッシュ」の XOR を計算する。
        key_t sha256;
        std::size_t size = block_size;
        sha256_hash(pseudo_messages[index].data(), block_size, sha256);
        bytes_xor(sha256.data(), hash.data(), sha256.size(), hash.data());
    }

    // 初期化ベクトルを擬似メッセージに追加する。
    pseudo_messages.push_back(iv);

    // ハッシュを擬似メッセージに追加する。
    std::vector<block_t> key_blocks = key_to_blocks(hash);
    for (const block_t& block : key_blocks)
    {
        pseudo_messages.push_back(block);
    }

    std::cout << "hash: ";
    dump_hex(hash.data(), hash.size());
    std::cout << std::endl;

    // 擬似メッセージを結合して返す。
    return concatenate(pseudo_messages);
}

/**
 * @breif AONT 方式で入力データを復号する。
 * @param input 入力データ
 * @return 平文
 */
array_t aont_decrypt(const array_t& input)
{
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;

    // 入力データを擬似メッセージに分割する。
    std::vector<block_t> pseudo_messages = split_blocks(input);

    // 擬似メッセージからハッシュ値を取得する。
    key_t hash = blocks_to_key(&pseudo_messages[pseudo_messages.size() - 2], 2);
    pseudo_messages.resize(pseudo_messages.size() - 2);

    std::cout << "hash: ";
    dump_hex(hash.data(), hash.size());
    std::cout << std::endl;

    // 擬似メッセージから初期化ベクトルを取得する。
    const block_t iv = pseudo_messages[pseudo_messages.size() - 1];
    pseudo_messages.resize(pseudo_messages.size() - 1);

    std::cout << "iv: ";
    dump_hex(iv.data(), iv.size());
    std::cout << std::endl;

    // 擬似メッセージのすべてのブロックのハッシュを XOR してランダム鍵を復号する。
    for (std::size_t index = 0; index < pseudo_messages.size(); ++index)
    {
        key_t sha256;
        sha256_hash(pseudo_messages[index].data(), block_size, sha256);
        bytes_xor(sha256.data(), hash.data(), key_size, hash.data());
    }
    e.SetKeyWithIV(hash.data(), hash.size(), iv.data(), iv.size());

    std::cout << "Random Key: ";
    dump_hex(hash.data(), hash.size());
    std::cout << std::endl;

    // 擬似メッセージのすべてのブロックをランダム鍵で暗号化されたそのブロックのインデックスと XOR 演算することにより復号する。
    for (std::size_t index = 0; index < pseudo_messages.size(); ++index)
    {
        const block_t encrypted_index = encrypt_index(index, e);
        bytes_xor(encrypted_index.data(), pseudo_messages[index].data(), block_size, pseudo_messages[index].data());
    }

    // 元のファイルサイズを取得する。
    std::vector<block_t> source_size_blocks;
    for (auto iterator = pseudo_messages.rbegin(); iterator != std::next(pseudo_messages.rbegin(), 2); ++iterator)
    {
        source_size_blocks.push_back(*iterator);
    }
    pseudo_messages.resize(pseudo_messages.size() - 2);
    const std::size_t source_size = array_to_value(source_size_blocks[0].data(), key_size);
    std::cout << "Source Size: " << source_size << std::endl;

    // 平文を結合する。
    array_t result = concatenate(pseudo_messages);

    // 元のファイルサイズに切り詰める。
    result.resize(source_size);

    return result;
}

/**
 * @breif ファイルを可変長配列として読み込む。
 * @param file ファイルのパス
 * @return 可変長配列
 */
array_t file_to_array(const std::filesystem::path& file)
{
    std::ifstream ifs{ file, std::ios_base::binary };
    array_t result{ std::istreambuf_iterator<char>{ ifs }, std::istreambuf_iterator<char>{} };
    return result;
}

/**
 * @breif encrypt モードの実装
 * @param source_file_path 平文ファイルのパス
 * @param split_number 分割数
 */
void encrypt_mode(const std::filesystem::path& source_file_path, unsigned int split_number)
{
    const array_t source_file = file_to_array(source_file_path);
    const array_t encrypted = aont_encrypt(source_file);
    const std::vector<array_t> splited = split_arrays(encrypted, split_number);

    for (unsigned int i = 0; i < split_number; ++i)
    {
        const std::filesystem::path output_file_path = source_file_path.string() + std::string{ "." } + std::to_string(i);
        std::ofstream ofs{ output_file_path, std::ios_base::binary };
        ofs.write(reinterpret_cast<const char*>(splited[i].data()), splited[i].size());
    }
    std::cout << "Encryption was successful." << std::endl;
}

/**
 * @breif decrypt モードの実装
 * @param encrypted_files 暗号化されたファイルのパスの可変長配列
 * @param output_file_path 出力ファイルのパス
 */
void decrypt_mode(const std::vector<std::filesystem::path>& encrypted_files, const std::filesystem::path& output_file_path)
{
    std::vector<array_t> temp;
    for (const std::filesystem::path& encrypted_file : encrypted_files)
    {
        temp.push_back(file_to_array(encrypted_file));
    }
    const array_t decrypted = aont_decrypt(concatenate(temp));
    std::ofstream ofs{ output_file_path, std::ios_base::binary };
    ofs.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
    std::cout << "Decryption was successful." << std::endl;
}

int main(int argc, char** argv)
{
    namespace po = boost::program_options;

    try
    {
        po::options_description global_desc("Global Options");
        global_desc.add_options()
            ("subcommand", po::value<std::string>(), "Subcommand to execute: 'encrypt' or 'decrypt'")
            ("subargs", po::value<std::vector<std::string>>(), "Arguments for subcommand");

        po::positional_options_description global_position;
        global_position.add("subcommand", 1).add("subargs", -1);

        po::variables_map vm;
        // 未知のオプションを無視してサブコマンドを特定する。
        po::parsed_options parsed = po::command_line_parser(argc, argv)
            .options(global_desc)
            .positional(global_position)
            .allow_unregistered()
            .run();

        po::store(parsed, vm);
        po::notify(vm);

        // サブコマンドが指定されていない場合
        if (!vm.count("subcommand"))
        {
            std::cerr << "Usage: AONT.exe [encrypt|decrypt] [options]" << std::endl;
            return 1;
        }

        std::string subcommand = vm["subcommand"].as<std::string>();

        // サブコマンド以降のオプションを集める。
        std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);

        // 先頭のサブコマンドを除外する。
        if (!opts.empty())
        {
            opts.erase(opts.begin());
        }

        // 暗号化および秘密分散の処理
        if (subcommand == "encrypt")
        {
            po::options_description enc_desc("Encrypt Options");
            enc_desc.add_options()
                ("help,h", "Help message")
                ("input,i", po::value<std::filesystem::path>()->required(), "Source file path")
                ("split-number,n", po::value<unsigned int>()->required(), "Number of splits");

            po::variables_map enc_vm;
            po::store(po::command_line_parser(opts).options(enc_desc).run(), enc_vm);

            if (enc_vm.count("help"))
            {
                std::cout << "Usage: AONT.exe encrypt -i <source-file> -n <split-number>" << std::endl << enc_desc << std::endl;
                return 0;
            }

            po::notify(enc_vm);

            const std::filesystem::path source_file = enc_vm["input"].as<std::filesystem::path>();
            const unsigned int split_number = enc_vm["split-number"].as<unsigned int>();

            std::cout << "[Encrypt Mode]" << std::endl;
            std::cout << "Source File: " << source_file << std::endl;
            std::cout << "Split Number: " << split_number << std::endl;

            encrypt_mode(source_file, split_number);
        }
        // 復号の処理
        else if (subcommand == "decrypt")
        {
            po::options_description dec_desc("Decrypt Options");
            dec_desc.add_options()
                ("help,h", "Help message")
                ("input,i", po::value<std::vector<std::filesystem::path>>()->multitoken()->required(), "Encrypted file list")
                ("output,o", po::value<std::filesystem::path>()->required(), "Output file path");

            po::variables_map dec_vm;
            po::store(po::command_line_parser(opts).options(dec_desc).run(), dec_vm);

            if (dec_vm.count("help"))
            {
                std::cout << "Usage: AONT.exe decrypt -i <encrypted-file-list> -o <output-file>" << std::endl << dec_desc << std::endl;
                return 0;
            }

            po::notify(dec_vm);

            std::vector<std::filesystem::path> encrypted_files = dec_vm["input"].as<std::vector<std::filesystem::path>>();
            std::filesystem::path output_file = dec_vm["output"].as<std::filesystem::path>();

            std::cout << "[Decrypt Mode]" << std::endl;
            std::cout << "Encrypted Files:" << std::endl;
            for (const std::filesystem::path& file : encrypted_files)
            {
                std::cout << "    " << file << std::endl;
            }
            std::cout << "Output File: " << output_file << std::endl;

            decrypt_mode(encrypted_files, output_file);
        }
        else
        {
            std::cerr << "Unknown subcommand: " << subcommand << std::endl;
            std::cerr << "Usage: AONT.exe [encrypt|decrypt] [options]" << std::endl;
            return 1;
        }
    }
    catch (const po::error& e)
    {
        std::cerr << "Error (boost::program_options::error): " << e.what() << std::endl;
        return 1;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error (std::exception): " << e.what() << std::endl;
        return 1;
    }

    return 0;
}