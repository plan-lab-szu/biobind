#include <seal/seal.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <optional>
#include <vector>

using namespace seal;

namespace {

struct Config {
    std::string model = "FaceNet";
    std::string method = "scmv";
    int n = 1;
    std::size_t N = 10000;
    int repeat = 3;
    int seed = 12345;
    std::size_t max_measured_blocks = 0;
    std::string out_path;
    std::optional<int> plain_bits_override;
    std::vector<int> coeff_bits_override;
    bool validate_only = false;
};

struct ModelParams {
    std::string model;
    std::size_t L;
    int gamma;
    std::uint64_t T;
    std::size_t d;
    int plain_bits;
    std::vector<int> coeff_bits;
};

void usage(const char *argv0)
{
    std::cerr
        << "Usage: " << argv0 << " --model FaceNet|MobileFaceNet --n N --N gallery_size [options]\n"
        << "Options:\n"
        << "  --method scmv|horizontal  Matching layout to benchmark (default: scmv)\n"
        << "  --repeat R                 Repetitions per measured block (default: 3)\n"
        << "  --seed S                   Deterministic random seed (default: 12345)\n"
        << "  --max-measured-blocks B    Measure at most B blocks; 0 means all blocks (default: 0)\n"
        << "  --plain-bits B             Override plaintext modulus bit count\n"
        << "  --coeff-bits LIST          Override coeff modulus limbs, e.g. 50,50,50,50\n"
        << "  --validate-only            Only check SEAL parameter validity and print JSON\n"
        << "  --out PATH                 Write JSONL rows to PATH\n";
}

std::vector<int> parse_coeff_bits(const std::string &value)
{
    std::vector<int> bits;
    std::stringstream ss(value);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (!item.empty()) {
            bits.push_back(std::stoi(item));
        }
    }
    if (bits.empty()) {
        throw std::runtime_error("--coeff-bits cannot be empty");
    }
    return bits;
}

Config parse_args(int argc, char **argv)
{
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const std::string &name) -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error("missing value for " + name);
            }
            return argv[++i];
        };
        if (a == "--model") {
            cfg.model = need(a);
        } else if (a == "--method") {
            cfg.method = need(a);
        } else if (a == "--n") {
            cfg.n = std::stoi(need(a));
        } else if (a == "--N") {
            cfg.N = static_cast<std::size_t>(std::stoull(need(a)));
        } else if (a == "--repeat") {
            cfg.repeat = std::stoi(need(a));
        } else if (a == "--seed") {
            cfg.seed = std::stoi(need(a));
        } else if (a == "--max-measured-blocks") {
            cfg.max_measured_blocks = static_cast<std::size_t>(std::stoull(need(a)));
        } else if (a == "--plain-bits") {
            cfg.plain_bits_override = std::stoi(need(a));
        } else if (a == "--coeff-bits") {
            cfg.coeff_bits_override = parse_coeff_bits(need(a));
        } else if (a == "--validate-only") {
            cfg.validate_only = true;
        } else if (a == "--out") {
            cfg.out_path = need(a);
        } else if (a == "--help" || a == "-h") {
            usage(argv[0]);
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + a);
        }
    }
    if (cfg.repeat <= 0) {
        throw std::runtime_error("--repeat must be positive");
    }
    if (cfg.method != "scmv" && cfg.method != "horizontal") {
        throw std::runtime_error("--method must be scmv or horizontal");
    }
    if (cfg.method == "horizontal" && cfg.n != 1) {
        throw std::runtime_error("horizontal baseline uses n=1");
    }
    return cfg;
}

int bits_for_bound(std::uint64_t T, int n, std::uint64_t D)
{
    long double sum = 0.0L;
    long double pow_t = 1.0L;
    for (int i = 0; i < n; ++i) {
        sum += pow_t;
        pow_t *= static_cast<long double>(T);
    }
    long double required = 2.0L * static_cast<long double>(D) * sum + 1.0L;
    return static_cast<int>(std::ceil(std::log2(required))) + 1;
}

ModelParams select_params(const std::string &model, int n)
{
    if (model == "FaceNet") {
        if (n < 1 || n > 3) {
            throw std::runtime_error("FaceNet supports n=1,2,3 for E3");
        }
        ModelParams p;
        p.model = model;
        p.L = 128;
        p.gamma = 128;
        p.T = 35729;
        p.d = 8192;
        if (n == 1) {
            p.plain_bits = 20;
            p.coeff_bits = { 30, 25, 25, 30 };
        } else if (n == 2) {
            p.plain_bits = 31;
            p.coeff_bits = { 45, 30, 30, 45 };
        } else {
            p.plain_bits = 46;
            p.coeff_bits = { 45, 40, 40, 45 };
        }
        return p;
    }
    if (model == "MobileFaceNet") {
        if (n < 1 || n > 2) {
            throw std::runtime_error("MobileFaceNet supports n=1,2 for E3");
        }
        ModelParams p;
        p.model = model;
        p.L = 512;
        p.gamma = 512;
        p.T = 547715;
        p.d = 8192;
        const std::uint64_t D = static_cast<std::uint64_t>(
            p.gamma * p.gamma + p.gamma * std::sqrt(static_cast<double>(p.L)) + 0.25 * p.L);
        p.plain_bits = bits_for_bound(p.T, n, D);
        p.coeff_bits = (n == 1) ? std::vector<int>{ 30, 30, 30, 30 } : std::vector<int>{ 45, 35, 35, 45 };
        return p;
    }
    throw std::runtime_error("unsupported model: " + model);
}

std::string join_bits(const std::vector<int> &bits)
{
    std::ostringstream os;
    for (std::size_t i = 0; i < bits.size(); ++i) {
        if (i) {
            os << "+";
        }
        os << bits[i];
    }
    return os.str();
}

std::string json_escape(const std::string &s)
{
    std::ostringstream os;
    for (char c : s) {
        if (c == '"' || c == '\\') {
            os << '\\' << c;
        } else if (c == '\n') {
            os << "\\n";
        } else {
            os << c;
        }
    }
    return os.str();
}

std::vector<int64_t> random_embedding(std::mt19937_64 &rng, std::size_t L, int gamma)
{
    std::normal_distribution<double> dist(0.0, 1.0);
    std::vector<double> tmp(L);
    double norm2 = 0.0;
    for (double &x : tmp) {
        x = dist(rng);
        norm2 += x * x;
    }
    double scale = static_cast<double>(gamma) / std::sqrt(norm2);
    std::vector<int64_t> out(L);
    for (std::size_t i = 0; i < L; ++i) {
        out[i] = static_cast<int64_t>(std::llround(tmp[i] * scale));
    }
    return out;
}

int64_t centered_mod(std::uint64_t value, std::uint64_t modulus)
{
    std::uint64_t r = value % modulus;
    if (r > modulus / 2) {
        return -static_cast<int64_t>(modulus - r);
    }
    return static_cast<int64_t>(r);
}

int64_t centered_plain(std::uint64_t value, std::uint64_t plain_modulus)
{
    if (value > plain_modulus / 2) {
        return -static_cast<int64_t>(plain_modulus - value);
    }
    return static_cast<int64_t>(value);
}

int64_t centered_mod_signed(int64_t value, std::uint64_t modulus)
{
    int64_t mod = static_cast<int64_t>(modulus);
    int64_t r = value % mod;
    if (r < 0) {
        r += mod;
    }
    if (r > mod / 2) {
        r -= mod;
    }
    return r;
}

std::vector<int64_t> decompose_scores(int64_t packed, std::uint64_t T, int n)
{
    std::vector<int64_t> scores;
    scores.reserve(static_cast<std::size_t>(n));
    int64_t z = packed;
    for (int t = 0; t < n; ++t) {
        int64_t score = centered_mod_signed(z, T);
        scores.push_back(score);
        z = (z - score) / static_cast<int64_t>(T);
    }
    return scores;
}

std::uint64_t encode_signed(int64_t x, std::uint64_t plain_modulus)
{
    if (x >= 0) {
        return static_cast<std::uint64_t>(x);
    }
    return plain_modulus - static_cast<std::uint64_t>(-x);
}

int64_t dot(const std::vector<int64_t> &a, const std::vector<int64_t> &b)
{
    int64_t s = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        s += a[i] * b[i];
    }
    return s;
}

std::vector<std::vector<int64_t>> make_templates(
    std::mt19937_64 &rng, const ModelParams &mp, std::size_t count)
{
    std::vector<std::vector<int64_t>> templates;
    templates.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        templates.push_back(random_embedding(rng, mp.L, mp.gamma));
    }
    return templates;
}

std::vector<Ciphertext> encrypt_query(
    const std::vector<int64_t> &query,
    const ModelParams &mp,
    BatchEncoder &encoder,
    Encryptor &encryptor)
{
    std::vector<Ciphertext> out;
    out.reserve(mp.L);
    for (std::size_t i = 0; i < mp.L; ++i) {
        std::vector<int64_t> row(mp.d, query[i]);
        Plaintext pt;
        encoder.encode(row, pt);
        Ciphertext ct;
        encryptor.encrypt(pt, ct);
        out.push_back(std::move(ct));
    }
    return out;
}

std::vector<Ciphertext> encrypt_block(
    const std::vector<std::vector<int64_t>> &templates,
    std::size_t block_index,
    const ModelParams &mp,
    int n,
    BatchEncoder &encoder,
    Encryptor &encryptor)
{
    std::vector<Ciphertext> block;
    block.reserve(mp.L);
    const std::size_t base = block_index * static_cast<std::size_t>(n) * mp.d;
    for (std::size_t dim = 0; dim < mp.L; ++dim) {
        std::vector<int64_t> row(mp.d, 0);
        for (std::size_t slot = 0; slot < mp.d; ++slot) {
            long long pow_t = 1;
            long long packed = 0;
            for (int layer = 0; layer < n; ++layer) {
                std::size_t idx = base + static_cast<std::size_t>(layer) * mp.d + slot;
                if (idx < templates.size()) {
                    packed += templates[idx][dim] * pow_t;
                }
                pow_t *= static_cast<long long>(mp.T);
            }
            row[slot] = packed;
        }
        Plaintext pt;
        encoder.encode(row, pt);
        Ciphertext ct;
        encryptor.encrypt(pt, ct);
        block.push_back(std::move(ct));
    }
    return block;
}

Ciphertext identify_block(
    const std::vector<Ciphertext> &query,
    const std::vector<Ciphertext> &block,
    const ModelParams &mp,
    Evaluator &evaluator)
{
    Ciphertext sum;
    bool initialized = false;
    for (std::size_t i = 0; i < mp.L; ++i) {
        Ciphertext prod;
        evaluator.multiply(query[i], block[i], prod);
        if (!initialized) {
            sum = std::move(prod);
            initialized = true;
        } else {
            evaluator.add_inplace(sum, prod);
        }
    }
    return sum;
}

Ciphertext encrypt_horizontal_query(
    const std::vector<int64_t> &query,
    const ModelParams &mp,
    BatchEncoder &encoder,
    Encryptor &encryptor)
{
    std::vector<int64_t> row(mp.d, 0);
    const std::size_t templates_per_block = mp.d / mp.L;
    for (std::size_t templ = 0; templ < templates_per_block; ++templ) {
        const std::size_t base = templ * mp.L;
        for (std::size_t dim = 0; dim < mp.L; ++dim) {
            row[base + dim] = query[dim];
        }
    }
    Plaintext pt;
    encoder.encode(row, pt);
    Ciphertext ct;
    encryptor.encrypt(pt, ct);
    return ct;
}

Ciphertext encrypt_horizontal_template(
    const std::vector<std::vector<int64_t>> &templates,
    std::size_t block_index,
    const ModelParams &mp,
    BatchEncoder &encoder,
    Encryptor &encryptor)
{
    std::vector<int64_t> row(mp.d, 0);
    const std::size_t templates_per_block = mp.d / mp.L;
    const std::size_t template_base = block_index * templates_per_block;
    for (std::size_t templ = 0; templ < templates_per_block; ++templ) {
        const std::size_t idx = template_base + templ;
        if (idx >= templates.size()) {
            break;
        }
        const std::size_t slot_base = templ * mp.L;
        for (std::size_t dim = 0; dim < mp.L; ++dim) {
            row[slot_base + dim] = templates[idx][dim];
        }
    }
    Plaintext pt;
    encoder.encode(row, pt);
    Ciphertext ct;
    encryptor.encrypt(pt, ct);
    return ct;
}

Ciphertext identify_horizontal_template(
    const Ciphertext &query,
    const Ciphertext &templ,
    const ModelParams &mp,
    Evaluator &evaluator,
    const RelinKeys &relin_keys,
    const GaloisKeys &galois_keys)
{
    Ciphertext sum;
    evaluator.multiply(query, templ, sum);
    evaluator.relinearize_inplace(sum, relin_keys);
    for (std::size_t step = 1; step < mp.L; step <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_rows(sum, -static_cast<int>(step), galois_keys, rotated);
        evaluator.add_inplace(sum, rotated);
    }
    return sum;
}

std::size_t serialized_size(const Ciphertext &ct)
{
    std::ostringstream os;
    ct.save(os);
    return os.str().size();
}

} // namespace

int main(int argc, char **argv)
{
    try {
        Config cfg = parse_args(argc, argv);
        ModelParams mp = select_params(cfg.model, cfg.n);
        if (cfg.plain_bits_override) {
            mp.plain_bits = *cfg.plain_bits_override;
        }
        if (!cfg.coeff_bits_override.empty()) {
            mp.coeff_bits = cfg.coeff_bits_override;
        }
        if (cfg.method == "horizontal" && mp.d % mp.L != 0) {
            throw std::runtime_error("horizontal packing requires d to be divisible by L");
        }
        if (cfg.method == "horizontal" && (mp.d / 2) % mp.L != 0) {
            throw std::runtime_error("horizontal packing requires each SEAL batching row to contain whole templates");
        }
        const std::size_t templates_per_block = cfg.method == "horizontal" ? mp.d / mp.L :
            static_cast<std::size_t>(cfg.n) * mp.d;
        const std::size_t M = (cfg.N + templates_per_block - 1) / templates_per_block;
        const std::size_t measured_blocks =
            cfg.max_measured_blocks == 0 ? M : std::min(M, cfg.max_measured_blocks);

        EncryptionParameters parms(scheme_type::bgv);
        parms.set_poly_modulus_degree(mp.d);
        parms.set_coeff_modulus(CoeffModulus::Create(mp.d, mp.coeff_bits));
        parms.set_plain_modulus(PlainModulus::Batching(mp.d, mp.plain_bits));
        SEALContext context(parms);

        const int coeff_bits_total = std::accumulate(mp.coeff_bits.begin(), mp.coeff_bits.end(), 0);
        if (cfg.validate_only) {
            std::cout << "{"
                      << "\"model\":\"" << json_escape(mp.model) << "\","
                      << "\"method\":\"" << json_escape(cfg.method) << "\","
                      << "\"n\":" << cfg.n << ","
                      << "\"plain_bits\":" << mp.plain_bits << ","
                      << "\"plain_modulus\":" << parms.plain_modulus().value() << ","
                      << "\"q_bits\":" << coeff_bits_total << ","
                      << "\"rns_limbs\":\"" << join_bits(mp.coeff_bits) << "\","
                      << "\"parameters_set\":" << (context.parameters_set() ? "true" : "false") << ","
                      << "\"parameter_error_name\":\"" << context.parameter_error_name() << "\","
                      << "\"parameter_error_message\":\"" << context.parameter_error_message() << "\""
                      << "}\n";
            return context.parameters_set() ? 0 : 2;
        }

        if (!context.parameters_set()) {
            std::ostringstream err;
            err << "SEAL parameters are invalid: " << context.parameter_error_name()
                << " (" << context.parameter_error_message() << ")";
            throw std::runtime_error(err.str());
        }

        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secret_key();
        PublicKey public_key;
        keygen.create_public_key(public_key);
        RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);
        GaloisKeys galois_keys;
        if (cfg.method == "horizontal") {
            keygen.create_galois_keys(galois_keys);
        }

        BatchEncoder encoder(context);
        Encryptor encryptor(context, public_key);
        Evaluator evaluator(context);
        Decryptor decryptor(context, secret_key);

        std::mt19937_64 rng(static_cast<std::uint64_t>(cfg.seed));
        std::vector<int64_t> query = random_embedding(rng, mp.L, mp.gamma);
        std::size_t template_count = measured_blocks * templates_per_block;
        template_count = std::min(template_count, cfg.N);
        auto templates = make_templates(rng, mp, template_count);

        auto t0 = std::chrono::steady_clock::now();
        std::vector<Ciphertext> encrypted_query;
        Ciphertext horizontal_query;
        if (cfg.method == "horizontal") {
            horizontal_query = encrypt_horizontal_query(query, mp, encoder, encryptor);
        } else {
            encrypted_query = encrypt_query(query, mp, encoder, encryptor);
        }
        auto t1 = std::chrono::steady_clock::now();
        const double query_encryption_ms =
            std::chrono::duration<double, std::milli>(t1 - t0).count();

        std::ofstream file_out;
        std::ostream *out = &std::cout;
        if (!cfg.out_path.empty()) {
            file_out.open(cfg.out_path, std::ios::app);
            if (!file_out) {
                throw std::runtime_error("cannot open output file: " + cfg.out_path);
            }
            out = &file_out;
        }

        const std::uint64_t plain_modulus = parms.plain_modulus().value();
        for (std::size_t b = 0; b < measured_blocks; ++b) {
            auto enc0 = std::chrono::steady_clock::now();
            std::vector<Ciphertext> block;
            Ciphertext horizontal_template;
            if (cfg.method == "horizontal") {
                horizontal_template = encrypt_horizontal_template(templates, b, mp, encoder, encryptor);
            } else {
                block = encrypt_block(templates, b, mp, cfg.n, encoder, encryptor);
            }
            auto enc1 = std::chrono::steady_clock::now();
            const double block_encryption_ms =
                std::chrono::duration<double, std::milli>(enc1 - enc0).count();

            double total_match_ms = 0.0;
            Ciphertext last_result;
            for (int r = 0; r < cfg.repeat; ++r) {
                auto m0 = std::chrono::steady_clock::now();
                if (cfg.method == "horizontal") {
                    last_result = identify_horizontal_template(
                        horizontal_query, horizontal_template, mp, evaluator, relin_keys, galois_keys);
                } else {
                    last_result = identify_block(encrypted_query, block, mp, evaluator);
                }
                auto m1 = std::chrono::steady_clock::now();
                total_match_ms += std::chrono::duration<double, std::milli>(m1 - m0).count();
            }
            const double avg_match_ms = total_match_ms / static_cast<double>(cfg.repeat);

            Plaintext plain_result;
            decryptor.decrypt(last_result, plain_result);
            std::vector<std::uint64_t> decoded;
            encoder.decode(plain_result, decoded);

            bool correctness_pass = true;
            int64_t horizontal_expected = 0;
            int64_t horizontal_slot0 = 0;
            int64_t horizontal_slot_last = 0;
            if (cfg.method == "horizontal") {
                horizontal_slot0 = centered_plain(decoded[0], plain_modulus);
                horizontal_slot_last = centered_plain(decoded[mp.L - 1], plain_modulus);
                const std::size_t template_base = b * templates_per_block;
                horizontal_expected = template_base < templates.size() ? dot(query, templates[template_base]) : 0;
                correctness_pass = horizontal_slot_last == horizontal_expected;
                for (std::size_t templ = 0; templ < templates_per_block && correctness_pass; ++templ) {
                    const std::size_t idx = template_base + templ;
                    if (idx >= templates.size()) {
                        break;
                    }
                    const std::size_t output_slot = templ * mp.L + mp.L - 1;
                    const int64_t got = centered_plain(decoded[output_slot], plain_modulus);
                    const int64_t expected = dot(query, templates[idx]);
                    if (got != expected) {
                        correctness_pass = false;
                    }
                }
            } else {
                const std::size_t slots_to_check = std::min<std::size_t>(8, mp.d);
                for (std::size_t slot = 0; slot < slots_to_check && correctness_pass; ++slot) {
                    auto got = decompose_scores(centered_plain(decoded[slot], plain_modulus), mp.T, cfg.n);
                    for (int layer = 0; layer < cfg.n; ++layer) {
                        std::size_t idx = b * static_cast<std::size_t>(cfg.n) * mp.d +
                            static_cast<std::size_t>(layer) * mp.d + slot;
                        int64_t expected = 0;
                        if (idx < templates.size()) {
                            expected = dot(query, templates[idx]);
                        }
                        if (got[static_cast<std::size_t>(layer)] != expected) {
                            correctness_pass = false;
                            break;
                        }
                    }
                }
            }

            const int noise_budget_bits = decryptor.invariant_noise_budget(last_result);
            const std::size_t db_ciphertext_bytes = cfg.method == "horizontal" ?
                serialized_size(horizontal_template) : serialized_size(block[0]);
            const std::size_t result_ciphertext_bytes = serialized_size(last_result);
            const std::size_t ciphertexts_per_block = cfg.method == "horizontal" ? 1 : mp.L;
            const long double storage_bytes =
                static_cast<long double>(M) * static_cast<long double>(ciphertexts_per_block) *
                static_cast<long double>(db_ciphertext_bytes);
            const std::size_t rotations_per_block = cfg.method == "horizontal" ?
                static_cast<std::size_t>(std::ceil(std::log2(static_cast<double>(mp.L)))) : 0;
            const std::size_t ct_ct_multiplications_per_block = cfg.method == "horizontal" ? 1 : mp.L;
            const std::size_t additions_per_block = cfg.method == "horizontal" ?
                rotations_per_block : (mp.L > 0 ? mp.L - 1 : 0);

            *out << "{"
                 << "\"experiment\":\"" << (cfg.method == "horizontal" ? "E4_SEAL_HORIZONTAL" : "E3_SEAL_SCMV") << "\","
                 << "\"method\":\"" << json_escape(cfg.method) << "\","
                 << "\"model\":\"" << json_escape(mp.model) << "\","
                 << "\"n\":" << cfg.n << ","
                 << "\"N\":" << cfg.N << ","
                 << "\"M\":" << M << ","
                 << "\"templates_per_block\":" << templates_per_block << ","
                 << "\"block_index\":" << b << ","
                 << "\"measured_blocks\":" << measured_blocks << ","
                 << "\"repeat\":" << cfg.repeat << ","
                 << "\"d\":" << mp.d << ","
                 << "\"L\":" << mp.L << ","
                 << "\"Gamma\":" << mp.gamma << ","
                 << "\"T\":" << mp.T << ","
                 << "\"plain_bits\":" << mp.plain_bits << ","
                 << "\"plain_modulus\":" << plain_modulus << ","
                 << "\"q_bits\":" << coeff_bits_total << ","
                 << "\"rns_limbs\":\"" << join_bits(mp.coeff_bits) << "\","
                 << "\"query_encryption_ms\":" << std::fixed << std::setprecision(6) << query_encryption_ms << ","
                 << "\"block_encryption_ms\":" << block_encryption_ms << ","
                 << "\"matching_ms\":" << avg_match_ms << ","
                 << "\"estimated_total_matching_ms\":" << avg_match_ms * static_cast<double>(M) << ","
                 << "\"db_ciphertext_bytes\":" << db_ciphertext_bytes << ","
                 << "\"result_ciphertext_bytes\":" << result_ciphertext_bytes << ","
                 << "\"storage_bytes\":" << std::fixed << std::setprecision(0) << storage_bytes << ","
                 << "\"ciphertexts_per_block\":" << ciphertexts_per_block << ","
                 << "\"rotations_per_block\":" << rotations_per_block << ","
                 << "\"ct_ct_multiplications_per_block\":" << ct_ct_multiplications_per_block << ","
                 << "\"additions_per_block\":" << additions_per_block << ","
                 << "\"noise_budget_bits\":" << noise_budget_bits << ","
                 << "\"horizontal_expected\":" << horizontal_expected << ","
                 << "\"horizontal_slot0\":" << horizontal_slot0 << ","
                 << "\"horizontal_slot_last\":" << horizontal_slot_last << ","
                 << "\"correctness_pass\":" << (correctness_pass ? "true" : "false") << ","
                 << "\"classification\":\"" << (measured_blocks == M ? "MeasuredFullScan" : "MeasuredPerBlockExtrapolatedTotal") << "\""
                 << "}\n";
        }
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        usage(argv[0]);
        return 1;
    }
}
