// Local component experiment. No network, biometric capture, PVSC, or threshold decryption.
// The author's unmodified benchmark supplies E3 parameters, SCMV layout and decoding.
#define main author_benchmark_main
#include "vendor/scmv_e3_benchmark.cpp"
#undef main
#include <filesystem>
#include <limits>
#include <memory>
#if defined(__MINGW32__) && defined(SEAL_USE_SHARED_MUTEX)
#error "This MinGW run requires SEAL built with SEAL_USE_CXX17=OFF (stock atomic locks)."
#endif
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif
unsigned long process_handles() {
#ifdef _WIN32
    DWORD handles=0;
    if(!GetProcessHandleCount(GetCurrentProcess(),&handles)) throw std::runtime_error("handle telemetry failed");
    return handles;
#else
    return 0;
#endif
}
const SEALContext *stress_context=nullptr;
const PublicKey *stress_public_key=nullptr;
bool parallel_stress=false;

using Clock = std::chrono::steady_clock;
double elapsed(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now()-start).count();
}
void require(bool ok, const char *msg) { if (!ok) throw std::runtime_error(msg); }
void u64(std::ostream &s, uint64_t x) {
    for (int i=0;i<8;++i) s.put(static_cast<char>((x>>(8*i))&255));
}
uint64_t read64(std::istream &s) {
    uint64_t x=0; for(int i=0;i<8;++i) { int c=s.get(); require(c!=EOF,"short frame"); x|=uint64_t(c)<<(8*i); } return x;
}
std::string frame(const std::vector<Ciphertext> &rows, const ModelParams &p, int n,
                  compr_mode_type mode) {
    std::ostringstream out(std::ios::binary);
    out.write("BGBGV001",8); u64(out,p.d); u64(out,n); u64(out,p.L); u64(out,p.T);
    for(const auto &ct:rows) {
        std::ostringstream row(std::ios::binary); ct.save(row,mode); auto bytes=row.str();
        u64(out,bytes.size()); out.write(bytes.data(),bytes.size());
    }
    return out.str();
}
std::vector<Ciphertext> unframe(const std::string &bytes, const SEALContext &ctx,
                              const ModelParams &p, int n) {
    std::istringstream in(bytes,std::ios::binary); char magic[8]; in.read(magic,8);
    require(std::string(magic,8)=="BGBGV001","frame version");
    require(read64(in)==p.d && read64(in)==uint64_t(n) && read64(in)==p.L && read64(in)==p.T,"frame metadata");
    std::vector<Ciphertext> rows(p.L);
    for(auto &ct:rows) {
        auto len=read64(in); require(len<=bytes.size(),"frame length");
        std::string b(len,'\0'); in.read(b.data(),len); require(bool(in),"short row");
        std::istringstream r(b,std::ios::binary); ct.load(ctx,r); require(r.peek()==EOF,"row trailing data");
    }
    require(in.peek()==EOF,"frame trailing data"); return rows;
}
struct Times { double construct=0,encode=0,encrypt=0; };
std::vector<Ciphertext> encrypt_rows(const std::vector<int64_t> &v,const ModelParams &p,int n,
                                   size_t slot,bool query,BatchEncoder &encoder,Encryptor &encryptor,Times &t) {
    if(p.model=="Unified512") {
        require(v.size()==512,"unified vector dimension");
        int64_t norm2=0;
        for(auto x:v) { require(x>=-2047 && x<=2047,"unified coordinate domain"); norm2+=x*x; }
        require(norm2<=4236655,"unified normalized domain");
    }
    std::vector<Ciphertext> rows(p.L);
    std::vector<Times> row_times(p.L);
    #pragma omp parallel for num_threads(4) if(parallel_stress)
    for(size_t dim=0;dim<p.L;++dim) {
        thread_local std::unique_ptr<BatchEncoder> worker_encoder;
        thread_local std::unique_ptr<Encryptor> worker_encryptor;
        thread_local auto worker_pool=MemoryPoolHandle::New();
        if(parallel_stress && !worker_encoder) {
            worker_encoder=std::make_unique<BatchEncoder>(*stress_context);
            worker_encryptor=std::make_unique<Encryptor>(*stress_context,*stress_public_key);
        }
        auto &row_encoder=parallel_stress?*worker_encoder:encoder;
        auto &row_encryptor=parallel_stress?*worker_encryptor:encryptor;
        auto &rt=row_times[dim];
        auto a=Clock::now(); std::vector<int64_t> row(p.d,query?v[dim]:0);
        if(!query) { int64_t power=1; for(size_t l=0;l<slot/p.d;++l) power*=p.T; row[slot%p.d]=v[dim]*power; }
        rt.construct+=elapsed(a); Plaintext pt; a=Clock::now(); row_encoder.encode(row,pt); rt.encode+=elapsed(a);
        Ciphertext ct; a=Clock::now(); row_encryptor.encrypt(pt,ct,worker_pool); rt.encrypt+=elapsed(a); rows[dim]=std::move(ct);
    }
    for(auto &rt:row_times) { t.construct+=rt.construct; t.encode+=rt.encode; t.encrypt+=rt.encrypt; }
    return rows;
}
void save_file(const std::filesystem::path &path,const std::string &b) {
    std::ofstream f(path,std::ios::binary); f.write(b.data(),b.size()); require(bool(f),"write failed");
}
std::string idstr(const parms_id_type &id) {
    std::ostringstream s; s<<std::hex<<std::setfill('0'); for(auto x:id) s<<std::setw(16)<<x; return s.str();
}
void params_json(std::ostream &out,const ModelParams &p,int n,const SEALContext &ctx) {
    auto &parms=ctx.key_context_data()->parms();
    out<<"{\"model\":\""<<p.model<<"\",\"n\":"<<n<<",\"L\":"<<p.L<<",\"d\":"<<p.d
       <<",\"Gamma\":"<<p.gamma<<",\"T\":"<<p.T<<",\"plain_modulus\":"<<parms.plain_modulus().value()
       <<",\"coeff_modulus\":[";
    bool first=true; for(auto &m:parms.coeff_modulus()) { if(!first) out<<','; first=false; out<<m.value(); }
    out<<"],\"key_parms_id\":\""<<idstr(ctx.key_parms_id())<<"\",\"data_parms_id\":\""<<idstr(ctx.first_parms_id())
       <<"\",\"data_modulus_bits\":"<<ctx.first_context_data()->total_coeff_modulus_bit_count()
       <<",\"security_level\":\"tc128\",\"seal\":\""<<SEAL_VERSION<<"\",\"default_compression\":"<<int(Serialization::compr_mode_default)<<"}\n";
}
int main(int argc,char **argv) {
 try {
    require(argc>=5,"usage: bgv-measure measure|stress MODEL n OUT [max-additions]");
    std::string mode=argv[1]; int n=std::stoi(argv[3]); ModelParams p;
    if(std::string(argv[2])=="Unified512") {
        require(n==2,"Unified512 requires n=2");
        p.model="Unified512"; p.L=512; p.gamma=2047; p.d=8192;
        p.T=8473312; p.plain_bits=48; p.coeff_bits={60,50,50,50};
    } else p=select_params(argv[2],n);
    // Optional diagnostic parameter override; original E3 results remain separate artifacts.
    if(argc>6) p.coeff_bits=parse_coeff_bits(argv[6]);
    std::filesystem::path outdir=argv[4]; std::filesystem::create_directories(outdir);
    EncryptionParameters parms(scheme_type::bgv); parms.set_poly_modulus_degree(p.d);
    parms.set_coeff_modulus(CoeffModulus::Create(p.d,p.coeff_bits)); parms.set_plain_modulus(PlainModulus::Batching(p.d,p.plain_bits));
    SEALContext ctx(parms,true,sec_level_type::tc128); require(ctx.parameters_set(),ctx.parameter_error_message());
    KeyGenerator keys(ctx); PublicKey pk; keys.create_public_key(pk); Encryptor enc(ctx,pk);
    Decryptor dec(ctx,keys.secret_key()); BatchEncoder encoder(ctx); Evaluator eval(ctx);
    {std::ofstream f(outdir/"parameters.json"); params_json(f,p,n,ctx);}
    parallel_stress=mode=="stress"; stress_context=&ctx; stress_public_key=&pk;
    uint64_t seed=argc>7?std::stoull(argv[7]):20261031;
    std::mt19937_64 rng(seed); auto query=random_embedding(rng,p.L,p.gamma);
    bool correctness_failed=false;
    if(mode=="measure") {
        require(!std::filesystem::exists(outdir/"samples.jsonl"),"output exists");
        std::ofstream log(outdir/"samples.jsonl");
        auto templates=make_templates(rng,p,n*p.d-1); auto enrollment=random_embedding(rng,p.L,p.gamma);
        auto tail=encrypt_block(templates,0,p,n,encoder,enc); templates.push_back(enrollment);
        auto oldframe=frame(tail,p,n,compr_mode_type::none); save_file(outdir/"tail.bin",oldframe);
        for(int round=0;round<6;++round) {
            Times et,qt; auto enrollment_ct=encrypt_rows(enrollment,p,n,n*p.d-1,false,encoder,enc,et);
            auto qct=encrypt_rows(query,p,n,0,true,encoder,enc,qt);
            auto start=Clock::now(); auto ef=frame(enrollment_ct,p,n,compr_mode_type::none); double save_ms=elapsed(start);
            start=Clock::now(); auto compressed=frame(enrollment_ct,p,n,Serialization::compr_mode_default); double compress_ms=elapsed(start);
            start=Clock::now(); auto left=unframe(oldframe,ctx,p,n); auto right=unframe(ef,ctx,p,n); double load_ms=elapsed(start);
            start=Clock::now(); for(size_t i=0;i<p.L;++i) eval.add_inplace(left[i],right[i]); double add_ms=elapsed(start);
            start=Clock::now(); auto mf=frame(left,p,n,compr_mode_type::none); double merge_save_ms=elapsed(start);
            // Second participant reconstructs its own context and objects from the same wire bytes.
            SEALContext ctx2(parms,true,sec_level_type::tc128); Evaluator eval2(ctx2);
            auto left2=unframe(oldframe,ctx2,p,n),right2=unframe(ef,ctx2,p,n);
            for(size_t i=0;i<p.L;++i) eval2.add_inplace(left2[i],right2[i]);
            bool equal=frame(left2,p,n,compr_mode_type::none)==mf; require(equal,"independent merge bytes differ");
            start=Clock::now(); auto answer=identify_block(qct,left,p,eval); double query_ms=elapsed(start);
            int budget=dec.invariant_noise_budget(answer); Plaintext plain; dec.decrypt(answer,plain);
            std::vector<int64_t> decoded; encoder.decode(plain,decoded); size_t errors=0,packing_errors=0;
            for(size_t slot=0;slot<p.d;++slot) {
                int64_t expected=0,power=1; std::vector<int64_t> expected_scores;
                for(int layer=0;layer<n;++layer) { auto score=dot(query,templates[layer*p.d+slot]); expected_scores.push_back(score); expected+=power*score; if(layer+1<n) power*=p.T; }
                if(decoded[slot]!=centered_mod_signed(expected,parms.plain_modulus().value())) ++errors;
                auto scores=decompose_scores(decoded[slot],p.T,n); if(scores!=expected_scores) ++packing_errors;
            }
            int rowbudget=std::numeric_limits<int>::max(); for(auto &ct:left) rowbudget=std::min(rowbudget,dec.invariant_noise_budget(ct));
            correctness_failed |= (errors || packing_errors);
            log<<std::setprecision(12)<<"{\"round\":"<<round<<",\"warmup\":"<<(round==0?"true":"false")
               <<",\"enroll_construct_ms\":"<<et.construct<<",\"enroll_encode_ms\":"<<et.encode<<",\"enroll_encrypt_ms\":"<<et.encrypt
               <<",\"query_construct_ms\":"<<qt.construct<<",\"query_encode_ms\":"<<qt.encode<<",\"query_encrypt_ms\":"<<qt.encrypt
               <<",\"save_none_ms\":"<<save_ms<<",\"save_default_ms\":"<<compress_ms<<",\"load_two_ms\":"<<load_ms
               <<",\"add_ms\":"<<add_ms<<",\"save_merge_ms\":"<<merge_save_ms<<",\"query_evaluation_ms\":"<<query_ms
               <<",\"none_bytes\":"<<ef.size()<<",\"default_bytes\":"<<compressed.size()<<",\"framing_bytes\":"<<(40+8*p.L)
               <<",\"ciphertext_size\":"<<left[0].size()<<",\"coeff_modulus_size\":"<<left[0].coeff_modulus_size()
               <<",\"ntt\":"<<(left[0].is_ntt_form()?"true":"false")<<",\"correction_factor\":"<<left[0].correction_factor()
               <<",\"independent_bytes_equal\":true,\"row_noise_min\":"<<rowbudget<<",\"query_noise\":"<<budget
               <<",\"wrong_slots\":"<<errors<<",\"wrong_packed_slots\":"<<packing_errors<<"}\n"; log.flush();
            if(round==1) { save_file(outdir/"enrollment.bin",ef); save_file(outdir/"merged.bin",mf); }
            std::cout<<p.model<<' '<<n<<" round "<<round<<" query noise "<<budget<<" errors "<<errors<<'/'<<packing_errors<<std::endl;
        }
    } else if(mode=="stress") {
        // Full L-row encrypted accumulation, one independent public-key encryption per row/registration.
        // Check at powers of two, at layer boundaries, and at capacity; stop at the first failure.
        require(!std::filesystem::exists(outdir/"stress.jsonl"),"output exists");
        size_t limit=argc>5?std::stoull(argv[5]):n*p.d; limit=std::min(limit,n*p.d);
        require(limit>0,"max enrollments must be positive");
        std::ofstream log(outdir/"stress.jsonl"), progress(outdir/"progress.jsonl"); Times qt;
        auto qct=encrypt_rows(query,p,n,0,true,encoder,enc,qt); std::vector<Ciphertext> block;
        std::vector<int64_t> expected(p.d,0); std::vector<std::vector<int64_t>> scores(p.d,std::vector<int64_t>(n,0));
        std::vector<std::vector<int64_t>> enrolled;
        std::vector<std::vector<int64_t>> expected_rows(p.L,std::vector<int64_t>(p.d,0));
        auto start=Clock::now();
        for(size_t count=1;count<=limit;++count) {
            auto v=random_embedding(rng,p.L,p.gamma);
            // Capacity boundary vectors are admissible normalized axis vectors, not impossible all-Gamma vectors.
            if(count==1 || count==p.d || count==p.d+1 || count==n*p.d) { std::fill(v.begin(),v.end(),0); v[(count-1)%p.L]=count%2?p.gamma:-p.gamma; }
            Times et; auto ct=encrypt_rows(v,p,n,count-1,false,encoder,enc,et);
            if(count==1) block=std::move(ct); else for(size_t i=0;i<p.L;++i) eval.add_inplace(block[i],ct[i]);
            size_t slot=(count-1)%p.d,layer=(count-1)/p.d; int64_t power=1; for(size_t k=0;k<layer;++k) power*=p.T;
            enrolled.push_back(v);
            for(size_t dim=0;dim<p.L;++dim) expected_rows[dim][slot]+=v[dim]*power;
            auto score=dot(query,v); expected[slot]+=power*score; scores[slot][layer]=score;
            if(count==1 || count%64==0 || count==limit) {
                auto handles=process_handles();
                progress<<"{\"enrollments\":"<<count<<",\"process_handles\":"<<handles
                        <<",\"elapsed_ms\":"<<elapsed(start)<<"}\n"; progress.flush();
                require(handles<10000,"runtime handle growth: stopping before resource exhaustion");
            }
            bool checkpoint=(count&(count-1))==0 || count==limit || count%p.d==0 || count%p.d==1;
            if(!checkpoint) continue;
            auto answer=identify_block(qct,block,p,eval); int budget=dec.invariant_noise_budget(answer);
            Plaintext pt; dec.decrypt(answer,pt); std::vector<int64_t> decoded; encoder.decode(pt,decoded);
            size_t errors=0,packing_errors=0; for(size_t j=0;j<p.d;++j) {
                if(decoded[j]!=centered_mod_signed(expected[j],parms.plain_modulus().value())) ++errors;
                if(decompose_scores(decoded[j],p.T,n)!=scores[j]) ++packing_errors;
            }
            int rowbudget=std::numeric_limits<int>::max(); for(auto &c:block) rowbudget=std::min(rowbudget,dec.invariant_noise_budget(c));
            // Diagnose the stage: verify every accumulated row, then compare a fresh
            // encryption of the SAME gallery with the SAME encrypted query.
            // The fresh control is never substituted for the accumulated block.
            size_t row_errors=0;
            for(size_t dim=0;dim<p.L;++dim) {
                dec.decrypt(block[dim],pt); encoder.decode(pt,decoded);
                for(size_t j=0;j<p.d;++j)
                    if(decoded[j]!=centered_mod_signed(expected_rows[dim][j],parms.plain_modulus().value())) ++row_errors;
            }
            auto fresh=encrypt_block(enrolled,0,p,n,encoder,enc);
            auto fresh_answer=identify_block(qct,fresh,p,eval);
            int fresh_budget=dec.invariant_noise_budget(fresh_answer);
            dec.decrypt(fresh_answer,pt); encoder.decode(pt,decoded);
            size_t fresh_errors=0,fresh_packing_errors=0;
            for(size_t j=0;j<p.d;++j) {
                if(decoded[j]!=centered_mod_signed(expected[j],parms.plain_modulus().value())) ++fresh_errors;
                if(decompose_scores(decoded[j],p.T,n)!=scores[j]) ++fresh_packing_errors;
            }
            log<<std::setprecision(12)<<"{\"enrollments\":"<<count<<",\"merges\":"<<count-1<<",\"capacity\":"<<n*p.d
               <<",\"row_noise_min\":"<<rowbudget<<",\"query_noise\":"<<budget<<",\"wrong_slots\":"<<errors
               <<",\"wrong_packed_slots\":"<<packing_errors<<",\"wrong_row_slots\":"<<row_errors
               <<",\"fresh_query_noise\":"<<fresh_budget<<",\"fresh_wrong_slots\":"<<fresh_errors
               <<",\"fresh_wrong_packed_slots\":"<<fresh_packing_errors<<",\"process_handles\":"<<process_handles()
               <<",\"elapsed_ms\":"<<elapsed(start)<<"}\n"; log.flush();
            std::cout<<p.model<<' '<<n<<" count "<<count<<" noise "<<budget<<" errors "<<errors<<'/'<<packing_errors<<std::endl;
            if(errors || packing_errors || row_errors || fresh_errors || fresh_packing_errors) { correctness_failed=true; break; }
        }
    } else throw std::runtime_error("unknown mode");
    // Decoding failure must not look like a successful executable/test run.
    return correctness_failed ? 2 : 0;
 } catch(const std::exception &e) { std::cerr<<e.what()<<std::endl; return 1; }
}
