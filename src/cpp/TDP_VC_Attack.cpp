#include <bits/stdc++.h>
using namespace std;

/*
 * TDP-VC reproduction + robustness attacks
 * Protocol reproduced from SIGMOD 2025 "Robust Privacy-Preserving Triangle Counting under Edge LDP".
 * Only TDP-VC is implemented.
 *
 * Main protocol:
 *   Round 1: d_tilde(u) = deg(u) + Lap(1/eps0) + alpha
 *   Round 2: randomized response on the lower triangle of adjacency matrix to construct A'
 *   Round 3: for each u, sample at most d_tilde(u) true neighbors from N(u), enumerate wedges
 *            centered at u, add phi(v,w), and add Lap(GS(f_u)/eps2)
 *            where phi(v,w)=(A'[v,w]*(1+exp(eps1))-1)/(exp(eps1)-1)
 *            and GS(f_u)=d_tilde(u)*exp(eps1)/(exp(eps1)-1)
 *   Return Delta_hat / 3.
 *
 * Attack modes:
 *   none
 *   orig_inc / orig_dec       : before protocol, add/delete edges among malicious users with probability poison_prob
 *   rr_inc / rr_dec           : after RR, force A'[i,j]=1/0 among malicious user pairs with probability poison_prob
 *   lap_fixed_inc/dec         : after normal Laplace report, malicious vertices add +/- fixed_offset with prob poison_prob
 *   lap_scale_inc/dec         : add +/- scale_k * (GS_u/eps2) with prob poison_prob
 *   lap_local_inc/dec         : add +/- local_k * max(|local_sum_before_lap|,1) with prob poison_prob
 *
 * Notes:
 *   - Use --n to reproduce prior experiments on the first n nodes.
 *   - For arbitrary node IDs, use --remap 1. For already-renumbered 0..n-1 datasets, use --remap 0.
 *   - For files whose first non-comment line is "n m", use --has_header 1.
 */

struct Config {
    string input = "";
    string output = "tdp_vc_results.csv";
    int n = -1;
    int runs = 5;
    double epsilon = 1.0;
    double alpha = 150.0;
    double eps0_ratio = 0.1;
    string budget_mode = "auto";      // auto or fixed
    double eps1_total_ratio = -1.0;    // for fixed mode: eps1 = eps1_total_ratio * epsilon; default=(epsilon-eps0)/2
    string attack_mode = "none";
    double malicious_ratio = 0.0;
    double poison_prob = 1.0;
    double fixed_offset = 10000.0;
    double scale_k = 3.0;
    double local_k = 0.5;
    uint64_t seed = 1;
    bool remap = false;
    bool has_header = false;
    bool compute_exact_after_original_attack = true;
    bool verbose = true;
};

struct RunStats {
    int run = 0;
    double eps0 = 0, eps1 = 0, eps2 = 0;
    long long clean_edges = 0, protocol_edges = 0;
    long long clean_tri = 0, protocol_tri = 0;
    double estimate = 0;
    double rel_err_clean = 0, rel_err_protocol = 0;
    long long orig_edge_changes = 0;
    long long rr_changes = 0;
    long long lap_attacked_reports = 0;
    double lap_total_offset = 0;
    double seconds = 0;
};

static inline bool starts_with(const string &s, const string &p) {
    return s.rfind(p, 0) == 0;
}

static void usage() {
    cerr << "Usage: ./tdp_vc_attack --input graph.txt --n 10000 --epsilon 1.0 --runs 5 --attack none [options]\n";
    cerr << "Options:\n"
         << "  --out results.csv\n"
         << "  --alpha 150\n"
         << "  --eps0_ratio 0.1\n"
         << "  --budget_mode auto|fixed\n"
         << "  --eps1_total_ratio 0.45   (fixed mode only; if omitted, eps1=(eps-eps0)/2)\n"
         << "  --attack none|orig_inc|orig_dec|rr_inc|rr_dec|lap_fixed_inc|lap_fixed_dec|lap_scale_inc|lap_scale_dec|lap_local_inc|lap_local_dec\n"
         << "  --malicious_ratio 0.10\n"
         << "  --poison_prob 1.0\n"
         << "  --fixed_offset 10000\n"
         << "  --scale_k 3\n"
         << "  --local_k 0.5\n"
         << "  --seed 1\n"
         << "  --remap 0|1\n"
         << "  --has_header 0|1\n";
}

static Config parse_args(int argc, char **argv) {
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        string k = argv[i];
        auto need = [&](const string &key) -> string {
            if (i + 1 >= argc) {
                cerr << "Missing value for " << key << "\n";
                usage();
                exit(1);
            }
            return string(argv[++i]);
        };
        if (k == "--input") cfg.input = need(k);
        else if (k == "--out") cfg.output = need(k);
        else if (k == "--n") cfg.n = stoi(need(k));
        else if (k == "--runs") cfg.runs = stoi(need(k));
        else if (k == "--epsilon") cfg.epsilon = stod(need(k));
        else if (k == "--alpha") cfg.alpha = stod(need(k));
        else if (k == "--eps0_ratio") cfg.eps0_ratio = stod(need(k));
        else if (k == "--budget_mode") cfg.budget_mode = need(k);
        else if (k == "--eps1_total_ratio") cfg.eps1_total_ratio = stod(need(k));
        else if (k == "--attack") cfg.attack_mode = need(k);
        else if (k == "--malicious_ratio") cfg.malicious_ratio = stod(need(k));
        else if (k == "--poison_prob") cfg.poison_prob = stod(need(k));
        else if (k == "--fixed_offset") cfg.fixed_offset = stod(need(k));
        else if (k == "--scale_k") cfg.scale_k = stod(need(k));
        else if (k == "--local_k") cfg.local_k = stod(need(k));
        else if (k == "--seed") cfg.seed = stoull(need(k));
        else if (k == "--remap") cfg.remap = (stoi(need(k)) != 0);
        else if (k == "--has_header") cfg.has_header = (stoi(need(k)) != 0);
        else if (k == "--verbose") cfg.verbose = (stoi(need(k)) != 0);
        else if (k == "--help" || k == "-h") { usage(); exit(0); }
        else {
            cerr << "Unknown option: " << k << "\n";
            usage();
            exit(1);
        }
    }
    if (cfg.input.empty()) {
        cerr << "--input is required\n";
        usage();
        exit(1);
    }
    if (cfg.n <= 0 && !cfg.remap) {
        cerr << "--n must be positive when --remap 0\n";
        exit(1);
    }
    if (cfg.epsilon <= 0) {
        cerr << "epsilon must be positive\n";
        exit(1);
    }
    if (cfg.eps0_ratio <= 0 || cfg.eps0_ratio >= 1) {
        cerr << "eps0_ratio must be in (0,1)\n";
        exit(1);
    }
    if (cfg.malicious_ratio < 0 || cfg.malicious_ratio > 1 || cfg.poison_prob < 0 || cfg.poison_prob > 1) {
        cerr << "malicious_ratio and poison_prob must be in [0,1]\n";
        exit(1);
    }
    return cfg;
}

struct Graph {
    int n = 0;
    vector<vector<int>> adj;
    unordered_set<unsigned long long> edges;
};

static inline unsigned long long edge_key(int u, int v) {
    if (u > v) swap(u, v);
    return (static_cast<unsigned long long>(static_cast<unsigned int>(u)) << 32) |
           static_cast<unsigned int>(v);
}

static inline bool has_edge(const unordered_set<unsigned long long> &edges, int u, int v) {
    if (u == v) return false;
    return edges.find(edge_key(u, v)) != edges.end();
}

static inline bool add_edge_set(unordered_set<unsigned long long> &edges, int u, int v) {
    if (u == v) return false;
    return edges.insert(edge_key(u, v)).second;
}

static inline bool remove_edge_set(unordered_set<unsigned long long> &edges, int u, int v) {
    if (u == v) return false;
    return edges.erase(edge_key(u, v)) > 0;
}

static vector<long long> parse_ints_from_line(const string &line) {
    vector<long long> res;
    char *endp = nullptr;
    const char *s = line.c_str();
    while (*s) {
        while (*s && !(isdigit(*s) || *s == '-' || *s == '+')) ++s;
        if (!*s) break;
        long long val = strtoll(s, &endp, 10);
        if (endp == s) break;
        res.push_back(val);
        s = endp;
    }
    return res;
}

static void rebuild_adj(Graph &g) {
    g.adj.assign(g.n, {});
    for (auto key : g.edges) {
        int u = static_cast<int>(key >> 32);
        int v = static_cast<int>(key & 0xffffffffULL);
        if (u >= 0 && u < g.n && v >= 0 && v < g.n && u != v) {
            g.adj[u].push_back(v);
            g.adj[v].push_back(u);
        }
    }
    for (auto &vec : g.adj) {
        sort(vec.begin(), vec.end());
        vec.erase(unique(vec.begin(), vec.end()), vec.end());
    }
}

static Graph load_graph(const Config &cfg) {
    ifstream fin(cfg.input);
    if (!fin) {
        cerr << "Cannot open input file: " << cfg.input << "\n";
        exit(1);
    }

    Graph g;
    g.n = cfg.n;
    unordered_map<long long, int> idmap;
    idmap.reserve(cfg.n > 0 ? cfg.n * 2 : 1000000);

    string line;
    bool header_skipped = false;
    long long read_edges = 0, kept_edges = 0;
    while (getline(fin, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto vals = parse_ints_from_line(line);
        if (vals.size() < 2) continue;
        if (cfg.has_header && !header_skipped) {
            header_skipped = true;
            if (g.n <= 0) g.n = static_cast<int>(vals[0]);
            continue;
        }
        long long a = vals[0], b = vals[1];
        ++read_edges;
        int u, v;
        if (cfg.remap) {
            auto get_id = [&](long long x) -> int {
                auto it = idmap.find(x);
                if (it != idmap.end()) return it->second;
                if (g.n > 0 && static_cast<int>(idmap.size()) >= g.n) return -1;
                int nid = static_cast<int>(idmap.size());
                idmap[x] = nid;
                return nid;
            };
            u = get_id(a);
            v = get_id(b);
            if (u < 0 || v < 0) continue;
        } else {
            u = static_cast<int>(a);
            v = static_cast<int>(b);
            if (u < 0 || v < 0 || u >= g.n || v >= g.n) continue;
        }
        if (u == v) continue;
        if (add_edge_set(g.edges, u, v)) ++kept_edges;
    }
    if (cfg.remap && g.n <= 0) g.n = static_cast<int>(idmap.size());
    rebuild_adj(g);
    cerr << "[Load] n=" << g.n << " edges=" << g.edges.size() << " read_lines=" << read_edges
         << " kept_unique=" << kept_edges << " remap=" << cfg.remap << "\n";
    return g;
}

static long long count_triangles_forward(const Graph &g) {
    vector<int> deg(g.n);
    for (int i = 0; i < g.n; ++i) deg[i] = static_cast<int>(g.adj[i].size());

    vector<vector<int>> out(g.n);
    out.assign(g.n, {});
    for (auto key : g.edges) {
        int u = static_cast<int>(key >> 32);
        int v = static_cast<int>(key & 0xffffffffULL);
        bool u_before_v = (deg[u] < deg[v]) || (deg[u] == deg[v] && u < v);
        if (u_before_v) out[u].push_back(v);
        else out[v].push_back(u);
    }
    for (auto &x : out) sort(x.begin(), x.end());

    vector<int> mark(g.n, 0);
    int token = 1;
    long long tri = 0;
    for (int u = 0; u < g.n; ++u) {
        ++token;
        if (token == INT_MAX) {
            fill(mark.begin(), mark.end(), 0);
            token = 1;
        }
        for (int v : out[u]) mark[v] = token;
        for (int v : out[u]) {
            for (int w : out[v]) {
                if (mark[w] == token) ++tri;
            }
        }
    }
    return tri;
}

static vector<char> choose_malicious(int n, double ratio, mt19937_64 &rng) {
    vector<char> mal(n, 0);
    int cnt = static_cast<int>(floor(n * ratio + 1e-12));
    for (int i = 0; i < cnt; ++i) mal[i] = 1;
    shuffle(mal.begin(), mal.end(), rng);
    return mal;
}

static vector<int> malicious_list(const vector<char> &mal) {
    vector<int> ids;
    for (int i = 0; i < static_cast<int>(mal.size()); ++i) if (mal[i]) ids.push_back(i);
    return ids;
}

static bool is_orig_attack(const string &m) { return m == "orig_inc" || m == "orig_dec"; }
static bool is_rr_attack(const string &m) { return m == "rr_inc" || m == "rr_dec"; }
static bool is_lap_attack(const string &m) {
    return starts_with(m, "lap_fixed_") || starts_with(m, "lap_scale_") || starts_with(m, "lap_local_");
}
static int attack_sign(const string &m) { return (m.find("_dec") != string::npos) ? -1 : 1; }

static long long apply_original_attack(Graph &g, const vector<int> &mal_ids, const Config &cfg, mt19937_64 &rng) {
    if (!is_orig_attack(cfg.attack_mode)) return 0;
    uniform_real_distribution<double> U(0.0, 1.0);
    bool inc = (cfg.attack_mode == "orig_inc");
    long long changes = 0;
    for (size_t a = 0; a < mal_ids.size(); ++a) {
        int u = mal_ids[a];
        for (size_t b = a + 1; b < mal_ids.size(); ++b) {
            int v = mal_ids[b];
            if (U(rng) > cfg.poison_prob) continue;
            if (inc) {
                if (add_edge_set(g.edges, u, v)) ++changes;
            } else {
                if (remove_edge_set(g.edges, u, v)) ++changes;
            }
        }
    }
    rebuild_adj(g);
    return changes;
}

static inline size_t lower_index(int i, int j) {
    // requires i > j, zero-based lower triangle index
    return static_cast<size_t>(static_cast<unsigned long long>(i) * static_cast<unsigned long long>(i - 1) / 2ULL + static_cast<unsigned long long>(j));
}

static inline unsigned char get_lower_val(const vector<unsigned char> &lower, int u, int v) {
    if (u == v) return 0;
    if (u < v) swap(u, v);
    return lower[lower_index(u, v)];
}

static inline void set_lower_val(vector<unsigned char> &lower, int u, int v, unsigned char val) {
    if (u == v) return;
    if (u < v) swap(u, v);
    lower[lower_index(u, v)] = val;
}

static double laplace_noise(double scale, mt19937_64 &rng) {
    if (scale <= 0) return 0.0;
    uniform_real_distribution<double> U(0.0, 1.0);
    double u = U(rng) - 0.5;
    return -scale * ((u < 0) ? -1.0 : 1.0) * log(1.0 - 2.0 * fabs(u));
}

static pair<double,double> choose_budget(double epsilon, double eps0, const vector<double> &dtilde, const Config &cfg) {
    double remain = epsilon - eps0;
    if (remain <= 1e-12) {
        cerr << "Invalid budget: epsilon - eps0 <= 0\n";
        exit(1);
    }
    if (cfg.budget_mode == "fixed") {
        double eps1;
        if (cfg.eps1_total_ratio > 0) eps1 = cfg.eps1_total_ratio * epsilon;
        else eps1 = remain / 2.0;
        eps1 = max(1e-9, min(remain - 1e-9, eps1));
        return {eps1, remain - eps1};
    }

    // Data-driven allocation according to the L2 bound in Theorem 3.
    // The paper uses Newton's method; here we minimize the same bound numerically for robustness.
    double dmax = 0.0, sumd2 = 0.0;
    int n = static_cast<int>(dtilde.size());
    for (double x : dtilde) {
        double d = max(0.0, x);
        dmax = max(dmax, d);
        sumd2 += d * d;
    }
    dmax = max(dmax, 1.0);
    sumd2 = max(sumd2, 1.0);

    auto F = [&](double e1) -> double {
        double e2 = remain - e1;
        if (e1 <= 0 || e2 <= 0) return numeric_limits<double>::infinity();
        double ee = exp(e1);
        double den = (ee - 1.0) * (ee - 1.0);
        if (den <= 0) return numeric_limits<double>::infinity();
        double term1 = ee * static_cast<double>(n) * dmax * dmax * dmax / (9.0 * den);
        double term2 = 2.0 * ee * ee * sumd2 / (9.0 * den * e2 * e2);
        return term1 + term2;
    };

    double lo = max(1e-6, remain * 1e-5);
    double hi = remain - max(1e-6, remain * 1e-5);
    if (hi <= lo) return {remain / 2.0, remain / 2.0};

    const int GRID = 1000;
    double best_e = lo, best_f = F(lo);
    for (int k = 1; k <= GRID; ++k) {
        double e = lo + (hi - lo) * k / GRID;
        double val = F(e);
        if (val < best_f) { best_f = val; best_e = e; }
    }
    double step = (hi - lo) / GRID;
    double a = max(lo, best_e - 2 * step);
    double b = min(hi, best_e + 2 * step);
    for (int it = 0; it < 100; ++it) {
        double m1 = a + (b - a) / 3.0;
        double m2 = b - (b - a) / 3.0;
        if (F(m1) < F(m2)) b = m2;
        else a = m1;
    }
    double eps1 = (a + b) / 2.0;
    return {eps1, remain - eps1};
}

static vector<double> degree_estimation_round(const Graph &g, double eps0, double alpha, mt19937_64 &rng) {
    vector<double> dtilde(g.n);
    double scale = 1.0 / eps0;
    for (int u = 0; u < g.n; ++u) {
        dtilde[u] = static_cast<double>(g.adj[u].size()) + laplace_noise(scale, rng) + alpha;
        if (dtilde[u] < 0.0) dtilde[u] = 0.0;
    }
    return dtilde;
}

static vector<unsigned char> rr_round(const Graph &g, double eps1, mt19937_64 &rng) {
    unsigned long long entries = static_cast<unsigned long long>(g.n) * static_cast<unsigned long long>(g.n - 1) / 2ULL;
    if (entries > static_cast<unsigned long long>(numeric_limits<size_t>::max())) {
        cerr << "n too large for lower-triangle vector on this machine. n=" << g.n << "\n";
        exit(1);
    }
    vector<unsigned char> lower(static_cast<size_t>(entries), 0);
    double p = 1.0 / (exp(eps1) + 1.0);
    uniform_real_distribution<double> U(0.0, 1.0);
    for (int i = 0; i < g.n; ++i) {
        for (int j = 0; j < i; ++j) {
            unsigned char x = has_edge(g.edges, i, j) ? 1 : 0;
            unsigned char y = (U(rng) < p) ? static_cast<unsigned char>(1 - x) : x;
            lower[lower_index(i, j)] = y;
        }
    }
    return lower;
}

static long long apply_rr_attack(vector<unsigned char> &lower, const vector<int> &mal_ids, const Config &cfg, mt19937_64 &rng) {
    if (!is_rr_attack(cfg.attack_mode)) return 0;
    uniform_real_distribution<double> U(0.0, 1.0);
    unsigned char target = (cfg.attack_mode == "rr_inc") ? 1 : 0;
    long long changes = 0;
    for (size_t a = 0; a < mal_ids.size(); ++a) {
        int u = mal_ids[a];
        for (size_t b = a + 1; b < mal_ids.size(); ++b) {
            int v = mal_ids[b];
            if (U(rng) > cfg.poison_prob) continue;
            unsigned char oldv = get_lower_val(lower, u, v);
            if (oldv != target) {
                set_lower_val(lower, u, v, target);
                ++changes;
            }
        }
    }
    return changes;
}

static vector<int> sample_neighbors_cap(const vector<int> &neigh, int cap, mt19937_64 &rng) {
    if (cap <= 0) return {};
    if (cap >= static_cast<int>(neigh.size())) return neigh;
    vector<int> s = neigh;
    // Partial Fisher-Yates for cap samples without replacement
    for (int i = 0; i < cap; ++i) {
        uniform_int_distribution<int> D(i, static_cast<int>(s.size()) - 1);
        int r = D(rng);
        swap(s[i], s[r]);
    }
    s.resize(cap);
    sort(s.begin(), s.end());
    return s;
}

static double phi_from_noisy(unsigned char y, double eps1) {
    double ee = exp(eps1);
    return (static_cast<double>(y) * (1.0 + ee) - 1.0) / (ee - 1.0);
}

static double tdp_vc_estimate(const Graph &g, const vector<unsigned char> &lower, const vector<double> &dtilde,
                              double eps1, double eps2, const vector<char> &mal, const Config &cfg,
                              mt19937_64 &rng, RunStats &stats) {
    double ee = exp(eps1);
    double phi_denom = ee - 1.0;
    if (phi_denom <= 0 || eps2 <= 0) {
        cerr << "Invalid eps1/eps2 in TDP-VC estimation.\n";
        exit(1);
    }
    uniform_real_distribution<double> U(0.0, 1.0);
    double total = 0.0;
    for (int u = 0; u < g.n; ++u) {
        int cap = static_cast<int>(floor(max(0.0, dtilde[u])));
        vector<int> Nu = sample_neighbors_cap(g.adj[u], cap, rng);
        double local_sum = 0.0;
        int sz = static_cast<int>(Nu.size());
        for (int a = 0; a < sz; ++a) {
            int v = Nu[a];
            for (int b = a + 1; b < sz; ++b) {
                int w = Nu[b];
                unsigned char y = get_lower_val(lower, v, w);
                local_sum += (static_cast<double>(y) * (1.0 + ee) - 1.0) / phi_denom;
            }
        }
        double gs = max(0.0, dtilde[u]) * ee / phi_denom;
        double scale = gs / eps2;
        double report = local_sum + laplace_noise(scale, rng);

        if (is_lap_attack(cfg.attack_mode) && mal[u] && U(rng) <= cfg.poison_prob) {
            int sgn = attack_sign(cfg.attack_mode);
            double offset = 0.0;
            if (starts_with(cfg.attack_mode, "lap_fixed_")) {
                offset = cfg.fixed_offset;
            } else if (starts_with(cfg.attack_mode, "lap_scale_")) {
                offset = cfg.scale_k * scale;
            } else if (starts_with(cfg.attack_mode, "lap_local_")) {
                offset = cfg.local_k * max(fabs(local_sum), 1.0);
            }
            report += sgn * offset;
            stats.lap_attacked_reports++;
            stats.lap_total_offset += sgn * offset;
        }
        total += report;
    }
    return total / 3.0;
}

static void write_header_if_needed(const string &out) {
    bool exists = false;
    {
        ifstream f(out);
        exists = f.good() && f.peek() != ifstream::traits_type::eof();
    }
    if (!exists) {
        ofstream fout(out, ios::app);
        fout << "run,attack,epsilon,eps0,eps1,eps2,alpha,malicious_ratio,malicious_count,poison_prob,"
             << "fixed_offset,scale_k,local_k,clean_edges,protocol_edges,clean_triangles,protocol_triangles,"
             << "estimate,rel_error_clean,rel_error_protocol,orig_edge_changes,rr_changes,lap_attacked_reports,lap_total_offset,seconds\n";
    }
}

static void append_result(const string &out, const Config &cfg, const RunStats &s, int malicious_count) {
    write_header_if_needed(out);
    ofstream fout(out, ios::app);
    fout.setf(std::ios::fixed); fout << setprecision(10);
    fout << s.run << ',' << cfg.attack_mode << ',' << cfg.epsilon << ',' << s.eps0 << ',' << s.eps1 << ',' << s.eps2 << ','
         << cfg.alpha << ',' << cfg.malicious_ratio << ',' << malicious_count << ',' << cfg.poison_prob << ','
         << cfg.fixed_offset << ',' << cfg.scale_k << ',' << cfg.local_k << ','
         << s.clean_edges << ',' << s.protocol_edges << ',' << s.clean_tri << ',' << s.protocol_tri << ','
         << s.estimate << ',' << s.rel_err_clean << ',' << s.rel_err_protocol << ','
         << s.orig_edge_changes << ',' << s.rr_changes << ',' << s.lap_attacked_reports << ',' << s.lap_total_offset << ','
         << s.seconds << "\n";
}

int main(int argc, char **argv) {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    Config cfg = parse_args(argc, argv);
    Graph clean = load_graph(cfg);
    long long clean_tri = count_triangles_forward(clean);
    long long clean_edges = static_cast<long long>(clean.edges.size());
    cerr << "[Exact clean] triangles=" << clean_tri << " edges=" << clean_edges << "\n";

    for (int r = 0; r < cfg.runs; ++r) {
        auto start = chrono::steady_clock::now();
        mt19937_64 rng(cfg.seed + 1000003ULL * static_cast<uint64_t>(r));
        RunStats stats;
        stats.run = r;
        stats.clean_edges = clean_edges;
        stats.clean_tri = clean_tri;

        vector<char> mal = choose_malicious(clean.n, cfg.malicious_ratio, rng);
        vector<int> mal_ids = malicious_list(mal);

        Graph protocol_g = clean;
        stats.orig_edge_changes = apply_original_attack(protocol_g, mal_ids, cfg, rng);
        stats.protocol_edges = static_cast<long long>(protocol_g.edges.size());
        if (is_orig_attack(cfg.attack_mode) && cfg.compute_exact_after_original_attack) {
            stats.protocol_tri = count_triangles_forward(protocol_g);
        } else {
            stats.protocol_tri = clean_tri;
        }

        stats.eps0 = cfg.epsilon * cfg.eps0_ratio;
        vector<double> dtilde = degree_estimation_round(protocol_g, stats.eps0, cfg.alpha, rng);
        auto budgets = choose_budget(cfg.epsilon, stats.eps0, dtilde, cfg);
        stats.eps1 = budgets.first;
        stats.eps2 = budgets.second;

        vector<unsigned char> lower = rr_round(protocol_g, stats.eps1, rng);
        stats.rr_changes = apply_rr_attack(lower, mal_ids, cfg, rng);
        stats.estimate = tdp_vc_estimate(protocol_g, lower, dtilde, stats.eps1, stats.eps2, mal, cfg, rng, stats);

        stats.rel_err_clean = (stats.clean_tri == 0) ? fabs(stats.estimate - stats.clean_tri) : fabs(stats.estimate - stats.clean_tri) / fabs(static_cast<double>(stats.clean_tri));
        stats.rel_err_protocol = (stats.protocol_tri == 0) ? fabs(stats.estimate - stats.protocol_tri) : fabs(stats.estimate - stats.protocol_tri) / fabs(static_cast<double>(stats.protocol_tri));

        auto end = chrono::steady_clock::now();
        stats.seconds = chrono::duration<double>(end - start).count();
        append_result(cfg.output, cfg, stats, static_cast<int>(mal_ids.size()));

        if (cfg.verbose) {
            cerr.setf(std::ios::fixed); cerr << setprecision(6);
            cerr << "[Run " << r << "] attack=" << cfg.attack_mode
                 << " eps=(" << stats.eps0 << ',' << stats.eps1 << ',' << stats.eps2 << ')'
                 << " mal=" << mal_ids.size()
                 << " changed_orig=" << stats.orig_edge_changes
                 << " changed_rr=" << stats.rr_changes
                 << " lap_reports=" << stats.lap_attacked_reports
                 << " est=" << stats.estimate
                 << " rel_clean=" << stats.rel_err_clean
                 << " rel_protocol=" << stats.rel_err_protocol
                 << " time=" << stats.seconds << "s\n";
        }
    }
    cerr << "[Done] Results appended to " << cfg.output << "\n";
    return 0;
}
