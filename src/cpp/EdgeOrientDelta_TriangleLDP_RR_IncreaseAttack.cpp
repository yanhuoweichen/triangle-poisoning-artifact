#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace std;

struct Timer {
    chrono::steady_clock::time_point t;
    Timer() : t(chrono::steady_clock::now()) {}
    double reset() {
        auto now = chrono::steady_clock::now();
        double sec = chrono::duration<double>(now - t).count();
        t = now;
        return sec;
    }
    double elapsed() const {
        return chrono::duration<double>(chrono::steady_clock::now() - t).count();
    }
};

static inline string trim(const string &s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

static inline double log_base(double a, double b) {
    if (a <= 1.0) return 1.0;
    return log(a) / log(b);
}

class RandomGen {
public:
    explicit RandomGen(uint64_t seed) : rng(seed), uni(0.0, 1.0) {}

    double uniform01() { return uni(rng); }

    // Symmetric geometric / discrete Laplace noise.
    // P(X=0)=(1-alpha)/(1+alpha), P(X=+-k)=((1-alpha)/(1+alpha))*alpha^k, k>=1,
    // where alpha=exp(-lambda). Larger lambda means smaller noise.
    long long twoSidedGeometric(double lambda) {
        if (!(lambda > 0.0) || !isfinite(lambda)) return 0;
        double alpha = exp(-lambda);
        if (alpha <= 0.0) return 0;
        if (alpha >= 1.0) alpha = nextafter(1.0, 0.0);
        double p0 = (1.0 - alpha) / (1.0 + alpha);
        double u = uniform01();
        if (u < p0) return 0;
        double v = uniform01();
        // Geometric over {1,2,...}: P(K=k)=(1-alpha)*alpha^(k-1)
        long long mag = 1 + static_cast<long long>(floor(log(max(1e-300, 1.0 - v)) / log(alpha)));
        if (mag < 1) mag = 1;
        return (uniform01() < 0.5) ? -mag : mag;
    }

    double laplace(double scale) {
        if (!(scale > 0.0) || !isfinite(scale)) return 0.0;
        double u = uniform01() - 0.5;
        double sgn = (u < 0.0) ? -1.0 : 1.0;
        return -scale * sgn * log(1.0 - 2.0 * fabs(u));
    }

public:
    template <class T>
    void shuffleVec(vector<T> &v) {
        shuffle(v.begin(), v.end(), rng);
    }

private:
    mt19937_64 rng;
    uniform_real_distribution<double> uni;
};

struct Graph {
    int n_header = 0;
    int n = 0;
    long long m = 0;
    vector<vector<int>> adj;
    vector<unordered_set<int>> adj_set;
};

struct RRAttackConfig {
    bool enabled = false;
    bool force_one = true;              // true: increase attack; false: decrease attack
    double malicious_ratio = 0.0;       // controlled existing users / all users
    double poison_prob = 1.0;           // probability to override an RR output bit
    string selection = "random";        // random | high_degree | low_degree
    string owner_mode = "reporter";     // reporter | either
    string attack_type = "rr_increase";
};

struct RRAttackStats {
    int malicious_nodes = 0;
    long long attack_candidates = 0; // RR bits whose owner/endpoint is malicious
    long long poisoned_bits = 0;     // RR bits actually overridden
    long long forced_one = 0;
    long long forced_zero = 0;
};

static vector<uint8_t> selectMaliciousUsers(const Graph &g, const RRAttackConfig &cfg, RandomGen &rng, int &mal_cnt_out) {
    int n = g.n;
    int mal_cnt = (int)floor((double)n * cfg.malicious_ratio + 1e-12);
    if (mal_cnt < 0) mal_cnt = 0;
    if (mal_cnt > n) mal_cnt = n;
    mal_cnt_out = mal_cnt;

    vector<int> ids(n);
    iota(ids.begin(), ids.end(), 0);

    if (cfg.selection == "high_degree") {
        sort(ids.begin(), ids.end(), [&](int a, int b) {
            if (g.adj[a].size() != g.adj[b].size()) return g.adj[a].size() > g.adj[b].size();
            return a < b;
        });
    } else if (cfg.selection == "low_degree") {
        sort(ids.begin(), ids.end(), [&](int a, int b) {
            if (g.adj[a].size() != g.adj[b].size()) return g.adj[a].size() < g.adj[b].size();
            return a < b;
        });
    } else {
        rng.shuffleVec(ids);
    }

    vector<uint8_t> malicious(n, 0);
    for (int i = 0; i < mal_cnt; ++i) malicious[ids[i]] = 1;
    return malicious;
}


static Graph readTriangleLDPEdges(const string &edgeFile, int nArg) {
    ifstream fin(edgeFile.c_str());
    if (!fin) {
        throw runtime_error("Cannot open edge file: " + edgeFile);
    }

    string line;
    int headerN = -1;
    vector<pair<int,int>> edges;
    int maxNode = -1;

    // TriangleLDP format:
    // #nodes
    // 107614
    // node,node
    // u,v
    // ...
    bool afterNodesTag = false;
    while (getline(fin, line)) {
        line = trim(line);
        if (line.empty()) continue;
        if (line == "#nodes") {
            afterNodesTag = true;
            continue;
        }
        if (afterNodesTag) {
            headerN = atoi(line.c_str());
            afterNodesTag = false;
            continue;
        }
        if (line.find("node") != string::npos || line[0] == '#') continue;

        for (char &c : line) {
            if (c == ',') c = ' ';
        }
        stringstream ss(line);
        int u, v;
        if (!(ss >> u >> v)) continue;
        if (u == v) continue;
        maxNode = max(maxNode, max(u, v));
        edges.emplace_back(u, v);
    }

    int n = nArg;
    if (n <= 0) {
        if (headerN > 0) n = headerN;
        else n = maxNode + 1;
    }
    if (n <= 0) throw runtime_error("Invalid node number. Use n>0 or provide a valid #nodes header.");

    Graph g;
    g.n_header = (headerN > 0) ? headerN : (maxNode + 1);
    g.n = n;
    g.adj.assign(n, {});
    g.adj_set.assign(n, {});

    for (auto &e : edges) {
        int u = e.first, v = e.second;
        if (u < 0 || v < 0 || u >= n || v >= n) continue;
        if (g.adj_set[u].insert(v).second) {
            g.adj[u].push_back(v);
            g.adj_set[v].insert(u);
            g.adj[v].push_back(u);
            g.m++;
        }
    }
    for (int i = 0; i < n; ++i) sort(g.adj[i].begin(), g.adj[i].end());
    return g;
}

static long long exactTriangleCount(const Graph &g) {
    // Degeneracy-style orientation by (degree, id), then intersect forward adjacency.
    int n = g.n;
    vector<int> deg(n);
    for (int i = 0; i < n; ++i) deg[i] = (int)g.adj[i].size();

    vector<vector<int>> out(n);
    for (int u = 0; u < n; ++u) {
        out[u].reserve(g.adj[u].size());
        for (int v : g.adj[u]) {
            if (deg[u] < deg[v] || (deg[u] == deg[v] && u < v)) out[u].push_back(v);
        }
        sort(out[u].begin(), out[u].end());
    }

    long long tri = 0;
    for (int u = 0; u < n; ++u) {
        const vector<int> &A = out[u];
        for (int v : A) {
            const vector<int> &B = out[v];
            size_t i = 0, j = 0;
            while (i < A.size() && j < B.size()) {
                if (A[i] == B[j]) { tri++; i++; j++; }
                else if (A[i] < B[j]) i++;
                else j++;
            }
        }
    }
    return tri;
}

struct KCoreDResult {
    vector<int> level;
    vector<double> core_est;
    int rounds_cap = 0;
    int rounds_run = 0;
    int max_threshold = 0;
    double levels_per_group = 1.0;
};

static KCoreDResult runKCoreD(
    const Graph &g,
    double psi,
    double epsilon_phase,
    double split_factor,
    bool use_noise,
    int bias_factor,
    RandomGen &rng
) {
    const int n = g.n;
    const double base = 1.0 + psi;
    const double logn = max(1.0, log_base(max(2, n), base));
    const double levels_per_group = max(1.0, ceil(logn) / 4.0);
    const int rounds_cap = max(1, (int)ceil(4.0 * pow(logn, 1.2)));

    const double eps1 = epsilon_phase * split_factor;
    const double eps2 = epsilon_phase * (1.0 - split_factor);

    vector<int> level(n, 0), permanent_zero(n, 1), threshold(n, 1);
    int maxThreshold = 0;

    for (int v = 0; v < n; ++v) {
        long long noisy_degree = (long long)g.adj[v].size();
        if (use_noise) {
            double lambda = eps1 / 2.0;
            noisy_degree += rng.twoSidedGeometric(lambda);
            double denom = exp(2.0 * lambda) - 1.0;
            double bias = 0.0;
            if (fabs(denom) > 1e-300) bias = (double)bias_factor * (2.0 * exp(lambda)) / denom;
            // Port of the Go implementation: subtract min(bias, noisy_degree), then add 1.
            noisy_degree -= (long long)floor(min(bias, (double)noisy_degree));
            noisy_degree += 1;
        }
        if (noisy_degree < 1) noisy_degree = 1;
        int tv = (int)(ceil(log_base((double)noisy_degree, 2.0)) * levels_per_group) + 1;
        if (tv < 1) tv = 1;
        threshold[v] = tv;
        maxThreshold = max(maxThreshold, tv);
    }

    int rounds_run = min(rounds_cap - 2, maxThreshold);
    if (rounds_run < 0) rounds_run = 0;

    for (int round = 0; round < rounds_run; ++round) {
        int group_index = (int)floor((double)round / levels_per_group);
        vector<uint8_t> move(n, 0);

        for (int v = 0; v < n; ++v) {
            if (threshold[v] == round) permanent_zero[v] = 0;
            if (level[v] == round && permanent_zero[v] != 0) {
                int same_level_count = 0;
                for (int nb : g.adj[v]) {
                    if (level[nb] == round) same_level_count++;
                }

                long long noisy_count = same_level_count;
                if (use_noise) {
                    double scale = eps2 / (2.0 * max(1, threshold[v]));
                    noisy_count += rng.twoSidedGeometric(scale);
                    double denom = exp(2.0 * scale) - 1.0;
                    double extra_bias = 0.0;
                    if (fabs(denom) > 1e-300) extra_bias = 6.0 * exp(scale) / pow(denom, 3.0);
                    if (isfinite(extra_bias)) noisy_count += (long long)floor(extra_bias);
                }

                double threshold_value = pow(base, (double)group_index);
                if ((double)noisy_count > threshold_value) {
                    move[v] = 1;
                } else {
                    permanent_zero[v] = 0;
                }
            }
        }

        for (int v = 0; v < n; ++v) if (move[v]) level[v]++;
    }

    vector<double> core(n, 0.0);
    const double lambda_const = 0.5; // same constant used by the Go implementation when estimating core numbers.
    for (int i = 0; i < n; ++i) {
        double power = max(floor(((double)level[i] + 1.0) / levels_per_group) - 1.0, 0.0);
        core[i] = (2.0 + lambda_const) * pow(base, power);
    }

    KCoreDResult res;
    res.level.swap(level);
    res.core_est.swap(core);
    res.rounds_cap = rounds_cap;
    res.rounds_run = rounds_run;
    res.max_threshold = maxThreshold;
    res.levels_per_group = levels_per_group;
    return res;
}

static inline bool isOutgoingByLevelId(int v, int nb, const vector<int> &level) {
    return (level[nb] > level[v]) || (level[nb] == level[v] && nb > v);
}

static vector<uint8_t> randomizedResponseNoisyMatrix(
    const Graph &g,
    double epsilon_rr,
    RandomGen &rng,
    const vector<uint8_t> &malicious,
    const RRAttackConfig &attack,
    RRAttackStats &stats
) {
    int n = g.n;
    vector<uint8_t> X((size_t)n * (size_t)n, 0);
    const double q = 1.0 / (exp(epsilon_rr) + 1.0);

    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            bool edge = g.adj_set[i].find(j) != g.adj_set[i].end();

            // Step 1: normal randomized response.
            bool noisy = false;
            double r = rng.uniform01();
            if (r < q) noisy = !edge;
            else noisy = edge;

            // Step 2: RR-output poisoning attack.
            // In this single-matrix port, each unordered bit {i,j} is reported once.
            // owner_mode=reporter: the lower-id endpoint i is treated as the reporter of M[i,j].
            // owner_mode=either: the bit is attackable if either endpoint is malicious; this is stronger.
            bool can_attack = false;
            if (attack.enabled && attack.poison_prob > 0.0 && !malicious.empty()) {
                if (attack.owner_mode == "either") can_attack = (malicious[i] != 0 || malicious[j] != 0);
                else can_attack = (malicious[i] != 0);
            }
            if (can_attack) {
                stats.attack_candidates++;
                if (rng.uniform01() < attack.poison_prob) {
                    stats.poisoned_bits++;
                    if (attack.force_one) {
                        noisy = true;   // increase attack: force noisy RR edge to 1
                        stats.forced_one++;
                    } else {
                        noisy = false;  // decrease attack: force noisy RR edge to 0
                        stats.forced_zero++;
                    }
                }
            }

            if (noisy) {
                X[(size_t)i * n + j] = 1;
                X[(size_t)j * n + i] = 1;
            }
        }
    }
    return X;
}

struct EdgeOrientResult {
    double estimate = 0.0;
    double max_noisy_out_degree = 0.0;
    double kcore_sec = 0.0;
    double rr_sec = 0.0;
    double maxout_sec = 0.0;
    double count_sec = 0.0;
    double total_sec = 0.0;
    KCoreDResult kcore;
    RRAttackStats attack_stats;
};

static EdgeOrientResult runEdgeOrientDelta(
    const Graph &g,
    double epsilon_total,
    double psi,
    double split_factor,
    int workers,
    bool use_noise,
    int bias_factor,
    uint64_t seed,
    const RRAttackConfig &attack_cfg
) {
    (void)workers; // workers are simulated by node ranges in this single-file port.
    RandomGen rng(seed);
    Timer totalTimer;
    Timer timer;

    const double eps_kcore = epsilon_total / 4.0;
    const double eps_rr = epsilon_total / 4.0;
    const double eps_out = epsilon_total / 4.0;
    const double eps_count = epsilon_total / 4.0;

    EdgeOrientResult res;
    res.kcore = runKCoreD(g, psi, eps_kcore, split_factor, use_noise, bias_factor, rng);
    res.kcore_sec = timer.reset();

    int malicious_nodes = 0;
    vector<uint8_t> malicious;
    RRAttackConfig attack = attack_cfg;
    if (attack.malicious_ratio <= 0.0 || attack.poison_prob <= 0.0) attack.enabled = false;
    if (use_noise && attack.enabled) {
        malicious = selectMaliciousUsers(g, attack, rng, malicious_nodes);
        res.attack_stats.malicious_nodes = malicious_nodes;
    }

    vector<uint8_t> X;
    if (use_noise) {
        X = randomizedResponseNoisyMatrix(g, eps_rr, rng, malicious, attack, res.attack_stats);
    } else {
        X.assign((size_t)g.n * (size_t)g.n, 0);
        for (int u = 0; u < g.n; ++u) {
            for (int v : g.adj[u]) X[(size_t)u * g.n + v] = 1;
        }
    }
    res.rr_sec = timer.reset();

    double maxNoisyOut = 0.0;
    for (int v = 0; v < g.n; ++v) {
        int outDegree = 0;
        for (int nb : g.adj[v]) if (isOutgoingByLevelId(v, nb, res.kcore.level)) outDegree++;
        double noisy = (double)outDegree;
        if (use_noise) noisy += (double)rng.twoSidedGeometric(eps_out);
        if (noisy > maxNoisyOut) maxNoisyOut = noisy;
    }
    if (maxNoisyOut < 0.0) maxNoisyOut = 0.0;
    res.max_noisy_out_degree = maxNoisyOut;
    res.maxout_sec = timer.reset();

    const int endCap = (int)floor(maxNoisyOut);
    const double a = exp(eps_rr);
    const double denom = a - 1.0;
    const double ucoef = a + 1.0;
    double totalCount = 0.0;

    for (int v = 0; v < g.n; ++v) {
        vector<int> out;
        out.reserve(g.adj[v].size());
        for (int nb : g.adj[v]) if (isOutgoingByLevelId(v, nb, res.kcore.level)) out.push_back(nb);
        sort(out.begin(), out.end());
        int e = min((int)out.size(), max(0, endCap));

        double local = 0.0;
        if (denom > 0.0) {
            for (int jj = 0; jj < e; ++jj) {
                int j = out[jj];
                size_t row = (size_t)j * g.n;
                for (int kk = jj + 1; kk < e; ++kk) {
                    int k = out[kk];
                    double x = X[row + k] ? 1.0 : 0.0;
                    if (use_noise) local += (x * ucoef - 1.0) / denom;
                    else local += x;
                }
            }
        }

        if (use_noise) {
            // Port of Go AddNoiseFloat64(local, l0=1, lInf=maxNoisyOut, epsilon=eps_count/2, delta=0).
            double eps_lap = eps_count / 2.0;
            double scale = (eps_lap > 0.0) ? (maxNoisyOut / eps_lap) : 0.0;
            local += rng.laplace(scale);
        }
        totalCount += local;
    }
    res.estimate = totalCount;
    res.count_sec = timer.reset();
    res.total_sec = totalTimer.elapsed();
    return res;
}

static const bool ATTACK_FORCE_ONE = true;
static const string ATTACK_TYPE = "rr_increase";

static void printUsage(const char *prog) {
    cerr << "Usage:\n"
         << "  " << prog << " <edges.csv> <n|-1> <epsilon_list> <psi> <workers> <runs> <noise:0/1> <seed> <output.csv> "
         << "<malicious_ratio_list> <poison_prob> [selection=random|high_degree|low_degree] [owner_mode=reporter|either] [split_factor=0.5] [bias_factor=8]\n\n"
         << "Example:\n"
         << "  " << prog << " ../data/Gplus/edges.csv 10000 0.5,1.0,2.0 0.5 2 5 1 1776 ../data/Gplus/rr_attack.csv 0.05,0.10,0.20 1.0 random reporter\n";
}

static vector<double> parseDoubleList(string s) {
    vector<double> vals;
    for (char &c : s) if (c == ';' || c == ':') c = ',';
    stringstream ss(s);
    string token;
    while (getline(ss, token, ',')) {
        token = trim(token);
        if (!token.empty()) vals.push_back(atof(token.c_str()));
    }
    return vals;
}

int main(int argc, char **argv) {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    if (argc < 12) {
        printUsage(argv[0]);
        return 1;
    }

    string edgeFile = argv[1];
    int nArg = atoi(argv[2]);
    vector<double> epsList = parseDoubleList(argv[3]);
    double psi = atof(argv[4]);
    int workers = atoi(argv[5]);
    int runs = atoi(argv[6]);
    bool use_noise = atoi(argv[7]) != 0;
    uint64_t baseSeed = strtoull(argv[8], nullptr, 10);
    string outputFile = argv[9];
    vector<double> maliciousRatios = parseDoubleList(argv[10]);
    double poison_prob = atof(argv[11]);
    string selection = (argc >= 13) ? argv[12] : "random";
    string owner_mode = (argc >= 14) ? argv[13] : "reporter";
    double split_factor = (argc >= 15) ? atof(argv[14]) : 0.5;
    int bias_factor = (argc >= 16) ? atoi(argv[15]) : 8;

    if (epsList.empty()) throw runtime_error("epsilon_list is empty.");
    if (maliciousRatios.empty()) maliciousRatios.push_back(0.0);
    if (psi <= 0.0) throw runtime_error("psi must be positive.");
    if (workers <= 0) workers = 1;
    if (runs <= 0) runs = 1;
    if (split_factor <= 0.0 || split_factor >= 1.0) split_factor = 0.5;
    if (bias_factor < 0) bias_factor = 0;
    if (poison_prob < 0.0) poison_prob = 0.0;
    if (poison_prob > 1.0) poison_prob = 1.0;
    if (owner_mode != "reporter" && owner_mode != "either") owner_mode = "reporter";
    if (selection != "random" && selection != "high_degree" && selection != "low_degree") selection = "random";

    Timer loadTimer;
    Graph g = readTriangleLDPEdges(edgeFile, nArg);
    double loadSec = loadTimer.elapsed();

    if (g.n > 50000) {
        cerr << "Refusing to run n=" << g.n << " because this single-file port materializes an n*n RR matrix. "
             << "Use n=10000/20000 for the TriangleLDP-style reproduction, or modify the code to use a sparse/hash RR structure.\n";
        return 2;
    }

    Timer exactTimer;
    long long exactTri = exactTriangleCount(g);
    double exactSec = exactTimer.elapsed();

    ofstream out(outputFile.c_str());
    if (!out) throw runtime_error("Cannot open output file: " + outputFile);
    out << "edge_file,n_header,n_used,m_used,exact_triangles,load_seconds,exact_seconds,"
        << "attack_type,malicious_ratio,poison_prob,malicious_selection,owner_mode,malicious_nodes,"
        << "rr_attack_candidates,rr_poisoned_bits,rr_forced_one,rr_forced_zero,"
        << "epsilon,psi,workers,runs,run,noise,seed,"
        << "estimate,abs_error,relative_error,max_noisy_out_degree,kcore_rounds_cap,kcore_rounds_run,kcore_max_threshold,"
        << "levels_per_group,kcore_seconds,rr_seconds,maxout_seconds,count_seconds,total_seconds\n";

    cerr << "Loaded " << edgeFile << " | header n=" << g.n_header << " | used n=" << g.n
         << " | m=" << g.m << " | exact triangles=" << exactTri << "\n";
    cerr << "=== RR Output Poisoning Attack ===\n"
         << "Attack type: " << ATTACK_TYPE << "\n"
         << "Malicious ratios: " << argv[10] << "\n"
         << "Poison probability: " << poison_prob << "\n"
         << "Selection: " << selection << " | owner_mode: " << owner_mode << "\n"
         << "==================================\n";

    for (double mr : maliciousRatios) {
        if (mr < 0.0) mr = 0.0;
        if (mr > 1.0) mr = 1.0;
        for (double eps : epsList) {
            if (eps <= 0.0) continue;
            for (int r = 0; r < runs; ++r) {
                uint64_t seed = baseSeed
                    + (uint64_t)r * 1000003ULL
                    + (uint64_t)llround(eps * 1000000.0)
                    + (uint64_t)llround(mr * 1000000000.0);

                RRAttackConfig cfg;
                cfg.enabled = use_noise && (mr > 0.0) && (poison_prob > 0.0);
                cfg.force_one = ATTACK_FORCE_ONE;
                cfg.malicious_ratio = mr;
                cfg.poison_prob = poison_prob;
                cfg.selection = selection;
                cfg.owner_mode = owner_mode;
                cfg.attack_type = ATTACK_TYPE;

                EdgeOrientResult res = runEdgeOrientDelta(g, eps, psi, split_factor, workers, use_noise, bias_factor, seed, cfg);
                double absErr = fabs(res.estimate - (double)exactTri);
                double relErr = (exactTri == 0) ? absErr : absErr / max(1.0, fabs((double)exactTri));

                out << edgeFile << ',' << g.n_header << ',' << g.n << ',' << g.m << ',' << exactTri << ','
                    << fixed << setprecision(8) << loadSec << ',' << exactSec << ','
                    << ATTACK_TYPE << ',' << mr << ',' << poison_prob << ',' << selection << ',' << owner_mode << ','
                    << res.attack_stats.malicious_nodes << ',' << res.attack_stats.attack_candidates << ','
                    << res.attack_stats.poisoned_bits << ',' << res.attack_stats.forced_one << ',' << res.attack_stats.forced_zero << ','
                    << eps << ',' << psi << ',' << workers << ',' << runs << ',' << r << ',' << (use_noise ? 1 : 0) << ',' << seed << ','
                    << res.estimate << ',' << absErr << ',' << relErr << ',' << res.max_noisy_out_degree << ','
                    << res.kcore.rounds_cap << ',' << res.kcore.rounds_run << ',' << res.kcore.max_threshold << ','
                    << res.kcore.levels_per_group << ',' << res.kcore_sec << ',' << res.rr_sec << ','
                    << res.maxout_sec << ',' << res.count_sec << ',' << res.total_sec << '\n';

                cerr << "attack_ratio=" << mr << " eps=" << eps << " run=" << r
                     << " estimate=" << res.estimate << " rel_error=" << relErr
                     << " poisoned_bits=" << res.attack_stats.poisoned_bits
                     << " time=" << res.total_sec << "s\n";
            }
        }
    }

    cerr << "Results written to " << outputFile << "\n";
    return 0;
}
