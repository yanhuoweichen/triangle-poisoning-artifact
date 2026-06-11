#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
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

static inline double safe_log_base(double a, double b) {
    if (!(a > 1.0) || !(b > 1.0) || !isfinite(a) || !isfinite(b)) return 0.0;
    return log(a) / log(b);
}

static uint64_t splitmix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

static uint64_t makeSeed(uint64_t base, uint64_t phase, uint64_t worker, uint64_t round = 0) {
    return splitmix64(base ^ (phase * 0x9e3779b97f4a7c15ULL) ^ (worker << 17) ^ (round << 37));
}

class RandomGen {
public:
    explicit RandomGen(uint64_t seed) : rng(seed), uni(0.0, 1.0) {}

    double uniform01() { return uni(rng); }

    // Symmetric geometric / discrete Laplace noise.
    // P(X=0)=(1-alpha)/(1+alpha), P(X=+-k)=((1-alpha)/(1+alpha))*alpha^k, k>=1,
    // where alpha=exp(-lambda). This matches Geom(lambda) in the paper/code.
    long long twoSidedGeometric(double lambda) {
        if (!(lambda > 0.0) || !isfinite(lambda)) return 0;
        double alpha = exp(-lambda);
        if (alpha <= 0.0) return 0;
        if (alpha >= 1.0) alpha = nextafter(1.0, 0.0);
        double p0 = (1.0 - alpha) / (1.0 + alpha);
        if (uniform01() < p0) return 0;
        double v = uniform01();
        long long mag = 1 + static_cast<long long>(floor(log(max(1e-300, 1.0 - v)) / log(alpha)));
        if (mag < 1) mag = 1;
        return (uniform01() < 0.5) ? -mag : mag;
    }

    // Standard Laplace with density (1/(2*scale))*exp(-|x|/scale).
    // The paper writes Lap(b) with b as rate; use scale=1/b.
    double laplaceScale(double scale) {
        if (!(scale > 0.0) || !isfinite(scale)) return 0.0;
        double u = uniform01() - 0.5;
        double sgn = (u < 0.0) ? -1.0 : 1.0;
        return -scale * sgn * log(1.0 - 2.0 * fabs(u));
    }

private:
    mt19937_64 rng;
    uniform_real_distribution<double> uni;
};

struct Range { int start; int end; Range() : start(0), end(0) {} Range(int s, int e) : start(s), end(e) {} };

static vector<Range> makeWorkerRanges(int n, int workers) {
    workers = max(1, min(workers, max(1, n)));
    vector<Range> ranges;
    ranges.reserve(workers);
    int chunk = n / workers;
    for (int w = 0; w < workers; ++w) {
        int start = w * chunk;
        int end = (w == workers - 1) ? n : (w + 1) * chunk;
        ranges.push_back(Range(start, end));
    }
    return ranges;
}

struct Graph {
    int n_header = 0;
    int n = 0;
    long long m = 0;
    vector<vector<int>> adj;
    vector<unordered_set<int>> adj_set;
};

static vector<int> parseInts(string line) {
    for (char &c : line) {
        if (c == ',' || c == ':' || c == ';' || c == '\t') c = ' ';
    }
    stringstream ss(line);
    vector<int> vals;
    long long x;
    while (ss >> x) {
        if (x >= numeric_limits<int>::min() && x <= numeric_limits<int>::max()) vals.push_back((int)x);
    }
    return vals;
}

static void addUndirectedEdge(Graph &g, int u, int v) {
    if (u == v || u < 0 || v < 0 || u >= g.n || v >= g.n) return;
    if (g.adj_set[u].insert(v).second) {
        g.adj[u].push_back(v);
        g.adj_set[v].insert(u);
        g.adj[v].push_back(u);
        g.m++;
    }
}

// Reads the TriangleLDP CSV format and ordinary edge-list / adjacency-list text files.
// Supported examples:
//   #nodes \n 107614 \n node,node \n u,v
//   u v
//   u v1 v2 v3 ...   (treated as adjacency row if a line has more than two integers)
static Graph readGraphAuto(const string &edgeFile, int nArg) {
    ifstream fin(edgeFile.c_str());
    if (!fin) throw runtime_error("Cannot open edge file: " + edgeFile);

    string line;
    int headerN = -1;
    int maxNode = -1;
    bool afterNodesTag = false;
    vector<vector<int>> rows;

    while (getline(fin, line)) {
        line = trim(line);
        if (line.empty()) continue;
        if (line == "#nodes") { afterNodesTag = true; continue; }
        if (afterNodesTag) {
            vector<int> v = parseInts(line);
            if (!v.empty()) headerN = v[0];
            afterNodesTag = false;
            continue;
        }
        // Skip common textual headers, but do not skip negative numeric lines.
        if (line[0] == '#') continue;
        if (line.find("node") != string::npos || line.find("source") != string::npos || line.find("target") != string::npos) continue;

        vector<int> vals = parseInts(line);
        if (vals.size() < 2) continue;
        for (int x : vals) if (x >= 0) maxNode = max(maxNode, x);
        rows.push_back(vals);
    }

    int n = nArg;
    if (n <= 0) n = (headerN > 0) ? headerN : maxNode + 1;
    if (n <= 0) throw runtime_error("Invalid node number. Use n>0 or provide a valid #nodes header.");

    Graph g;
    g.n_header = (headerN > 0) ? headerN : (maxNode + 1);
    g.n = n;
    g.adj.assign(n, {});
    g.adj_set.assign(n, {});

    for (const auto &vals : rows) {
        int u = vals[0];
        if (vals.size() == 2) {
            addUndirectedEdge(g, u, vals[1]);
        } else {
            // Treat as adjacency row: u v1 v2 ...
            for (size_t i = 1; i < vals.size(); ++i) addUndirectedEdge(g, u, vals[i]);
        }
    }
    for (int i = 0; i < n; ++i) sort(g.adj[i].begin(), g.adj[i].end());
    return g;
}

static long long exactTriangleCount(const Graph &g) {
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
    vector<int> order_rank;       // Z[v]: rank in the low-out-degree order. Edge v->u iff Z[u] > Z[v].
    vector<double> core_est;
    int rounds_cap = 0;
    int rounds_run = 0;
    int max_threshold = 0;
    double levels_per_group = 1.0;
};

static double degreeBias(double eps, int bias_factor) {
    if (!isfinite(eps) || eps <= 0.0 || bias_factor <= 0) return 0.0;
    double denom = exp(2.0 * eps) - 1.0;
    if (fabs(denom) < 1e-300) return 0.0;
    return (double)bias_factor * (2.0 * exp(eps)) / denom;
}

static double levelMoveBias(double geom_param) {
    if (!isfinite(geom_param) || geom_param <= 0.0) return 0.0;
    double denom = exp(2.0 * geom_param) - 1.0;
    if (fabs(denom) < 1e-300) return 0.0;
    // Official Go code: 3 * (2*exp(scale)) / (exp(2*scale)-1)^3.
    double val = 6.0 * exp(geom_param) / pow(denom, 3.0);
    return isfinite(val) ? val : 0.0;
}

static vector<int> computeOrderRankByLevelId(const vector<int> &level) {
    int n = (int)level.size();
    vector<int> nodes(n);
    iota(nodes.begin(), nodes.end(), 0);
    stable_sort(nodes.begin(), nodes.end(), [&](int a, int b) {
        if (level[a] != level[b]) return level[a] < level[b];
        return a < b;
    });
    vector<int> rank(n);
    for (int i = 0; i < n; ++i) rank[nodes[i]] = i;
    return rank;
}

static KCoreDResult runKCoreD(
    const Graph &g,
    double psi,
    double epsilon_phase,
    double split_factor,
    int workers,
    bool use_noise,
    int bias_factor,
    uint64_t seed
) {
    const int n = g.n;
    const double base = 1.0 + psi;
    const double logn = max(1.0, safe_log_base(max(2, n), base));
    const double levels_per_group = max(1.0, ceil(logn) / 4.0);
    // The official implementation uses this empirical cap; the paper states the theoretical cap in terms of D_max.
    const int rounds_cap = max(1, (int)ceil(4.0 * pow(logn, 1.2)));

    const double eps1 = epsilon_phase * split_factor;
    const double eps2 = epsilon_phase * (1.0 - split_factor);
    const vector<Range> ranges = makeWorkerRanges(n, workers);

    vector<int> level(n, 0), active(n, 1), threshold(n, 1);
    vector<int> workerMaxThreshold(ranges.size(), 0);

    vector<thread> threads;
    threads.reserve(ranges.size());
    for (size_t w = 0; w < ranges.size(); ++w) {
        threads.emplace_back([&, w]() {
            RandomGen rng(makeSeed(seed, 101, (uint64_t)w));
            int localMax = 0;
            for (int v = ranges[w].start; v < ranges[w].end; ++v) {
                long long noisy_degree = (long long)g.adj[v].size();
                if (use_noise) {
                    // Algorithm 3.2 samples Geom(eps1/2), but the degree-threshold bias uses eps1.
                    noisy_degree += rng.twoSidedGeometric(eps1 / 2.0);
                    double b = degreeBias(eps1, bias_factor);
                    noisy_degree -= (long long)floor(min(b, (double)noisy_degree));
                    noisy_degree += 1; // ensure at least 1 after post-processing
                }
                if (noisy_degree < 1) noisy_degree = 1;
                int tv = (int)(ceil(safe_log_base((double)noisy_degree, 2.0)) * levels_per_group) + 1;
                if (tv < 1) tv = 1;
                threshold[v] = tv;
                localMax = max(localMax, tv);
            }
            workerMaxThreshold[w] = localMax;
        });
    }
    for (auto &t : threads) t.join();

    int maxThreshold = 0;
    for (int x : workerMaxThreshold) maxThreshold = max(maxThreshold, x);
    int rounds_run = min(rounds_cap - 2, maxThreshold);
    if (rounds_run < 0) rounds_run = 0;

    for (int round = 0; round < rounds_run; ++round) {
        int group_index = (int)floor((double)round / levels_per_group);
        vector<uint8_t> move(n, 0);
        threads.clear();
        for (size_t w = 0; w < ranges.size(); ++w) {
            threads.emplace_back([&, w, round, group_index]() {
                RandomGen rng(makeSeed(seed, 202, (uint64_t)w, (uint64_t)round));
                for (int v = ranges[w].start; v < ranges[w].end; ++v) {
                    if (threshold[v] == round) active[v] = 0;
                    if (level[v] == round && active[v] != 0) {
                        int same_level_count = 0;
                        for (int nb : g.adj[v]) {
                            if (level[nb] == round) same_level_count++;
                        }

                        long long noisy_count = same_level_count;
                        if (use_noise) {
                            double geom_param = eps2 / (2.0 * max(1, threshold[v]));
                            noisy_count += rng.twoSidedGeometric(geom_param);
                            noisy_count += (long long)floor(levelMoveBias(geom_param));
                        }

                        double threshold_value = pow(base, (double)group_index);
                        if ((double)noisy_count > threshold_value) move[v] = 1;
                        else active[v] = 0;
                    }
                }
            });
        }
        for (auto &t : threads) t.join();
        for (int v = 0; v < n; ++v) if (move[v]) level[v]++;
    }

    vector<double> core(n, 0.0);
    const double lambda_const = 0.5; // official implementation constant for core number estimation.
    for (int i = 0; i < n; ++i) {
        double power = max(floor(((double)level[i] + 1.0) / levels_per_group) - 1.0, 0.0);
        core[i] = (2.0 + lambda_const) * pow(base, power);
    }

    KCoreDResult res;
    res.level.swap(level);
    res.order_rank = computeOrderRankByLevelId(res.level);
    res.core_est.swap(core);
    res.rounds_cap = rounds_cap;
    res.rounds_run = rounds_run;
    res.max_threshold = maxThreshold;
    res.levels_per_group = levels_per_group;
    return res;
}

static inline bool isOutgoingByRank(int v, int nb, const vector<int> &rank) {
    return rank[nb] > rank[v];
}

static inline size_t denseIndex(int i, int j, int n) {
    return (size_t)i * (size_t)n + (size_t)j;
}

static inline bool getNoisyUpperEdge(const vector<uint8_t> &X, int u, int v, int n) {
    if (u == v) return false;
    int a = min(u, v), b = max(u, v);
    return X[denseIndex(a, b, n)] != 0;
}

static vector<uint8_t> randomizedResponseNoisyUpperMatrix(
    const Graph &g,
    double epsilon_rr,
    const vector<Range> &ranges,
    bool use_noise,
    uint64_t seed
) {
    int n = g.n;
    vector<uint8_t> X((size_t)n * (size_t)n, 0);
    const double q = use_noise ? (1.0 / (exp(epsilon_rr) + 1.0)) : 0.0;

    vector<thread> threads;
    for (size_t w = 0; w < ranges.size(); ++w) {
        threads.emplace_back([&, w]() {
            RandomGen rng(makeSeed(seed, 303, (uint64_t)w));
            for (int i = ranges[w].start; i < ranges[w].end; ++i) {
                for (int j = i + 1; j < n; ++j) {
                    bool edge = g.adj_set[i].find(j) != g.adj_set[i].end();
                    bool noisy = edge;
                    if (use_noise) {
                        bool flip = rng.uniform01() < q;
                        noisy = flip ? !edge : edge;
                    }
                    if (noisy) X[denseIndex(i, j, n)] = 1;
                }
            }
        });
    }
    for (auto &t : threads) t.join();
    return X;
}

struct EdgeOrientResult {
    double estimate = 0.0;
    double max_noisy_out_degree_before_slack = 0.0;
    double max_noisy_out_degree = 0.0;
    double dmax_slack = 0.0;
    double kcore_sec = 0.0;
    double rr_sec = 0.0;
    double maxout_sec = 0.0;
    double count_sec = 0.0;
    double total_sec = 0.0;
    KCoreDResult kcore;
};

static EdgeOrientResult runEdgeOrientDelta(
    const Graph &g,
    double epsilon_total,
    double psi,
    double split_factor,
    int workers,
    bool use_noise,
    int bias_factor,
    double dmax_slack_multiplier,
    uint64_t seed
) {
    Timer totalTimer;
    Timer timer;
    const vector<Range> ranges = makeWorkerRanges(g.n, workers);

    const double eps_kcore = epsilon_total / 4.0;
    const double eps_rr = epsilon_total / 4.0;
    const double eps_out = epsilon_total / 4.0;
    const double eps_count = epsilon_total / 4.0;

    EdgeOrientResult res;
    res.kcore = runKCoreD(g, psi, eps_kcore, split_factor, workers, use_noise, bias_factor, makeSeed(seed, 1, 0));
    res.kcore_sec = timer.reset();

    // Round 1: each worker applies RR to the upper triangular row entries of its local vertices.
    vector<uint8_t> X = randomizedResponseNoisyUpperMatrix(g, eps_rr, ranges, use_noise, makeSeed(seed, 2, 0));
    res.rr_sec = timer.reset();

    // Round 2: each worker computes a noisy max out-degree over its node partition.
    vector<double> workerMax(ranges.size(), 0.0);
    vector<thread> threads;
    for (size_t w = 0; w < ranges.size(); ++w) {
        threads.emplace_back([&, w]() {
            RandomGen rng(makeSeed(seed, 404, (uint64_t)w));
            double localMax = 0.0;
            for (int v = ranges[w].start; v < ranges[w].end; ++v) {
                int outDegree = 0;
                for (int nb : g.adj[v]) {
                    if (isOutgoingByRank(v, nb, res.kcore.order_rank)) outDegree++;
                }
                double noisy = (double)outDegree;
                if (use_noise) noisy += (double)rng.twoSidedGeometric(eps_out);
                if (noisy > localMax) localMax = noisy;
            }
            workerMax[w] = localMax;
        });
    }
    for (auto &t : threads) t.join();

    double maxNoisyOut = 0.0;
    for (double x : workerMax) maxNoisyOut = max(maxNoisyOut, x);
    if (maxNoisyOut < 0.0) maxNoisyOut = 0.0;
    res.max_noisy_out_degree_before_slack = maxNoisyOut;

    // Paper Algorithm 4.1 adds 12 log(n)/epsilon after taking the max. The released GitHub implementation omits it.
    // Set dmax_slack_multiplier=0 to reproduce the GitHub empirical implementation exactly.
    res.dmax_slack = (use_noise && dmax_slack_multiplier > 0.0)
                       ? dmax_slack_multiplier * log(max(2, g.n)) / epsilon_total
                       : 0.0;
    maxNoisyOut += res.dmax_slack;
    res.max_noisy_out_degree = maxNoisyOut;
    res.maxout_sec = timer.reset();

    // Round 3: each worker counts local oriented wedges, debiases RR edge indicators, and adds Laplace noise.
    const int endCap = max(0, (int)floor(maxNoisyOut));
    const double a = exp(eps_rr);
    const double denom = a - 1.0;
    const double ucoef = a + 1.0;
    vector<double> workerCounts(ranges.size(), 0.0);
    threads.clear();
    for (size_t w = 0; w < ranges.size(); ++w) {
        threads.emplace_back([&, w]() {
            RandomGen rng(makeSeed(seed, 505, (uint64_t)w));
            double workerCount = 0.0;
            vector<int> out;
            for (int v = ranges[w].start; v < ranges[w].end; ++v) {
                out.clear();
                out.reserve(g.adj[v].size());
                for (int nb : g.adj[v]) {
                    if (isOutgoingByRank(v, nb, res.kcore.order_rank)) out.push_back(nb);
                }
                sort(out.begin(), out.end());
                int e = min((int)out.size(), endCap);

                double local = 0.0;
                if (use_noise) {
                    if (denom > 0.0) {
                        for (int jj = 0; jj < e; ++jj) {
                            int j = out[jj];
                            for (int kk = jj + 1; kk < e; ++kk) {
                                int k = out[kk];
                                double x = getNoisyUpperEdge(X, j, k, g.n) ? 1.0 : 0.0;
                                local += (x * ucoef - 1.0) / denom;
                            }
                        }
                    }
                    // Algorithm 4.4 uses Lap(eps_count/(2*dmax)); this is standard Laplace scale 2*dmax/eps_count.
                    double scale = (eps_count > 0.0) ? (2.0 * maxNoisyOut / eps_count) : 0.0;
                    local += rng.laplaceScale(scale);
                } else {
                    // Non-private debug mode: true existence test, no RR debiasing and no Laplace noise.
                    for (int jj = 0; jj < e; ++jj) {
                        int j = out[jj];
                        for (int kk = jj + 1; kk < e; ++kk) {
                            int k = out[kk];
                            if (g.adj_set[j].find(k) != g.adj_set[j].end()) local += 1.0;
                        }
                    }
                }
                workerCount += local;
            }
            workerCounts[w] = workerCount;
        });
    }
    for (auto &t : threads) t.join();

    double totalCount = 0.0;
    for (double x : workerCounts) totalCount += x;
    res.estimate = totalCount;
    res.count_sec = timer.reset();
    res.total_sec = totalTimer.elapsed();
    return res;
}

static void printUsage(const char *prog) {
    cerr << "Usage:\n"
         << "  " << prog << " <edges.csv/txt> <n|-1> <epsilon_list> <psi> <workers> <runs> <noise:0/1> <seed> <output.csv> [split_factor=0.8] [bias_factor=8] [dmax_slack_multiplier=12]\n\n"
         << "Notes:\n"
         << "  * This is a paper-faithful single-machine distributed simulation: nodes are partitioned into worker ranges.\n"
         << "  * dmax_slack_multiplier=12 matches Algorithm 4.1; set it to 0 to mimic the released GitHub empirical code.\n\n"
         << "Example:\n"
         << "  " << prog << " ../data/Gplus/edges.csv 10000 0.5,1.0,2.0 0.5 4 5 1 1776 ../data/Gplus/EdgeOrientDelta_corrected.csv\n";
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

    try {
        if (argc < 10) { printUsage(argv[0]); return 1; }

        string edgeFile = argv[1];
        int nArg = atoi(argv[2]);
        vector<double> epsList = parseDoubleList(argv[3]);
        double psi = atof(argv[4]);
        int workers = atoi(argv[5]);
        int runs = atoi(argv[6]);
        bool use_noise = atoi(argv[7]) != 0;
        uint64_t baseSeed = strtoull(argv[8], nullptr, 10);
        string outputFile = argv[9];
        double split_factor = (argc >= 11) ? atof(argv[10]) : 0.8;
        int bias_factor = (argc >= 12) ? atoi(argv[11]) : 8;
        double dmax_slack_multiplier = (argc >= 13) ? atof(argv[12]) : 12.0;

        if (epsList.empty()) throw runtime_error("epsilon_list is empty.");
        if (psi <= 0.0) throw runtime_error("psi must be positive.");
        if (workers <= 0) workers = 1;
        if (runs <= 0) runs = 1;
        if (split_factor <= 0.0 || split_factor >= 1.0) split_factor = 0.8;
        if (bias_factor < 0) bias_factor = 0;
        if (dmax_slack_multiplier < 0.0) dmax_slack_multiplier = 0.0;

        Timer loadTimer;
        Graph g = readGraphAuto(edgeFile, nArg);
        double loadSec = loadTimer.elapsed();

        if (g.n > 50000) {
            cerr << "Refusing to run n=" << g.n << " because this version materializes a dense n*n RR matrix. "
                 << "Use n=10000/20000 for the thesis experiments or replace the RR matrix with a sparse/hash oracle.\n";
            return 2;
        }

        Timer exactTimer;
        long long exactTri = exactTriangleCount(g);
        double exactSec = exactTimer.elapsed();

        ofstream out(outputFile.c_str());
        if (!out) throw runtime_error("Cannot open output file: " + outputFile);
        out << "edge_file,n_header,n_used,m_used,exact_triangles,load_seconds,exact_seconds,epsilon,psi,workers,runs,run,noise,seed,"
            << "split_factor,bias_factor,dmax_slack_multiplier,estimate,abs_error,relative_error,"
            << "max_noisy_out_degree_before_slack,dmax_slack,max_noisy_out_degree,kcore_rounds_cap,kcore_rounds_run,kcore_max_threshold,"
            << "levels_per_group,kcore_seconds,rr_seconds,maxout_seconds,count_seconds,total_seconds\n";

        cerr << "Loaded " << edgeFile << " | header n=" << g.n_header << " | used n=" << g.n
             << " | m=" << g.m << " | exact triangles=" << exactTri
             << " | workers=" << workers << " | split_factor=" << split_factor
             << " | dmax_slack_multiplier=" << dmax_slack_multiplier << "\n";

        for (double eps : epsList) {
            if (eps <= 0.0) continue;
            for (int r = 0; r < runs; ++r) {
                uint64_t seed = makeSeed(baseSeed, (uint64_t)llround(eps * 1000000.0), (uint64_t)r);
                EdgeOrientResult res = runEdgeOrientDelta(g, eps, psi, split_factor, workers, use_noise, bias_factor, dmax_slack_multiplier, seed);
                double absErr = fabs(res.estimate - (double)exactTri);
                double relErr = (exactTri == 0) ? absErr : absErr / max(1.0, fabs((double)exactTri));
                out << edgeFile << ',' << g.n_header << ',' << g.n << ',' << g.m << ',' << exactTri << ','
                    << fixed << setprecision(8) << loadSec << ',' << exactSec << ','
                    << eps << ',' << psi << ',' << workers << ',' << runs << ',' << r << ',' << (use_noise ? 1 : 0) << ',' << seed << ','
                    << split_factor << ',' << bias_factor << ',' << dmax_slack_multiplier << ','
                    << res.estimate << ',' << absErr << ',' << relErr << ','
                    << res.max_noisy_out_degree_before_slack << ',' << res.dmax_slack << ',' << res.max_noisy_out_degree << ','
                    << res.kcore.rounds_cap << ',' << res.kcore.rounds_run << ',' << res.kcore.max_threshold << ','
                    << res.kcore.levels_per_group << ',' << res.kcore_sec << ',' << res.rr_sec << ','
                    << res.maxout_sec << ',' << res.count_sec << ',' << res.total_sec << '\n';
                cerr << "eps=" << eps << " run=" << r << " estimate=" << res.estimate
                     << " rel_error=" << relErr << " dmax=" << res.max_noisy_out_degree
                     << " time=" << res.total_sec << "s\n";
            }
        }

        cerr << "Results written to " << outputFile << "\n";
        return 0;
    } catch (const exception &e) {
        cerr << "ERROR: " << e.what() << "\n";
        return 3;
    }
}
