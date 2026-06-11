#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using namespace std;

/*
 * CCS25ShuffleTriangle.cpp
 *
 * A compact C++11 implementation/simulator for the triangle-counting protocol in
 * Fang & Yi, "Counting Subgraphs under Shuffle Differential Privacy" (CCS 2025),
 * together with two robustness attacks used in our experiments:
 *   1) original-data attack: add/remove edges among malicious users;
 *   2) RR attack: force malicious users' Radj/RR edge reports to 1 or 0.
 *
 * This code follows the experimental style of TriangleLDP/TriangleLDP:
 *   - one executable under cpp/;
 *   - edge list read from ../data/[Dataset]/edges.csv;
 *   - shell script runs multiple datasets/ratios/runs and appends a CSV summary.
 *
 * Implementation note:
 *   The paper's Rstar uses sampling + the negative-binomial mechanism. For efficient
 *   robustness experiments, we simulate the analyzer's aggregate Rstar output for
 *   each selected pair {i,j}: Binomial(common_neighbors(i,j), q) / q plus the
 *   equivalent discrete-Laplace aggregate noise induced by RNB.
 *
 *   We do NOT attack Rstar here, because the requested study only includes original
 *   data attacks and RR attacks.
 */

struct Args {
    string mode = "run";                 // run | exact
    string dataset = "Gplus";
    string edge_file = "";
    string output = "../results_ccs25_shuffle/summary.csv";
    string attack_type = "clean";        // clean, orig_increase, orig_decrease, rr_increase, rr_decrease
    string budget_mode = "simple";       // simple | paper

    int node_num = 10000;
    int m_groups = 10;
    int run_id = 0;
    int compute_true_after = 0;

    long long seed = 1776;
    long long clean_triangles_arg = -1;

    double eps = 1.0;
    double q = 0.05;
    double malicious_ratio = 0.0;
    double attack_strength = 1.0;
    double delta = 1e-6;
};

static void PrintUsage() {
    cerr << "Usage:\n"
         << "  ./CCS25ShuffleTriangle --mode run --dataset Gplus --node_num 10000 \\\n"
         << "    --edge_file ../data/Gplus/edges.csv --eps 1 --q 0.05 --m 10 \\\n"
         << "    --attack_type rr_increase --malicious_ratio 0.10 --attack_strength 1 \\\n"
         << "    --run 0 --seed 1776 --output ../results_ccs25_shuffle/summary.csv\n\n"
         << "Exact triangle helper:\n"
         << "  ./CCS25ShuffleTriangle --mode exact --edge_file ../data/Gplus/edges.csv --node_num 10000\n";
}

static bool IsNumberToken(const string &s) {
    if (s.empty()) return false;
    size_t i = 0;
    if (s[0] == '-' || s[0] == '+') i = 1;
    bool has_digit = false;
    for (; i < s.size(); ++i) {
        if (isdigit(static_cast<unsigned char>(s[i]))) has_digit = true;
        else return false;
    }
    return has_digit;
}

static Args ParseArgs(int argc, char **argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        string key = argv[i];
        auto need_value = [&](const string &k) -> string {
            if (i + 1 >= argc) {
                throw runtime_error("Missing value for " + k);
            }
            return string(argv[++i]);
        };

        if (key == "--mode") a.mode = need_value(key);
        else if (key == "--dataset") a.dataset = need_value(key);
        else if (key == "--edge_file") a.edge_file = need_value(key);
        else if (key == "--output") a.output = need_value(key);
        else if (key == "--attack_type") a.attack_type = need_value(key);
        else if (key == "--budget_mode") a.budget_mode = need_value(key);
        else if (key == "--node_num") a.node_num = atoi(need_value(key).c_str());
        else if (key == "--m") a.m_groups = atoi(need_value(key).c_str());
        else if (key == "--run") a.run_id = atoi(need_value(key).c_str());
        else if (key == "--seed") a.seed = atoll(need_value(key).c_str());
        else if (key == "--eps") a.eps = atof(need_value(key).c_str());
        else if (key == "--q") a.q = atof(need_value(key).c_str());
        else if (key == "--malicious_ratio") a.malicious_ratio = atof(need_value(key).c_str());
        else if (key == "--attack_strength") a.attack_strength = atof(need_value(key).c_str());
        else if (key == "--delta") a.delta = atof(need_value(key).c_str());
        else if (key == "--clean_triangles") a.clean_triangles_arg = atoll(need_value(key).c_str());
        else if (key == "--compute_true_after") a.compute_true_after = atoi(need_value(key).c_str());
        else if (key == "--help" || key == "-h") {
            PrintUsage();
            exit(0);
        }
        else {
            throw runtime_error("Unknown argument: " + key);
        }
    }

    if (a.edge_file.empty()) {
        a.edge_file = "../data/" + a.dataset + "/edges.csv";
    }
    if (a.node_num <= 0) throw runtime_error("--node_num must be positive");
    if (a.eps <= 0.0) throw runtime_error("--eps must be positive");
    if (!(a.q > 0.0 && a.q <= 1.0)) throw runtime_error("--q must be in (0,1]");
    if (a.m_groups <= 0) throw runtime_error("--m must be positive");
    if (a.malicious_ratio < 0.0 || a.malicious_ratio > 1.0) throw runtime_error("--malicious_ratio must be in [0,1]");
    if (a.attack_strength < 0.0 || a.attack_strength > 1.0) throw runtime_error("--attack_strength must be in [0,1]");
    return a;
}

struct Graph {
    int n = 0;
    vector< unordered_set<int> > adj_hash;
    vector< vector<int> > adj;
    long long edge_count = 0;

    Graph() {}
    explicit Graph(int n_) : n(n_), adj_hash(n_), adj(n_) {}

    bool HasEdge(int u, int v) const {
        if (u < 0 || v < 0 || u >= n || v >= n) return false;
        return adj_hash[u].find(v) != adj_hash[u].end();
    }

    bool AddEdge(int u, int v) {
        if (u == v || u < 0 || v < 0 || u >= n || v >= n) return false;
        if (HasEdge(u, v)) return false;
        adj_hash[u].insert(v);
        adj_hash[v].insert(u);
        ++edge_count;
        return true;
    }

    bool RemoveEdge(int u, int v) {
        if (u == v || u < 0 || v < 0 || u >= n || v >= n) return false;
        if (!HasEdge(u, v)) return false;
        adj_hash[u].erase(v);
        adj_hash[v].erase(u);
        --edge_count;
        return true;
    }

    void BuildSortedAdj() {
        adj.assign(n, vector<int>());
        for (int i = 0; i < n; ++i) {
            adj[i].reserve(adj_hash[i].size());
            for (int v : adj_hash[i]) adj[i].push_back(v);
            sort(adj[i].begin(), adj[i].end());
        }
    }

    int MaxDegree() const {
        int dmax = 0;
        for (int i = 0; i < n; ++i) dmax = max(dmax, static_cast<int>(adj_hash[i].size()));
        return dmax;
    }
};

static bool ParseEdgeLine(const string &line, int &u, int &v) {
    if (line.empty()) return false;
    if (line[0] == '#' || line[0] == '%' || line[0] == '/') return false;

    string s = line;
    for (char &c : s) {
        if (c == ',' || c == '\t') c = ' ';
    }
    string a, b;
    stringstream ss(s);
    if (!(ss >> a >> b)) return false;
    if (!IsNumberToken(a) || !IsNumberToken(b)) return false;

    long long uu = atoll(a.c_str());
    long long vv = atoll(b.c_str());
    if (uu < 0 || vv < 0) return false;
    u = static_cast<int>(uu);
    v = static_cast<int>(vv);
    return true;
}

static Graph ReadGraph(const string &edge_file, int node_num) {
    ifstream fin(edge_file.c_str());
    if (!fin) {
        throw runtime_error("Cannot open edge file: " + edge_file);
    }

    Graph g(node_num);
    string line;
    int u, v;
    while (getline(fin, line)) {
        if (!ParseEdgeLine(line, u, v)) continue;
        if (u == v) continue;
        if (u >= 0 && u < node_num && v >= 0 && v < node_num) {
            g.AddEdge(u, v);
        }
    }
    g.BuildSortedAdj();
    return g;
}

static long long CountCommonNeighbors(const Graph &g, int u, int v) {
    const vector<int> &a = g.adj[u];
    const vector<int> &b = g.adj[v];
    size_t i = 0, j = 0;
    long long cnt = 0;
    while (i < a.size() && j < b.size()) {
        if (a[i] == b[j]) {
            ++cnt;
            ++i;
            ++j;
        } else if (a[i] < b[j]) {
            ++i;
        } else {
            ++j;
        }
    }
    return cnt;
}

static long long CountTrianglesExact(const Graph &g) {
    long long tri = 0;
    for (int u = 0; u < g.n; ++u) {
        for (int v : g.adj[u]) {
            if (v <= u) continue;
            const vector<int> &au = g.adj[u];
            const vector<int> &av = g.adj[v];
            size_t i = upper_bound(au.begin(), au.end(), v) - au.begin();
            size_t j = upper_bound(av.begin(), av.end(), v) - av.begin();
            while (i < au.size() && j < av.size()) {
                if (au[i] == av[j]) {
                    ++tri;
                    ++i;
                    ++j;
                } else if (au[i] < av[j]) {
                    ++i;
                } else {
                    ++j;
                }
            }
        }
    }
    return tri;
}

static vector<char> SelectMaliciousUsers(int n, double ratio, mt19937_64 &rng) {
    int m = static_cast<int>(floor(n * ratio + 1e-12));
    vector<int> nodes(n);
    for (int i = 0; i < n; ++i) nodes[i] = i;
    shuffle(nodes.begin(), nodes.end(), rng);

    vector<char> mal(n, 0);
    for (int i = 0; i < m; ++i) mal[nodes[i]] = 1;
    return mal;
}

struct AttackStats {
    long long added_edges = 0;
    long long removed_edges = 0;
    long long rr_forced_reports = 0;
};

static AttackStats ApplyOriginalDataAttack(Graph &g, const vector<char> &mal, const Args &args, mt19937_64 &rng) {
    AttackStats st;
    if (args.attack_type != "orig_increase" && args.attack_type != "orig_decrease") return st;

    vector<int> malicious_nodes;
    for (int i = 0; i < g.n; ++i) if (mal[i]) malicious_nodes.push_back(i);

    uniform_real_distribution<double> unif(0.0, 1.0);
    for (size_t a = 0; a < malicious_nodes.size(); ++a) {
        int u = malicious_nodes[a];
        for (size_t b = a + 1; b < malicious_nodes.size(); ++b) {
            int v = malicious_nodes[b];
            if (unif(rng) > args.attack_strength) continue;
            if (args.attack_type == "orig_increase") {
                if (g.AddEdge(u, v)) ++st.added_edges;
            } else {
                if (g.RemoveEdge(u, v)) ++st.removed_edges;
            }
        }
    }
    g.BuildSortedAdj();
    return st;
}

static vector<char> SelectGroups(int n, int m_groups, mt19937_64 &rng) {
    int m = min(m_groups, n);
    vector<int> groups(n);
    for (int i = 0; i < n; ++i) groups[i] = i;
    shuffle(groups.begin(), groups.end(), rng);

    vector<char> selected(n, 0);
    for (int i = 0; i < m; ++i) selected[groups[i]] = 1;
    return selected;
}

static int WarnerRR(int x, double eps, mt19937_64 &rng) {
    double p_keep = exp(eps) / (exp(eps) + 1.0);
    bernoulli_distribution keep(p_keep);
    bool z = keep(rng);
    return z ? x : 1 - x;
}

static double RRUnbiasedEstimate(int y, double eps) {
    double ee = exp(eps);
    return (static_cast<double>(y) * (ee + 1.0) - 1.0) / (ee - 1.0);
}

static long long SampleDiscreteLaplace(double scale, mt19937_64 &rng) {
    if (!(scale > 0.0) || !isfinite(scale)) return 0;
    // DLap(scale) with pmf proportional to exp(-|x|/scale).
    double alpha = exp(-1.0 / scale);
    if (alpha <= 0.0) return 0;
    if (alpha >= 1.0) alpha = nextafter(1.0, 0.0);
    double success_prob = 1.0 - alpha;
    geometric_distribution<long long> geom(success_prob);
    long long g1 = geom(rng);
    long long g2 = geom(rng);
    return g1 - g2;
}

static double ComputePaperEpsStar(double eps_total, double delta, int dmax) {
    // Paper: eps' = eps/2 and eps'' = argmax{t: sqrt(4d ln(2/delta)t + 2d t(e^t-1)) <= eps'}.
    // This is optional because it can become very small for large d.
    double eps_prime = eps_total / 2.0;
    if (dmax <= 0) return eps_prime;
    if (!(delta > 0.0 && delta < 1.0)) delta = 1e-6;
    double lo = 0.0, hi = eps_prime;
    for (int it = 0; it < 80; ++it) {
        double mid = (lo + hi) / 2.0;
        double val = sqrt(4.0 * dmax * log(2.0 / delta) * mid + 2.0 * dmax * mid * (exp(mid) - 1.0));
        if (val <= eps_prime) lo = mid;
        else hi = mid;
    }
    return max(lo, 1e-12);
}

struct EstimateResult {
    double estimate_triangle = 0.0;
    double raw_counted_three_times = 0.0;
    long long selected_pair_count = 0;
    long long rr_forced_reports = 0;
};

static EstimateResult EstimateTriangleCCS25(const Graph &g,
                                            const vector<char> &mal,
                                            const vector<char> &selected_group,
                                            const Args &args,
                                            double eps_edge,
                                            double eps_star,
                                            mt19937_64 &rng) {
    EstimateResult res;
    const int n = g.n;
    const int m_eff = min(args.m_groups, n);

    uniform_real_distribution<double> unif(0.0, 1.0);
    double sum = 0.0;

    // Algorithm 6 exact sampling transformation: eps_q = ln(1 + (e^eps_star - 1)/q).
    double eps_q = log(1.0 + (exp(eps_star) - 1.0) / args.q);
    if (!(eps_q > 0.0)) eps_q = eps_star;
    const double delta = 1.0;  // For triangle counting, k=|T|=2, so Delta=1.
    const double rnb_noise_scale_before_dividing_by_q = delta / eps_q;

    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            int group = (i + j) % n;
            if (!selected_group[group]) continue;
            ++res.selected_pair_count;

            // Rstar aggregate for f_{ {i,j}, 2 }(I): common-neighbor count.
            long long common = CountCommonNeighbors(g, i, j);
            long long sampled_common = 0;
            if (common > 0) {
                binomial_distribution<long long> binom(common, args.q);
                sampled_common = binom(rng);
            }
            long long noise = SampleDiscreteLaplace(rnb_noise_scale_before_dividing_by_q, rng);
            double star_hat = (static_cast<double>(sampled_common) + static_cast<double>(noise)) / args.q;

            // Radj/RRR for x_{i,j}; node i sends the upper-triangular report.
            int x = g.HasEdge(i, j) ? 1 : 0;
            int y = WarnerRR(x, eps_edge, rng);

            if ((args.attack_type == "rr_increase" || args.attack_type == "rr_decrease") && mal[i]) {
                if (unif(rng) <= args.attack_strength) {
                    y = (args.attack_type == "rr_increase") ? 1 : 0;
                    ++res.rr_forced_reports;
                }
            }
            double x_hat = RRUnbiasedEstimate(y, eps_edge);
            sum += star_hat * x_hat;
        }
    }

    // GenShuffle_m estimator, then divide by 3 because each triangle is counted three times.
    res.raw_counted_three_times = (static_cast<double>(n) / static_cast<double>(m_eff)) * sum;
    res.estimate_triangle = res.raw_counted_three_times / 3.0;
    return res;
}

static bool FileExists(const string &path) {
    ifstream f(path.c_str());
    return f.good();
}

static void AppendCSV(const Args &args,
                      long long malicious_count,
                      long long edge_count_before,
                      long long edge_count_after,
                      long long clean_triangles,
                      long long true_triangles_after,
                      int dmax_after,
                      double eps_edge,
                      double eps_star,
                      const AttackStats &attack_stats,
                      const EstimateResult &est,
                      double time_sec) {
    bool exists = FileExists(args.output);
    ofstream fout(args.output.c_str(), ios::app);
    if (!fout) {
        throw runtime_error("Cannot open output CSV: " + args.output);
    }

    if (!exists) {
        fout << "dataset,node_num,eps,eps_edge,eps_star,budget_mode,q,m,run,seed,"
             << "attack_type,malicious_ratio,malicious_count,attack_strength,"
             << "edge_count_before_attack,edge_count_after_attack,dmax_after_attack,"
             << "added_edges,removed_edges,rr_forced_reports,selected_pair_count,"
             << "clean_triangles,true_triangles_after_attack,estimate_triangle,raw_counted_three_times,"
             << "rel_error_clean,signed_rel_clean,rel_error_attack_true,time_sec\n";
    }

    double rel_clean = NAN;
    double signed_clean = NAN;
    if (clean_triangles > 0) {
        signed_clean = (est.estimate_triangle - static_cast<double>(clean_triangles)) / static_cast<double>(clean_triangles);
        rel_clean = fabs(signed_clean);
    }

    double rel_attack_true = NAN;
    if (true_triangles_after > 0) {
        rel_attack_true = fabs(est.estimate_triangle - static_cast<double>(true_triangles_after)) / static_cast<double>(true_triangles_after);
    }

    fout << fixed << setprecision(10)
         << args.dataset << ','
         << args.node_num << ','
         << args.eps << ','
         << eps_edge << ','
         << eps_star << ','
         << args.budget_mode << ','
         << args.q << ','
         << min(args.m_groups, args.node_num) << ','
         << args.run_id << ','
         << args.seed << ','
         << args.attack_type << ','
         << args.malicious_ratio << ','
         << malicious_count << ','
         << args.attack_strength << ','
         << edge_count_before << ','
         << edge_count_after << ','
         << dmax_after << ','
         << attack_stats.added_edges << ','
         << attack_stats.removed_edges << ','
         << est.rr_forced_reports << ','
         << est.selected_pair_count << ','
         << clean_triangles << ','
         << true_triangles_after << ','
         << est.estimate_triangle << ','
         << est.raw_counted_three_times << ','
         << rel_clean << ','
         << signed_clean << ','
         << rel_attack_true << ','
         << time_sec << '\n';
}

int main(int argc, char **argv) {
    try {
        Args args = ParseArgs(argc, argv);

        auto t0 = chrono::high_resolution_clock::now();
        Graph g = ReadGraph(args.edge_file, args.node_num);

        if (args.mode == "exact") {
            long long tri = CountTrianglesExact(g);
            cout << "clean_triangles=" << tri << "\n";
            cout << "edge_count=" << g.edge_count << "\n";
            cout << "node_num=" << args.node_num << "\n";
            return 0;
        }
        if (args.mode != "run") {
            throw runtime_error("Unsupported --mode: " + args.mode);
        }

        long long edge_count_before = g.edge_count;
        long long clean_triangles = args.clean_triangles_arg;
        if (clean_triangles < 0) {
            clean_triangles = CountTrianglesExact(g);
        }

        mt19937_64 rng_mal(args.seed + 1000003LL * args.run_id + 11);
        mt19937_64 rng_group(args.seed + 1000003LL * args.run_id + 23);
        mt19937_64 rng_attack(args.seed + 1000003LL * args.run_id + 31);
        mt19937_64 rng_protocol(args.seed + 1000003LL * args.run_id + 37);

        vector<char> malicious = SelectMaliciousUsers(args.node_num, args.malicious_ratio, rng_mal);
        long long malicious_count = 0;
        for (char c : malicious) if (c) ++malicious_count;

        AttackStats attack_stats = ApplyOriginalDataAttack(g, malicious, args, rng_attack);
        long long edge_count_after = g.edge_count;
        int dmax_after = g.MaxDegree();

        long long true_triangles_after = -1;
        if (args.compute_true_after) {
            true_triangles_after = CountTrianglesExact(g);
        }

        vector<char> selected_group = SelectGroups(args.node_num, args.m_groups, rng_group);

        double eps_edge = args.eps / 2.0;
        double eps_star = args.eps / 2.0;
        if (args.budget_mode == "paper") {
            eps_edge = args.eps / 2.0;
            eps_star = ComputePaperEpsStar(args.eps, args.delta, max(1, dmax_after));
        } else if (args.budget_mode != "simple") {
            throw runtime_error("Unsupported --budget_mode: " + args.budget_mode);
        }

        EstimateResult est = EstimateTriangleCCS25(g, malicious, selected_group, args, eps_edge, eps_star, rng_protocol);

        auto t1 = chrono::high_resolution_clock::now();
        double time_sec = chrono::duration<double>(t1 - t0).count();

        AppendCSV(args, malicious_count, edge_count_before, edge_count_after,
                  clean_triangles, true_triangles_after, dmax_after,
                  eps_edge, eps_star, attack_stats, est, time_sec);

        cout << fixed << setprecision(6)
             << "dataset=" << args.dataset
             << " attack=" << args.attack_type
             << " ratio=" << args.malicious_ratio
             << " eps=" << args.eps
             << " q=" << args.q
             << " m=" << min(args.m_groups, args.node_num)
             << " run=" << args.run_id
             << " clean_triangles=" << clean_triangles
             << " estimate=" << est.estimate_triangle
             << " rel_error_clean=" << (clean_triangles > 0 ? fabs(est.estimate_triangle - clean_triangles) / clean_triangles : NAN)
             << " selected_pairs=" << est.selected_pair_count
             << " rr_forced=" << est.rr_forced_reports
             << " added=" << attack_stats.added_edges
             << " removed=" << attack_stats.removed_edges
             << " time=" << time_sec << "s\n";
    } catch (const exception &e) {
        cerr << "ERROR: " << e.what() << "\n";
        PrintUsage();
        return 1;
    }
    return 0;
}
