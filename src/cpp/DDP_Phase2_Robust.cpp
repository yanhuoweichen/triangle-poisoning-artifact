#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <sys/stat.h>

using namespace std;

enum AttackType {
    ATTACK_NONE = 0,
    ORIG_INCREASE,
    ORIG_DECREASE,
    LAP_FIXED_INCREASE,
    LAP_FIXED_DECREASE,
    LAP_SCALE_INCREASE,
    LAP_SCALE_DECREASE,
    LAP_COUNT_INCREASE,
    LAP_COUNT_DECREASE
};

static bool file_exists(const string &path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

static string attack_name(AttackType a) {
    switch (a) {
        case ATTACK_NONE: return "none";
        case ORIG_INCREASE: return "orig_increase";
        case ORIG_DECREASE: return "orig_decrease";
        case LAP_FIXED_INCREASE: return "lap_fixed_increase";
        case LAP_FIXED_DECREASE: return "lap_fixed_decrease";
        case LAP_SCALE_INCREASE: return "lap_scale_increase";
        case LAP_SCALE_DECREASE: return "lap_scale_decrease";
        case LAP_COUNT_INCREASE: return "lap_count_increase";
        case LAP_COUNT_DECREASE: return "lap_count_decrease";
    }
    return "unknown";
}

static AttackType parse_attack(const string &s) {
    if (s == "none") return ATTACK_NONE;
    if (s == "orig_increase") return ORIG_INCREASE;
    if (s == "orig_decrease") return ORIG_DECREASE;
    if (s == "lap_fixed_increase") return LAP_FIXED_INCREASE;
    if (s == "lap_fixed_decrease") return LAP_FIXED_DECREASE;
    if (s == "lap_scale_increase") return LAP_SCALE_INCREASE;
    if (s == "lap_scale_decrease") return LAP_SCALE_DECREASE;
    if (s == "lap_count_increase") return LAP_COUNT_INCREASE;
    if (s == "lap_count_decrease") return LAP_COUNT_DECREASE;
    cerr << "Unknown attack: " << s << endl;
    exit(1);
}

struct GraphData {
    int n;
    long long edges;
    vector< unordered_set<int> > adj_set;
    vector< vector<int> > adj;
};

static double uniform01(mt19937_64 &rng) {
    static uniform_real_distribution<double> dist(0.0, 1.0);
    return dist(rng);
}

static double laplace_noise(double scale, mt19937_64 &rng) {
    if (scale <= 0.0) return 0.0;
    double u = uniform01(rng) - 0.5; // (-0.5, 0.5)
    if (u == 0.0) return 0.0;
    double sign = (u < 0.0 ? -1.0 : 1.0);
    return -scale * sign * log(1.0 - 2.0 * fabs(u));
}

static void build_sorted_adj(GraphData &g) {
    g.adj.assign(g.n, vector<int>());
    long long m2 = 0;
    for (int i = 0; i < g.n; ++i) {
        g.adj[i].reserve(g.adj_set[i].size());
        for (unordered_set<int>::const_iterator it = g.adj_set[i].begin(); it != g.adj_set[i].end(); ++it) {
            g.adj[i].push_back(*it);
        }
        sort(g.adj[i].begin(), g.adj[i].end());
        m2 += (long long)g.adj[i].size();
    }
    g.edges = m2 / 2;
}

static bool parse_edge_line(const string &line, long long &u, long long &v) {
    string s = line;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == ',' || s[i] == '\t' || s[i] == ';') s[i] = ' ';
    }
    stringstream ss(s);
    if (!(ss >> u >> v)) return false;
    return true;
}

static GraphData load_graph(const string &edge_file, int n_arg) {
    ifstream fin(edge_file.c_str());
    if (!fin) {
        cerr << "Cannot open edge file: " << edge_file << endl;
        exit(1);
    }

    vector< pair<int,int> > edges_tmp;
    string line;
    long long max_id = -1;
    long long read_lines = 0, kept_lines = 0;

    while (getline(fin, line)) {
        ++read_lines;
        if (line.size() == 0) continue;
        if (line[0] == '#') continue;
        long long u_ll, v_ll;
        if (!parse_edge_line(line, u_ll, v_ll)) continue;
        if (u_ll < 0 || v_ll < 0 || u_ll == v_ll) continue;
        if (n_arg > 0) {
            if (u_ll >= n_arg || v_ll >= n_arg) continue;
        }
        max_id = max(max_id, max(u_ll, v_ll));
        edges_tmp.push_back(make_pair((int)u_ll, (int)v_ll));
        ++kept_lines;
    }

    GraphData g;
    if (n_arg > 0) g.n = n_arg;
    else g.n = (int)(max_id + 1);
    if (g.n <= 0) {
        cerr << "No valid edges or invalid n." << endl;
        exit(1);
    }
    g.adj_set.assign(g.n, unordered_set<int>());

    for (size_t i = 0; i < edges_tmp.size(); ++i) {
        int u = edges_tmp[i].first;
        int v = edges_tmp[i].second;
        if (u < 0 || v < 0 || u >= g.n || v >= g.n || u == v) continue;
        if (g.adj_set[u].insert(v).second) {
            g.adj_set[v].insert(u);
        }
    }
    build_sorted_adj(g);
    cerr << "[Load] n=" << g.n << " edges=" << g.edges
         << " read_lines=" << read_lines << " kept_lines=" << kept_lines << endl;
    return g;
}

static vector<char> choose_malicious(int n, double malicious_ratio, mt19937_64 &rng, int &mal_count) {
    if (malicious_ratio < 0.0) malicious_ratio = 0.0;
    if (malicious_ratio > 1.0) malicious_ratio = 1.0;
    mal_count = (int)floor(n * malicious_ratio + 1e-12);
    vector<int> ids(n);
    for (int i = 0; i < n; ++i) ids[i] = i;
    shuffle(ids.begin(), ids.end(), rng);
    vector<char> mal(n, 0);
    for (int i = 0; i < mal_count; ++i) mal[ids[i]] = 1;
    return mal;
}

static long long apply_original_attack(GraphData &g, const vector<char> &mal, AttackType attack,
                                       double poison_prob, mt19937_64 &rng) {
    if (attack != ORIG_INCREASE && attack != ORIG_DECREASE) return 0;
    if (poison_prob < 0.0) poison_prob = 0.0;
    if (poison_prob > 1.0) poison_prob = 1.0;
    long long changed = 0;
    vector<int> malicious_nodes;
    for (int i = 0; i < g.n; ++i) if (mal[i]) malicious_nodes.push_back(i);

    if (attack == ORIG_INCREASE) {
        for (size_t a = 0; a < malicious_nodes.size(); ++a) {
            int u = malicious_nodes[a];
            for (size_t b = a + 1; b < malicious_nodes.size(); ++b) {
                int v = malicious_nodes[b];
                if (g.adj_set[u].find(v) == g.adj_set[u].end()) {
                    if (uniform01(rng) < poison_prob) {
                        g.adj_set[u].insert(v);
                        g.adj_set[v].insert(u);
                        ++changed;
                    }
                }
            }
        }
    } else if (attack == ORIG_DECREASE) {
        vector< pair<int,int> > to_remove;
        for (int u = 0; u < g.n; ++u) {
            if (!mal[u]) continue;
            for (unordered_set<int>::const_iterator it = g.adj_set[u].begin(); it != g.adj_set[u].end(); ++it) {
                int v = *it;
                if (u < v && mal[v]) {
                    if (uniform01(rng) < poison_prob) to_remove.push_back(make_pair(u, v));
                }
            }
        }
        for (size_t k = 0; k < to_remove.size(); ++k) {
            int u = to_remove[k].first;
            int v = to_remove[k].second;
            g.adj_set[u].erase(v);
            g.adj_set[v].erase(u);
            ++changed;
        }
    }
    build_sorted_adj(g);
    return changed;
}

static long long count_triangles_and_local(const GraphData &g, vector<long long> &local_tri) {
    local_tri.assign(g.n, 0LL);
    long long total = 0;
    for (int u = 0; u < g.n; ++u) {
        const vector<int> &Nu = g.adj[u];
        for (size_t idx = 0; idx < Nu.size(); ++idx) {
            int v = Nu[idx];
            if (v <= u) continue;
            const vector<int> &Nv = g.adj[v];
            vector<int>::const_iterator it1 = upper_bound(Nu.begin(), Nu.end(), v);
            vector<int>::const_iterator it2 = upper_bound(Nv.begin(), Nv.end(), v);
            while (it1 != Nu.end() && it2 != Nv.end()) {
                if (*it1 == *it2) {
                    int w = *it1;
                    ++local_tri[u];
                    ++local_tri[v];
                    ++local_tri[w];
                    ++total;
                    ++it1;
                    ++it2;
                } else if (*it1 < *it2) {
                    ++it1;
                } else {
                    ++it2;
                }
            }
        }
    }
    return total;
}

static int max_common_neighbor_count_for_node(const GraphData &g, int v) {
    unordered_map<int, int> cnt;
    const vector<int> &Nv = g.adj[v];
    for (size_t a = 0; a < Nv.size(); ++a) {
        int u = Nv[a];
        const vector<int> &Nu = g.adj[u];
        for (size_t b = 0; b < Nu.size(); ++b) {
            int w = Nu[b];
            if (w == v) continue;
            ++cnt[w];
        }
    }
    int best = 0;
    for (unordered_map<int,int>::const_iterator it = cnt.begin(); it != cnt.end(); ++it) {
        if (it->second > best) best = it->second;
    }
    return best;
}

struct Phase1Result {
    double lambda;
    int h;
    double max_d_tail;
    double max_c_dagger;
};

static Phase1Result optimized_two_phase_lambda(const GraphData &g, double eps1, double eps2,
                                                double delta, int h_prime, mt19937_64 &rng) {
    if (eps1 <= 0.0 || eps2 <= 0.0) {
        cerr << "eps1 and eps2 must be positive." << endl;
        exit(1);
    }
    if (delta <= 0.0 || delta >= 1.0) {
        cerr << "delta must be in (0,1)." << endl;
        exit(1);
    }
    if (h_prime < 1) h_prime = 1;
    if (h_prime > g.n - 2) h_prime = max(1, g.n - 2);

    const double half_eps1 = 0.5 * eps1;
    const double lambda_d = 2.0 / half_eps1; // Algorithm 1 Line 1
    const double delta_prime = delta / (2.0 * h_prime + 2.0); // Algorithm 1 Line 2
    const double log_term = log(1.0 / (2.0 * delta_prime));

    vector<double> d_top(g.n, 0.0);
    for (int i = 0; i < g.n; ++i) {
        d_top[i] = (double)g.adj[i].size() + laplace_noise(lambda_d, rng) + lambda_d * log_term;
        if (d_top[i] < 0.0) d_top[i] = 0.0;
    }

    vector<int> order(g.n);
    for (int i = 0; i < g.n; ++i) order[i] = i;
    sort(order.begin(), order.end(), [&](int a, int b) {
        if (d_top[a] != d_top[b]) return d_top[a] > d_top[b];
        return a < b;
    });

    int chosen_i = h_prime;
    int max_loop = min(h_prime, max(1, g.n - 2));
    for (int i = 1; i <= max_loop; ++i) {
        int idx = min(i + 1, g.n - 1); // v_[i+2] in 1-based notation
        double threshold = ((double)i / half_eps1) * log_term;
        if (threshold >= d_top[order[idx]]) {
            chosen_i = i;
            break;
        }
    }
    int h = (chosen_i + 1) / 2; // ceil(i/2)
    if (h < 1) h = 1;
    if (h > g.n - 1) h = g.n - 1;

    const double lambda_c = (double)h / half_eps1; // Algorithm 1 Line 12
    double max_c_dagger = 0.0;
    for (int pos = 1; pos <= h && pos < g.n; ++pos) { // S={v_[2],...,v_[h+1]}
        int v = order[pos];
        int c = max_common_neighbor_count_for_node(g, v);
        double c_top = (double)c + laplace_noise(lambda_c, rng) + lambda_c * log_term;
        if (c_top < 0.0) c_top = 0.0;
        double c_dagger = min(c_top, d_top[v]);
        if (c_dagger > max_c_dagger) max_c_dagger = c_dagger;
    }

    int tail_idx = min(h_prime + 1, g.n - 1); // v_[h'+2] in 1-based notation
    double d_tail = d_top[order[tail_idx]];
    double upper = max(d_tail, max_c_dagger);

    Phase1Result r;
    r.lambda = 3.0 * upper / eps2; // Algorithm 1 Line 17
    r.h = h;
    r.max_d_tail = d_tail;
    r.max_c_dagger = max_c_dagger;
    return r;
}

static double malicious_bias(AttackType attack, double lap_strength, double lambda,
                             long long local_count) {
    double sign = 0.0;
    if (attack == LAP_FIXED_INCREASE || attack == LAP_SCALE_INCREASE || attack == LAP_COUNT_INCREASE) sign = 1.0;
    if (attack == LAP_FIXED_DECREASE || attack == LAP_SCALE_DECREASE || attack == LAP_COUNT_DECREASE) sign = -1.0;
    if (sign == 0.0) return 0.0;

    if (attack == LAP_FIXED_INCREASE || attack == LAP_FIXED_DECREASE) {
        return sign * lap_strength;
    }
    if (attack == LAP_SCALE_INCREASE || attack == LAP_SCALE_DECREASE) {
        return sign * lap_strength * lambda;
    }
    if (attack == LAP_COUNT_INCREASE || attack == LAP_COUNT_DECREASE) {
        return sign * lap_strength * (double)local_count;
    }
    return 0.0;
}

static void usage() {
    cerr << "USAGE:\n"
         << "  ./DDP_Phase2_Robust [edge_file] [n|-1] [eps] [delta] [h_prime] [runs] "
         << "[attack] [mal_ratio] [orig_poison_prob] [lap_strength] [seed] [out_csv] [eps1_frac]\n\n"
         << "Attacks:\n"
         << "  none\n"
         << "  orig_increase, orig_decrease\n"
         << "  lap_fixed_increase, lap_fixed_decrease\n"
         << "  lap_scale_increase, lap_scale_decrease\n"
         << "  lap_count_increase, lap_count_decrease\n\n"
         << "Notes:\n"
         << "  eps1 = eps * eps1_frac, eps2 = eps - eps1. Default eps1_frac is 0.1.\n"
         << "  orig_poison_prob is used only by original-data attacks.\n"
         << "  lap_strength is used only by Phase-2 Laplace report attacks.\n";
}

int main(int argc, char **argv) {
    if (argc < 13 || argc > 14) {
        usage();
        return 1;
    }

    string edge_file = argv[1];
    int n_arg = atoi(argv[2]);
    double eps = atof(argv[3]);
    double delta = atof(argv[4]);
    int h_prime = atoi(argv[5]);
    int runs = atoi(argv[6]);
    AttackType attack = parse_attack(argv[7]);
    double mal_ratio = atof(argv[8]);
    double orig_poison_prob = atof(argv[9]);
    double lap_strength = atof(argv[10]);
    unsigned long long seed = strtoull(argv[11], NULL, 10);
    string out_csv = argv[12];
    double eps1_frac = 0.1;
    if (argc == 14) eps1_frac = atof(argv[13]);

    if (eps <= 0.0 || eps1_frac <= 0.0 || eps1_frac >= 1.0 || runs <= 0) {
        cerr << "Invalid eps / eps1_frac / runs." << endl;
        return 1;
    }
    const double eps1 = eps * eps1_frac;
    const double eps2 = eps - eps1;

    GraphData clean_graph = load_graph(edge_file, n_arg);
    vector<long long> clean_local;
    auto t0 = chrono::steady_clock::now();
    long long clean_tri = count_triangles_and_local(clean_graph, clean_local);
    auto t1 = chrono::steady_clock::now();
    cerr << "[Exact clean] triangles=" << clean_tri << " edges=" << clean_graph.edges
         << " count_time=" << chrono::duration<double>(t1 - t0).count() << "s" << endl;

    bool need_header = !file_exists(out_csv);
    ofstream fout(out_csv.c_str(), ios::app);
    if (!fout) {
        cerr << "Cannot open output csv: " << out_csv << endl;
        return 1;
    }
    if (need_header) {
        fout << "run,attack,n,eps,eps1,eps2,delta,h_prime,h,mal_ratio,mal_count,"
             << "orig_poison_prob,lap_strength,edges_clean,edges_protocol,changed_edges,"
             << "clean_triangles,protocol_triangles,lambda,max_d_tail,max_c_dagger,"
             << "estimate,rel_clean,rel_protocol,changed_reports,bias_sum,phase2_noise_sum,time_sec,seed\n";
    }
    fout << setprecision(15);

    for (int run = 0; run < runs; ++run) {
        mt19937_64 rng(seed + (unsigned long long)run * 104729ULL + 17ULL);
        GraphData g = clean_graph; // copies adj_set and adj; original attack modifies this copy

        int mal_count = 0;
        vector<char> malicious = choose_malicious(g.n, mal_ratio, rng, mal_count);

        auto run_t0 = chrono::steady_clock::now();

        long long changed_edges = apply_original_attack(g, malicious, attack, orig_poison_prob, rng);

        vector<long long> local_tri;
        long long protocol_tri = count_triangles_and_local(g, local_tri);

        Phase1Result phase1 = optimized_two_phase_lambda(g, eps1, eps2, delta, h_prime, rng);
        double lambda = phase1.lambda;

        double sum_reports = 0.0;
        double bias_sum = 0.0;
        double noise_sum = 0.0;
        long long changed_reports = 0;

        for (int i = 0; i < g.n; ++i) {
            double noise = laplace_noise(lambda, rng);
            double report = (double)local_tri[i] + noise;
            double bias = 0.0;
            if (malicious[i]) {
                bias = malicious_bias(attack, lap_strength, lambda, local_tri[i]);
                if (bias != 0.0) ++changed_reports;
                report += bias;
            }
            sum_reports += report;
            bias_sum += bias;
            noise_sum += noise;
        }
        double estimate = sum_reports / 3.0;
        double rel_clean = fabs(estimate - (double)clean_tri) / max(1.0, (double)clean_tri);
        double rel_protocol = fabs(estimate - (double)protocol_tri) / max(1.0, (double)protocol_tri);

        auto run_t1 = chrono::steady_clock::now();
        double time_sec = chrono::duration<double>(run_t1 - run_t0).count();

        cerr << "[Run " << run << "] attack=" << attack_name(attack)
             << " eps=(" << eps1 << "," << eps2 << ") mal=" << mal_count
             << " changed_edges=" << changed_edges
             << " changed_reports=" << changed_reports
             << " lambda=" << lambda
             << " clean=" << clean_tri << " protocol=" << protocol_tri
             << " est=" << estimate
             << " rel_clean=" << rel_clean
             << " rel_protocol=" << rel_protocol
             << " time=" << time_sec << "s" << endl;

        fout << run << ',' << attack_name(attack) << ',' << g.n << ','
             << eps << ',' << eps1 << ',' << eps2 << ',' << delta << ','
             << h_prime << ',' << phase1.h << ',' << mal_ratio << ',' << mal_count << ','
             << orig_poison_prob << ',' << lap_strength << ','
             << clean_graph.edges << ',' << g.edges << ',' << changed_edges << ','
             << clean_tri << ',' << protocol_tri << ',' << lambda << ','
             << phase1.max_d_tail << ',' << phase1.max_c_dagger << ','
             << estimate << ',' << rel_clean << ',' << rel_protocol << ','
             << changed_reports << ',' << bias_sum << ',' << noise_sum << ','
             << time_sec << ',' << (seed + (unsigned long long)run * 104729ULL + 17ULL) << '\n';
        fout.flush();
    }
    return 0;
}
