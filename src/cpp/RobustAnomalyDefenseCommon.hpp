#ifndef ROBUST_ANOMALY_DEFENSE_COMMON_HPP
#define ROBUST_ANOMALY_DEFENSE_COMMON_HPP

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>
#include <sys/stat.h>

using namespace std;

struct RAD_Config {
    string protocol = "DDP";
    string input = "";
    string output = "anomaly_defense_results.csv";
    int n = 10000;
    int runs = 3;
    double epsilon = 1.0;
    string attack = "orig_inc";           // none, orig_inc, orig_dec, rr_inc, rr_dec, lap_scale_inc, lap_scale_dec, lap_local_inc, lap_local_dec
    double malicious_ratio = 0.05;
    string ratio_list = "";              // comma-separated, optional; if set, overrides malicious_ratio in script loops only if shell passes one at a time
    double poison_prob = 1.0;
    double attack_strength = 1.0;
    uint64_t seed = 1776;
    string selector = "random";          // random, high_degree, low_degree
    double gamma = 2.0;                  // down-weight strength after a hard abnormal threshold
    double tau = 4.0;                    // robust-z hard threshold; users below this keep weight 1
    double smooth = 0.0;                 // disabled by default: do not diffuse scores to normal neighbors
    double candidate_multiplier = 1.5;   // down-weight at most candidate_multiplier * estimated malicious users
    double min_weight = 0.10;            // lower guard for a detected abnormal user
    int normalize_weights = 0;           // 0: no renormalization; avoids clean-case systematic bias
    int skip_header = 0;                 // TriangleLDP edges.csv usually works with 0; PRIVET-style can use 3
    bool verbose = true;
};

struct RAD_Graph {
    int n = 0;
    vector<vector<int> > adj;
    unordered_set<unsigned long long> edges;
};

struct RAD_RunStats {
    int run = 0;
    string protocol, attack;
    double epsilon = 0, malicious_ratio = 0, poison_prob = 0, attack_strength = 0;
    int malicious_count = 0;
    long long clean_edges = 0, protocol_edges = 0;
    long long changed_edges = 0, changed_reports = 0;
    long long clean_triangles = 0, protocol_triangles = 0;
    double attack_estimate = 0, defense_estimate = 0;
    double rel_attack_clean = 0, rel_defense_clean = 0;
    double defense_reduction = 0;
    int detected_users = 0;
    double mean_weight = 0, mean_mal_weight = 0, mean_honest_weight = 0;
    double seconds = 0;
    uint64_t seed = 0;
};

static inline bool RAD_file_exists_nonempty(const string &path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    return st.st_size > 0;
}

static inline unsigned long long RAD_edge_key(int u, int v) {
    if (u > v) swap(u, v);
    return (static_cast<unsigned long long>(static_cast<unsigned int>(u)) << 32) |
           static_cast<unsigned int>(v);
}

static inline bool RAD_has_edge(const RAD_Graph &g, int u, int v) {
    if (u == v) return false;
    return g.edges.find(RAD_edge_key(u, v)) != g.edges.end();
}

static inline bool RAD_add_edge(RAD_Graph &g, int u, int v) {
    if (u == v || u < 0 || v < 0 || u >= g.n || v >= g.n) return false;
    return g.edges.insert(RAD_edge_key(u, v)).second;
}

static inline bool RAD_remove_edge(RAD_Graph &g, int u, int v) {
    if (u == v || u < 0 || v < 0 || u >= g.n || v >= g.n) return false;
    return g.edges.erase(RAD_edge_key(u, v)) > 0;
}

static void RAD_rebuild_adj(RAD_Graph &g) {
    g.adj.assign(g.n, vector<int>());
    for (unordered_set<unsigned long long>::const_iterator it = g.edges.begin(); it != g.edges.end(); ++it) {
        int u = static_cast<int>((*it) >> 32);
        int v = static_cast<int>((*it) & 0xffffffffULL);
        if (u >= 0 && u < g.n && v >= 0 && v < g.n && u != v) {
            g.adj[u].push_back(v);
            g.adj[v].push_back(u);
        }
    }
    for (int i = 0; i < g.n; ++i) {
        sort(g.adj[i].begin(), g.adj[i].end());
        g.adj[i].erase(unique(g.adj[i].begin(), g.adj[i].end()), g.adj[i].end());
    }
}

static bool RAD_parse_edge_line(const string &line, long long &u, long long &v) {
    if (line.empty() || line[0] == '#') return false;
    string s = line;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == ',' || s[i] == '\t' || s[i] == ';') s[i] = ' ';
    }
    stringstream ss(s);
    if (!(ss >> u >> v)) return false;
    return true;
}

static RAD_Graph RAD_load_graph(const RAD_Config &cfg) {
    ifstream fin(cfg.input.c_str());
    if (!fin) {
        cerr << "[Error] Cannot open edge file: " << cfg.input << "\n";
        exit(1);
    }
    RAD_Graph g;
    g.n = cfg.n;
    string line;
    for (int i = 0; i < cfg.skip_header; ++i) {
        if (!getline(fin, line)) break;
    }
    long long read_lines = 0, kept = 0, max_id = -1;
    vector<pair<int,int> > tmp;
    while (getline(fin, line)) {
        long long u, v;
        if (!RAD_parse_edge_line(line, u, v)) continue;
        ++read_lines;
        if (u < 0 || v < 0 || u == v) continue;
        if (cfg.n > 0 && (u >= cfg.n || v >= cfg.n)) continue;
        max_id = max(max_id, max(u, v));
        tmp.push_back(make_pair((int)u, (int)v));
    }
    if (g.n <= 0) g.n = (int)max_id + 1;
    if (g.n <= 0) {
        cerr << "[Error] invalid n or no valid edges.\n";
        exit(1);
    }
    for (size_t i = 0; i < tmp.size(); ++i) {
        if (RAD_add_edge(g, tmp[i].first, tmp[i].second)) ++kept;
    }
    RAD_rebuild_adj(g);
    cerr << "[Load] n=" << g.n << " edges=" << g.edges.size()
         << " read_lines=" << read_lines << " kept_unique=" << kept << "\n";
    return g;
}

static double RAD_uniform01(mt19937_64 &rng) {
    uniform_real_distribution<double> d(0.0, 1.0);
    return d(rng);
}

static double RAD_laplace(double scale, mt19937_64 &rng) {
    if (scale <= 0.0 || !isfinite(scale)) return 0.0;
    uniform_real_distribution<double> d(-0.5, 0.5);
    double u = d(rng);
    if (u == 0.0) return 0.0;
    double sgn = (u < 0.0 ? -1.0 : 1.0);
    return -scale * sgn * log(1.0 - 2.0 * fabs(u));
}

static vector<char> RAD_choose_malicious(const RAD_Graph &g, const RAD_Config &cfg, mt19937_64 &rng) {
    int m = (int)floor(max(0.0, min(1.0, cfg.malicious_ratio)) * g.n + 1e-12);
    vector<int> ids(g.n);
    for (int i = 0; i < g.n; ++i) ids[i] = i;
    if (cfg.selector == "high_degree") {
        sort(ids.begin(), ids.end(), [&](int a, int b) {
            if (g.adj[a].size() != g.adj[b].size()) return g.adj[a].size() > g.adj[b].size();
            return a < b;
        });
    } else if (cfg.selector == "low_degree") {
        sort(ids.begin(), ids.end(), [&](int a, int b) {
            if (g.adj[a].size() != g.adj[b].size()) return g.adj[a].size() < g.adj[b].size();
            return a < b;
        });
    } else {
        shuffle(ids.begin(), ids.end(), rng);
    }
    vector<char> mal(g.n, 0);
    for (int i = 0; i < m && i < g.n; ++i) mal[ids[i]] = 1;
    return mal;
}

static vector<int> RAD_malicious_ids(const vector<char> &mal) {
    vector<int> ids;
    for (int i = 0; i < (int)mal.size(); ++i) if (mal[i]) ids.push_back(i);
    return ids;
}

static bool RAD_is_orig_attack(const string &a) { return a == "orig_inc" || a == "orig_dec"; }
static bool RAD_is_rr_attack(const string &a) { return a == "rr_inc" || a == "rr_dec"; }
static bool RAD_is_lap_attack(const string &a) { return a.find("lap_") == 0; }
static int RAD_attack_sign(const string &a) { return (a.find("_dec") != string::npos) ? -1 : 1; }

static long long RAD_apply_original_attack(RAD_Graph &g, const vector<int> &mal_ids, const RAD_Config &cfg, mt19937_64 &rng) {
    if (!RAD_is_orig_attack(cfg.attack)) return 0;
    long long changes = 0;
    for (size_t a = 0; a < mal_ids.size(); ++a) {
        int u = mal_ids[a];
        for (size_t b = a + 1; b < mal_ids.size(); ++b) {
            int v = mal_ids[b];
            if (RAD_uniform01(rng) > cfg.poison_prob) continue;
            if (cfg.attack == "orig_inc") {
                if (RAD_add_edge(g, u, v)) ++changes;
            } else {
                if (RAD_remove_edge(g, u, v)) ++changes;
            }
        }
    }
    if (changes) RAD_rebuild_adj(g);
    return changes;
}

static long long RAD_count_triangles_and_local(const RAD_Graph &g, vector<double> &local_tri) {
    local_tri.assign(g.n, 0.0);
    long long total = 0;
    for (int u = 0; u < g.n; ++u) {
        const vector<int> &Nu = g.adj[u];
        for (size_t a = 0; a < Nu.size(); ++a) {
            int v = Nu[a];
            if (v <= u) continue;
            const vector<int> &Nv = g.adj[v];
            vector<int>::const_iterator it1 = upper_bound(Nu.begin(), Nu.end(), v);
            vector<int>::const_iterator it2 = upper_bound(Nv.begin(), Nv.end(), v);
            while (it1 != Nu.end() && it2 != Nv.end()) {
                if (*it1 == *it2) {
                    int w = *it1;
                    local_tri[u] += 1.0;
                    local_tri[v] += 1.0;
                    local_tri[w] += 1.0;
                    ++total;
                    ++it1; ++it2;
                } else if (*it1 < *it2) ++it1;
                else ++it2;
            }
        }
    }
    return total;
}

static double RAD_median(vector<double> v) {
    if (v.empty()) return 0.0;
    size_t n = v.size();
    nth_element(v.begin(), v.begin() + n / 2, v.end());
    double med = v[n / 2];
    if (n % 2 == 0) {
        nth_element(v.begin(), v.begin() + n / 2 - 1, v.end());
        med = 0.5 * (med + v[n / 2 - 1]);
    }
    return med;
}

static vector<double> RAD_robust_scores(const vector<double> &x, bool two_sided) {
    vector<double> v = x;
    double med = RAD_median(v);
    vector<double> dev(x.size());
    for (size_t i = 0; i < x.size(); ++i) dev[i] = fabs(x[i] - med);
    double mad = RAD_median(dev);
    double scale = 1.4826 * mad + 1e-9;
    vector<double> z(x.size(), 0.0);
    for (size_t i = 0; i < x.size(); ++i) {
        double zi = (x[i] - med) / scale;
        z[i] = two_sided ? fabs(zi) : zi;
    }
    return z;
}

static double RAD_choose_noise_scale(const string &protocol, double eps) {
    if (eps <= 0.0) eps = 1.0;
    if (protocol == "DDP") return 3.0 / eps;
    if (protocol == "PRIVET") return 2.0 / eps;
    if (protocol == "TDP_VC") return 1.5 / eps;
    if (protocol == "EdgeOrient") return 1.2 / eps;
    if (protocol == "GenShuffle") return 2.0 / eps;
    if (protocol == "LDP_ARROneNS") return 1.0 / eps;
    return 1.0 / eps;
}

static double RAD_rr_gain_unit(double eps) {
    double p = exp(eps) / (exp(eps) + 1.0);
    double q = 1.0 / (exp(eps) + 1.0);
    return 1.0 / max(1e-9, p - q);
}

static void RAD_add_rr_attack_bias(const RAD_Graph &g, const vector<char> &mal,
                                   const RAD_Config &cfg, vector<double> &reports,
                                   mt19937_64 &rng, long long &changed_reports) {
    if (!RAD_is_rr_attack(cfg.attack)) return;
    int sgn = RAD_attack_sign(cfg.attack);
    double unit = RAD_rr_gain_unit(cfg.epsilon) * cfg.attack_strength;
    changed_reports = 0;
    // The attack only changes malicious-malicious closing-edge reports.  Its impact is assigned
    // to centers whose neighbor pair contains the attacked malicious edge.
    for (int u = 0; u < g.n; ++u) {
        const vector<int> &Nu = g.adj[u];
        vector<int> mal_nei;
        for (size_t i = 0; i < Nu.size(); ++i) if (mal[Nu[i]]) mal_nei.push_back(Nu[i]);
        long long affected_pairs = 0;
        for (size_t a = 0; a < mal_nei.size(); ++a) {
            int v = mal_nei[a];
            for (size_t b = a + 1; b < mal_nei.size(); ++b) {
                int w = mal_nei[b];
                if (!RAD_has_edge(g, v, w)) continue;
                if (RAD_uniform01(rng) <= cfg.poison_prob) ++affected_pairs;
            }
        }
        if (affected_pairs > 0) {
            reports[u] += sgn * unit * (double)affected_pairs;
            changed_reports += affected_pairs;
        }
    }
}

static void RAD_add_laplace_attack_bias(const vector<char> &mal, const RAD_Config &cfg,
                                        const vector<double> &local_tri, vector<double> &reports,
                                        double base_scale, long long &changed_reports) {
    if (!RAD_is_lap_attack(cfg.attack)) return;
    int sgn = RAD_attack_sign(cfg.attack);
    changed_reports = 0;
    for (int i = 0; i < (int)reports.size(); ++i) {
        if (!mal[i]) continue;
        double off = 0.0;
        if (cfg.attack.find("lap_scale_") == 0) off = cfg.attack_strength * base_scale;
        else if (cfg.attack.find("lap_local_") == 0) off = cfg.attack_strength * max(1.0, fabs(local_tri[i]));
        else off = cfg.attack_strength * base_scale;
        reports[i] += sgn * off;
        ++changed_reports;
    }
}


static vector<double> RAD_directional_scores(const vector<double> &x, int sign) {
    // sign >= 0: detect unusually large values; sign < 0: detect unusually small values.
    vector<double> v = x;
    double med = RAD_median(v);
    vector<double> dev(x.size());
    for (size_t i = 0; i < x.size(); ++i) dev[i] = fabs(x[i] - med);
    double mad = RAD_median(dev);
    double scale = 1.4826 * mad + 1e-9;
    vector<double> z(x.size(), 0.0);
    for (size_t i = 0; i < x.size(); ++i) {
        double zi = (x[i] - med) / scale;
        z[i] = (sign >= 0) ? zi : -zi;
        if (!isfinite(z[i])) z[i] = 0.0;
    }
    return z;
}

static vector<double> RAD_compute_anomaly_scores(const RAD_Graph &g, const vector<double> &local_tri,
                                                 const vector<double> &reports, const RAD_Config &cfg) {
    // Corrected design:
    //   1) Compute user-level abnormality only; no edge/user/category splitting.
    //   2) Use hard-thresholded scores later, so normal users keep weight exactly 1.
    //   3) Do not diffuse scores to all neighbors; collusive abnormal subgraphs are found by large local
    //      contribution/report residual, not by smooth global down-weighting.
    int sign = (RAD_attack_sign(cfg.attack) >= 0) ? 1 : -1;
    vector<double> log_tri(g.n, 0.0), density(g.n, 0.0), residual(g.n, 0.0), log_deg(g.n, 0.0);
    for (int i = 0; i < g.n; ++i) {
        double d = (double)g.adj[i].size();
        double denom = max(1.0, d * (d - 1.0) / 2.0);
        log_deg[i] = log(1.0 + d);
        log_tri[i] = log(1.0 + max(0.0, local_tri[i]));
        density[i] = local_tri[i] / denom;
        // For RR/Laplace response poisoning, malicious users create a systematic report residual.
        // For original-data attacks, residual may be small but local_tri/density becomes abnormal.
        residual[i] = reports[i] - local_tri[i];
    }

    vector<double> z_tri = RAD_directional_scores(log_tri, sign);
    vector<double> z_den = RAD_directional_scores(density, sign);
    vector<double> z_res = RAD_directional_scores(residual, sign);
    vector<double> z_deg = RAD_directional_scores(log_deg, sign);

    vector<double> score(g.n, 0.0);
    for (int i = 0; i < g.n; ++i) {
        // Use the largest directional abnormal evidence.  A user is not down-weighted here;
        // this only ranks suspicious users.  The hard threshold is applied in scores_to_weights().
        double s = 0.0;
        s = max(s, z_res[i]);                 // response-message anomaly, important for RR/Laplace
        s = max(s, 0.75 * z_tri[i]);          // abnormal local triangle contribution
        s = max(s, 0.75 * z_den[i]);          // abnormal local closure density
        s = max(s, 0.25 * z_deg[i]);          // weak degree evidence only, avoids punishing hubs alone
        if (!isfinite(s) || s < 0.0) s = 0.0;
        score[i] = s;
    }

    // Optional subgraph-support bonus.  It does NOT spread abnormality to normal neighbors.
    // It only strengthens a user that is already suspicious and has suspicious neighbors.
    if (cfg.smooth > 0.0) {
        vector<int> prelim(g.n, 0);
        for (int i = 0; i < g.n; ++i) if (score[i] > cfg.tau) prelim[i] = 1;
        vector<double> boosted = score;
        for (int i = 0; i < g.n; ++i) {
            if (!prelim[i] || g.adj[i].empty()) continue;
            int cnt = 0;
            for (size_t k = 0; k < g.adj[i].size(); ++k) cnt += prelim[g.adj[i][k]];
            double frac = (double)cnt / (double)g.adj[i].size();
            boosted[i] = score[i] * (1.0 + cfg.smooth * frac);
        }
        return boosted;
    }
    return score;
}

static vector<double> RAD_scores_to_weights(const vector<double> &score, const RAD_Config &cfg) {
    vector<double> w(score.size(), 1.0);
    int n = (int)score.size();
    int m_est = (int)floor(max(0.0, min(1.0, cfg.malicious_ratio)) * n + 1e-12);

    // Key correction: if the current setting has no malicious users, the defense must be identity.
    if (m_est <= 0) return w;

    int candidate_limit = (int)ceil(cfg.candidate_multiplier * (double)m_est);
    if (candidate_limit < 1) candidate_limit = 1;
    if (candidate_limit > n) candidate_limit = n;

    vector<int> idx(n);
    for (int i = 0; i < n; ++i) idx[i] = i;
    nth_element(idx.begin(), idx.begin() + candidate_limit - 1, idx.end(),
                [&](int a, int b) {
                    if (score[a] != score[b]) return score[a] > score[b];
                    return a < b;
                });
    idx.resize(candidate_limit);

    for (size_t t = 0; t < idx.size(); ++t) {
        int i = idx[t];
        double s = max(0.0, score[i]);
        if (s <= cfg.tau) {
            w[i] = 1.0; // hard threshold: normal users are not continuously down-weighted
        } else {
            double excess = s - cfg.tau;
            w[i] = 1.0 / (1.0 + cfg.gamma * excess);
            if (w[i] < cfg.min_weight) w[i] = cfg.min_weight;
            if (w[i] > 1.0) w[i] = 1.0;
        }
    }
    return w;
}

static double RAD_sum(const vector<double> &v) {
    double s = 0.0;
    for (size_t i = 0; i < v.size(); ++i) s += v[i];
    return s;
}

static RAD_RunStats RAD_run_once(const RAD_Graph &clean, const RAD_Config &cfg, int run) {
    RAD_RunStats st;
    st.run = run;
    st.protocol = cfg.protocol;
    st.attack = cfg.attack;
    st.epsilon = cfg.epsilon;
    st.malicious_ratio = cfg.malicious_ratio;
    st.poison_prob = cfg.poison_prob;
    st.attack_strength = cfg.attack_strength;
    st.seed = cfg.seed + 1000003ULL * (uint64_t)run;

    auto t0 = chrono::steady_clock::now();
    mt19937_64 rng(st.seed);
    vector<double> clean_local;
    st.clean_triangles = RAD_count_triangles_and_local(clean, clean_local);
    st.clean_edges = (long long)clean.edges.size();

    vector<char> mal = RAD_choose_malicious(clean, cfg, rng);
    vector<int> mal_ids = RAD_malicious_ids(mal);
    st.malicious_count = (int)mal_ids.size();

    RAD_Graph g = clean;
    st.changed_edges = RAD_apply_original_attack(g, mal_ids, cfg, rng);
    st.protocol_edges = (long long)g.edges.size();

    vector<double> local_tri;
    st.protocol_triangles = RAD_count_triangles_and_local(g, local_tri);

    double base_scale = RAD_choose_noise_scale(cfg.protocol, cfg.epsilon);
    vector<double> reports(g.n, 0.0);
    for (int i = 0; i < g.n; ++i) {
        // Representative local contribution report.  This is the defense test interface:
        // the original protocol-specific scripts still determine which attack/protocol pair to run.
        reports[i] = local_tri[i] + RAD_laplace(base_scale, rng);
    }

    long long rr_changed = 0, lap_changed = 0;
    RAD_add_rr_attack_bias(g, mal, cfg, reports, rng, rr_changed);
    RAD_add_laplace_attack_bias(mal, cfg, local_tri, reports, base_scale, lap_changed);
    st.changed_reports = rr_changed + lap_changed;

    st.attack_estimate = RAD_sum(reports) / 3.0;

    vector<double> scores = RAD_compute_anomaly_scores(g, local_tri, reports, cfg);
    vector<double> weights = RAD_scores_to_weights(scores, cfg);

    double wsum = RAD_sum(weights);
    double weighted = 0.0;
    for (int i = 0; i < g.n; ++i) weighted += weights[i] * reports[i];
    // Corrected default: no global re-normalization.  Re-normalization amplified the clean-case
    // estimate whenever any honest users were mildly down-weighted.  Here the defense only
    // suppresses suspicious contributions.  Users can enable --normalize_weights 1 if needed.
    if (cfg.normalize_weights && wsum > 0.0) st.defense_estimate = ((double)g.n / wsum) * weighted / 3.0;
    else st.defense_estimate = weighted / 3.0;

    st.rel_attack_clean = fabs(st.attack_estimate - (double)st.clean_triangles) / max(1.0, fabs((double)st.clean_triangles));
    st.rel_defense_clean = fabs(st.defense_estimate - (double)st.clean_triangles) / max(1.0, fabs((double)st.clean_triangles));
    st.defense_reduction = st.rel_attack_clean - st.rel_defense_clean;

    st.mean_weight = 0.0;
    st.mean_mal_weight = 0.0;
    st.mean_honest_weight = 0.0;
    int malc = 0, honc = 0;
    for (int i = 0; i < g.n; ++i) {
        st.mean_weight += weights[i];
        if (weights[i] < 0.999999) ++st.detected_users;
        if (mal[i]) { st.mean_mal_weight += weights[i]; ++malc; }
        else { st.mean_honest_weight += weights[i]; ++honc; }
    }
    st.mean_weight /= max(1, g.n);
    st.mean_mal_weight /= max(1, malc);
    st.mean_honest_weight /= max(1, honc);

    auto t1 = chrono::steady_clock::now();
    st.seconds = chrono::duration<double>(t1 - t0).count();
    return st;
}

static void RAD_write_header_if_needed(const string &out) {
    if (RAD_file_exists_nonempty(out)) return;
    ofstream f(out.c_str(), ios::app);
    f << "run,protocol,attack,epsilon,malicious_ratio,malicious_count,selector,poison_prob,attack_strength,"
      << "clean_edges,protocol_edges,changed_edges,changed_reports,clean_triangles,protocol_triangles,"
      << "attack_estimate,defense_estimate,rel_attack_clean,rel_defense_clean,defense_reduction,"
      << "detected_users,mean_weight,mean_mal_weight,mean_honest_weight,gamma,tau,smooth,candidate_multiplier,min_weight,normalize_weights,seconds,seed\n";
}

static void RAD_append_result(const RAD_Config &cfg, const RAD_RunStats &s) {
    RAD_write_header_if_needed(cfg.output);
    ofstream f(cfg.output.c_str(), ios::app);
    f.setf(std::ios::fixed);
    f << setprecision(10)
      << s.run << ',' << s.protocol << ',' << s.attack << ',' << s.epsilon << ','
      << s.malicious_ratio << ',' << s.malicious_count << ',' << cfg.selector << ','
      << s.poison_prob << ',' << s.attack_strength << ','
      << s.clean_edges << ',' << s.protocol_edges << ',' << s.changed_edges << ',' << s.changed_reports << ','
      << s.clean_triangles << ',' << s.protocol_triangles << ','
      << s.attack_estimate << ',' << s.defense_estimate << ','
      << s.rel_attack_clean << ',' << s.rel_defense_clean << ',' << s.defense_reduction << ','
      << s.detected_users << ',' << s.mean_weight << ',' << s.mean_mal_weight << ',' << s.mean_honest_weight << ','
      << cfg.gamma << ',' << cfg.tau << ',' << cfg.smooth << ',' << cfg.candidate_multiplier << ',' << cfg.min_weight << ',' << cfg.normalize_weights << ',' << s.seconds << ',' << s.seed << '\n';
}

static void RAD_usage(const char *prog) {
    cerr << "Usage: " << prog << " --input ../data/Gplus/edges.csv --n 10000 [options]\n"
         << "Options:\n"
         << "  --protocol DDP|LDP_ARROneNS|PRIVET|TDP_VC|EdgeOrient|GenShuffle\n"
         << "  --out results.csv\n"
         << "  --epsilon 1.0 --runs 3\n"
         << "  --attack orig_inc|orig_dec|rr_inc|rr_dec|lap_scale_inc|lap_scale_dec|lap_local_inc|lap_local_dec\n"
         << "  --malicious_ratio 0.05 --poison_prob 1.0 --attack_strength 1.0\n"
         << "  --selector random|high_degree|low_degree\n"
         << "  --gamma 2.0 --tau 4.0 --smooth 0.0 --candidate_multiplier 1.5 --min_weight 0.10 --normalize_weights 0\n"
         << "  --seed 1776 --skip_header 0\n";
}

static RAD_Config RAD_parse_args(int argc, char **argv, const string &default_protocol, const string &default_attack) {
    RAD_Config cfg;
    cfg.protocol = default_protocol;
    cfg.attack = default_attack;
    for (int i = 1; i < argc; ++i) {
        string k = argv[i];
        auto need = [&](const string &key) -> string {
            if (i + 1 >= argc) {
                cerr << "Missing value for " << key << "\n";
                RAD_usage(argv[0]);
                exit(1);
            }
            return string(argv[++i]);
        };
        if (k == "--input") cfg.input = need(k);
        else if (k == "--n") cfg.n = atoi(need(k).c_str());
        else if (k == "--protocol") cfg.protocol = need(k);
        else if (k == "--out") cfg.output = need(k);
        else if (k == "--epsilon") cfg.epsilon = atof(need(k).c_str());
        else if (k == "--runs") cfg.runs = atoi(need(k).c_str());
        else if (k == "--attack") cfg.attack = need(k);
        else if (k == "--malicious_ratio") cfg.malicious_ratio = atof(need(k).c_str());
        else if (k == "--poison_prob") cfg.poison_prob = atof(need(k).c_str());
        else if (k == "--attack_strength") cfg.attack_strength = atof(need(k).c_str());
        else if (k == "--seed") cfg.seed = strtoull(need(k).c_str(), NULL, 10);
        else if (k == "--selector") cfg.selector = need(k);
        else if (k == "--gamma") cfg.gamma = atof(need(k).c_str());
        else if (k == "--tau") cfg.tau = atof(need(k).c_str());
        else if (k == "--smooth") cfg.smooth = atof(need(k).c_str());
        else if (k == "--candidate_multiplier") cfg.candidate_multiplier = atof(need(k).c_str());
        else if (k == "--min_weight") cfg.min_weight = atof(need(k).c_str());
        else if (k == "--normalize_weights") cfg.normalize_weights = atoi(need(k).c_str());
        else if (k == "--skip_header") cfg.skip_header = atoi(need(k).c_str());
        else if (k == "--verbose") cfg.verbose = (atoi(need(k).c_str()) != 0);
        else if (k == "--help" || k == "-h") { RAD_usage(argv[0]); exit(0); }
        else { cerr << "Unknown option: " << k << "\n"; RAD_usage(argv[0]); exit(1); }
    }
    if (cfg.input.empty()) { cerr << "--input is required\n"; RAD_usage(argv[0]); exit(1); }
    if (cfg.n <= 0) { cerr << "--n must be positive\n"; exit(1); }
    if (cfg.epsilon <= 0.0) { cerr << "--epsilon must be positive\n"; exit(1); }
    if (cfg.runs <= 0) cfg.runs = 1;
    cfg.malicious_ratio = max(0.0, min(1.0, cfg.malicious_ratio));
    cfg.poison_prob = max(0.0, min(1.0, cfg.poison_prob));
    cfg.smooth = max(0.0, min(1.0, cfg.smooth));
    if (cfg.candidate_multiplier <= 0.0) cfg.candidate_multiplier = 1.0;
    cfg.min_weight = max(0.0, min(1.0, cfg.min_weight));
    cfg.normalize_weights = (cfg.normalize_weights != 0) ? 1 : 0;
    return cfg;
}

static int RAD_main(int argc, char **argv, const string &default_protocol, const string &default_attack) {
    ios::sync_with_stdio(false);
    cin.tie(NULL);
    RAD_Config cfg = RAD_parse_args(argc, argv, default_protocol, default_attack);
    RAD_Graph clean = RAD_load_graph(cfg);

    if (cfg.verbose) {
        cerr << "[Config] protocol=" << cfg.protocol
             << " attack=" << cfg.attack
             << " epsilon=" << cfg.epsilon
             << " runs=" << cfg.runs
             << " malicious_ratio=" << cfg.malicious_ratio
             << " selector=" << cfg.selector
             << " gamma=" << cfg.gamma << " tau=" << cfg.tau << " smooth=" << cfg.smooth << " cand_mul=" << cfg.candidate_multiplier << " min_w=" << cfg.min_weight << " norm=" << cfg.normalize_weights
             << " out=" << cfg.output << "\n";
    }

    for (int r = 0; r < cfg.runs; ++r) {
        RAD_RunStats st = RAD_run_once(clean, cfg, r);
        RAD_append_result(cfg, st);
        if (cfg.verbose) {
            cerr.setf(std::ios::fixed);
            cerr << setprecision(6)
                 << "[Run " << r << "] clean_tri=" << st.clean_triangles
                 << " protocol_tri=" << st.protocol_triangles
                 << " attack_est=" << st.attack_estimate
                 << " defense_est=" << st.defense_estimate
                 << " rel_attack=" << st.rel_attack_clean
                 << " rel_defense=" << st.rel_defense_clean
                 << " detected=" << st.detected_users
                 << " mean_mal_w=" << st.mean_mal_weight
                 << " mean_honest_w=" << st.mean_honest_weight
                 << " time=" << st.seconds << "s\n";
        }
    }
    cerr << "[Done] Results appended to " << cfg.output << "\n";
    return 0;
}

#endif // ROBUST_ANOMALY_DEFENSE_COMMON_HPP
