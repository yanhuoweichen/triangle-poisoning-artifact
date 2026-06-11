// PRIVET.cpp
// C++ re-implementation/adaptor of PRIEVET (Edge-RLDP triangle counting)
// Designed to be placed under Triangle4CycleShuffle/cpp/ and read ../data/[Dataset]/edges.csv.
// Build: g++ -O3 -std=c++11 PRIVET_laplace_attack.cpp -o PRIVET_laplace_attack
//
// Usage:
//   ./PRIVET ../data/Gplus/edges.csv 20000 1 CaliToUpper
//   ./PRIVET ../data/Gplus/edges.csv 20000 1 CaliToLS
//   ./PRIVET ../data/Gplus/edges.csv 20000 1 CaliToTrunc
//
// Full usage:
//   ./PRIVET_laplace_attack <edge_file> <node_num> <epsilon> <scheme>
//            [delta=5e-6] [beta=0.2] [alpha=0.5] [h_prime=100]
//            [r=5] [p=0.01] [trial_num=300] [seed=1776] [dataset_name=auto]
//            [report_attack=clean] [malicious_ratio=0] [attack_lambda=0]
//            [attack_direction=1] [malicious_seed=0]
//
// Post-Laplace report attacks:
//   report_attack=clean  : no post-perturbation attack
//   report_attack=fixed  : y_i <- y_i +/- lambda
//   report_attack=scale  : y_i <- y_i +/- lambda * LaplaceScale_i
//   report_attack=count  : y_i <- y_i +/- lambda * LocalCount_i
// For CaliToTrunc, only the perturbed local count is attacked; the bias report is not attacked.
//
// Notes:
// - This file mirrors the public Python PRIEVET implementation as closely as practical.
// - It does not use SciPy sparse matrices. The sparse operations are implemented by
//   sorted adjacency lists and two-hop counting.
// - It reads Triangle4CycleShuffle-style edges.csv and skips the first 3 lines by default.
// - CaliToUpper variance intentionally mirrors the Python code's denominator behavior
//   (sumTri/6) to keep outputs comparable with the original implementation.

#include <algorithm>
#include <cmath>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

struct Params {
    string edge_file;
    int n = 0;
    double epsilon = 1.0;
    string scheme = "CaliToUpper";
    double delta = 5e-6;
    double beta = 0.2;
    double alpha = 0.5;
    int h_prime = 100;
    int r = 5;
    double p = 0.01;
    int trial_num = 300;
    uint64_t seed = 1776;
    string dataset_name = "";
    string report_attack = "clean";   // clean, fixed, scale, count
    double malicious_ratio = 0.0;     // fraction of real users controlled by attacker
    double attack_lambda = 0.0;       // attack strength
    int attack_direction = 1;         // 1=increase, -1=decrease
    uint64_t malicious_seed = 0;      // 0 means seed derived from main seed
    int skip_header = 3;
};

struct SampledData {
    // sampled triangle counts per oriented edge; aligned with adj[i]
    vector<vector<int>> tri_per_neighbor;
    vector<double> tri_sum;
    vector<double> loc_sen_max;
    double total_tri_sum = 0.0;
};

static inline string baseName(const string& path) {
    size_t slash = path.find_last_of("/\\");
    string name = (slash == string::npos) ? path : path.substr(slash + 1);
    size_t dot = name.find_last_of('.');
    if (dot != string::npos) name = name.substr(0, dot);
    return name;
}

class PRIEVET {
public:
    explicit PRIEVET(const Params& params)
        : par(params), rng(params.seed), adj(params.n), deg(params.n, 0), malicious(params.n, 0) {}

    void loadGraph() {
        ifstream fin(par.edge_file.c_str());
        if (!fin) {
            cerr << "Cannot open edge file: " << par.edge_file << endl;
            exit(1);
        }

        string line;
        for (int i = 0; i < par.skip_header; ++i) {
            if (!getline(fin, line)) break;
        }

        long long read_edges = 0;
        while (getline(fin, line)) {
            if (line.empty()) continue;
            for (char& c : line) {
                if (c == ',') c = ' ';
            }
            stringstream ss(line);
            int u, v;
            if (!(ss >> u >> v)) continue;
            if (u == v) continue;
            if (u < 0 || v < 0 || u >= par.n || v >= par.n) continue;
            adj[u].push_back(v);
            adj[v].push_back(u);
            ++read_edges;
        }

        long long undirected_edges = 0;
        for (int i = 0; i < par.n; ++i) {
            auto& a = adj[i];
            sort(a.begin(), a.end());
            a.erase(unique(a.begin(), a.end()), a.end());
            deg[i] = static_cast<int>(a.size());
            undirected_edges += deg[i];
        }
        undirected_edges /= 2;

        cout << "+ loaded graph from " << par.edge_file
             << "\n  NodeNum=" << par.n
             << "  input_edges=" << read_edges
             << "  stored_edges=" << undirected_edges << endl;
    }

    void showInfo() {
        const vector<double>& tri = triCnt();
        double sum_tri = accumulate(tri.begin(), tri.end(), 0.0);
        int max_deg = 0;
        long long edge_twice = 0;
        for (int d : deg) {
            max_deg = max(max_deg, d);
            edge_twice += d;
        }
        double avg_deg = par.n ? static_cast<double>(edge_twice) / par.n : 0.0;
        cout << fixed << setprecision(6);
        cout << "#Node:" << par.n
             << "\tEdges:" << edge_twice / 2.0
             << "\t#Triangles:" << sum_tri / 3.0
             << "\tMax d:" << max_deg
             << "\tAvg. d:" << avg_deg << endl;
    }

    void run() {
        auto start = chrono::steady_clock::now();
        initMaliciousUsers();

        if (par.scheme == "CaliToUpper") caliToUpper();
        else if (par.scheme == "CaliToLS") caliToLS();
        else if (par.scheme == "CaliToTrunc") caliToTrunc();
        else if (par.scheme == "DDP") DDP();
        else {
            cerr << "+ Undefined perturbation scheme: " << par.scheme << endl;
            exit(1);
        }

        auto end = chrono::steady_clock::now();
        double sec = chrono::duration<double>(end - start).count();
        cout << "+ counting finished.\n  counting time:" << sec / 60.0 << " minutes." << endl;
    }

private:
    Params par;
    mt19937_64 rng;
    vector<vector<int>> adj;
    vector<int> deg;
    vector<char> malicious;
    int malicious_count = 0;

    bool tri_ready = false;
    bool sen_ready = false;
    vector<double> tri_cache;
    vector<double> sen_cache;

    double uniform01() {
        uniform_real_distribution<double> dist(0.0, 1.0);
        return dist(rng);
    }

    bool reportAttackEnabled() const {
        return !(par.report_attack == "clean" || par.report_attack == "none" ||
                 par.malicious_ratio <= 0.0 || par.attack_lambda == 0.0);
    }

    void initMaliciousUsers() {
        malicious.assign(par.n, 0);
        malicious_count = 0;

        if (!reportAttackEnabled()) {
            cout << "+ post-Laplace report attack: clean" << endl;
            return;
        }

        if (!(par.report_attack == "fixed" || par.report_attack == "scale" || par.report_attack == "count")) {
            cerr << "Unknown report_attack: " << par.report_attack
                 << ". Supported: clean, fixed, scale, count." << endl;
            exit(1);
        }

        int m = static_cast<int>(floor(par.malicious_ratio * par.n));
        if (m < 1) {
            cout << "+ post-Laplace report attack skipped: malicious users fewer than 1." << endl;
            return;
        }
        if (m > par.n) m = par.n;
        malicious_count = m;

        vector<int> nodes(par.n);
        iota(nodes.begin(), nodes.end(), 0);
        uint64_t seed_for_mal = (par.malicious_seed == 0)
            ? (par.seed ^ 0x9e3779b97f4a7c15ULL)
            : par.malicious_seed;
        mt19937_64 mal_rng(seed_for_mal);
        shuffle(nodes.begin(), nodes.end(), mal_rng);

        for (int i = 0; i < m; ++i) malicious[nodes[i]] = 1;

        cout << "+ post-Laplace report attack enabled"
             << "\n  report_attack=" << par.report_attack
             << "\n  malicious_ratio=" << par.malicious_ratio
             << "\n  malicious_num=" << malicious_count
             << "\n  attack_lambda=" << par.attack_lambda
             << "\n  attack_direction=" << (par.attack_direction >= 0 ? "increase" : "decrease")
             << "\n  malicious_seed=" << seed_for_mal << endl;
    }

    double attackBias(double local_count, double laplace_scale) const {
        if (par.report_attack == "fixed") {
            return par.attack_lambda;
        }
        if (par.report_attack == "scale") {
            return par.attack_lambda * laplace_scale;
        }
        if (par.report_attack == "count") {
            return par.attack_lambda * max(0.0, local_count);
        }
        return 0.0;
    }

    double privatizedReport(int user_id, double local_count, double laplace_scale, bool allow_attack = true) {
        // The attack is intentionally placed after normal Laplace perturbation:
        // y_i = local_count + Lap(scale), then malicious users add a directional bias.
        double report = local_count + laplace(laplace_scale);
        if (allow_attack && reportAttackEnabled() && user_id >= 0 && user_id < par.n && malicious[user_id]) {
            double direction = (par.attack_direction >= 0) ? 1.0 : -1.0;
            report += direction * attackBias(local_count, laplace_scale);
        }
        return report;
    }

    double laplace(double scale) {
        if (scale <= 0.0 || !isfinite(scale)) return 0.0;
        uniform_real_distribution<double> dist(-0.5, 0.5);
        double u = dist(rng);
        double sign = (u < 0.0) ? -1.0 : 1.0;
        return -scale * sign * log(1.0 - 2.0 * fabs(u));
    }

    int binomialSample(int trials, double prob) {
        if (trials <= 0 || prob <= 0.0) return 0;
        if (prob >= 1.0) return trials;
        binomial_distribution<int> bd(trials, prob);
        return bd(rng);
    }

    unordered_map<int, int> twoHopCounts(int i) const {
        unordered_map<int, int> cnt;
        // Reserve a rough size to reduce rehash overhead.
        size_t approx = 0;
        for (int u : adj[i]) approx += adj[u].size();
        cnt.reserve(min<size_t>(approx, static_cast<size_t>(par.n)));

        for (int u : adj[i]) {
            for (int v : adj[u]) {
                if (v == i) continue;
                ++cnt[v];
            }
        }
        return cnt;
    }

    const vector<double>& triCnt() {
        if (tri_ready) return tri_cache;
        cout << "+ computing local triangle counts..." << endl;
        tri_cache.assign(par.n, 0.0);

        for (int i = 0; i < par.n; ++i) {
            unordered_map<int, int> cnt = twoHopCounts(i);
            long long sum_common_on_edges = 0;
            for (int v : adj[i]) {
                auto it = cnt.find(v);
                if (it != cnt.end()) sum_common_on_edges += it->second;
            }
            tri_cache[i] = static_cast<double>(sum_common_on_edges) / 2.0;

            if (i % 10000 == 0) cout << "  process:" << i << endl;
        }

        double total = accumulate(tri_cache.begin(), tri_cache.end(), 0.0);
        cout << "+ raw global triangle count:" << total / 3.0 << endl;
        tri_ready = true;
        return tri_cache;
    }

    const vector<double>& triSen() {
        if (sen_ready) return sen_cache;
        cout << "+ computing local sensitivities..." << endl;
        sen_cache.assign(par.n, 1.0);

        for (int i = 0; i < par.n; ++i) {
            unordered_map<int, int> cnt = twoHopCounts(i);
            int mx = 0;
            for (auto& kv : cnt) {
                if (kv.first == i) continue;
                mx = max(mx, kv.second);
            }
            sen_cache[i] = static_cast<double>(max(mx, 1));
            if (i % 10000 == 0) cout << "  process:" << i << endl;
        }

        sen_ready = true;
        return sen_cache;
    }

    vector<double> nodDeg() const {
        vector<double> d(par.n);
        for (int i = 0; i < par.n; ++i) d[i] = static_cast<double>(deg[i]);
        return d;
    }

    double lapUpperBound(double x, double lapScale, double delta) const {
        if (lapScale <= 0.0) return x;
        return x + lapScale * log(1.0 / (2.0 * delta));
    }

    double correlationEstimation(double eps, double delta) {
        const vector<double>& senCnt = triSen();
        vector<double> nodeDeg = nodDeg();

        vector<double> deg_prime(par.n), deg_upper(par.n);
        double scale_deg = 2.0 / (eps * par.alpha);
        double delta_each = delta / (par.h_prime + 1.0);

        for (int i = 0; i < par.n; ++i) {
            deg_prime[i] = nodeDeg[i] + laplace(scale_deg);
            deg_upper[i] = lapUpperBound(deg_prime[i], scale_deg, delta_each);
        }

        vector<int> order(par.n);
        iota(order.begin(), order.end(), 0);
        sort(order.begin(), order.end(), [&](int a, int b) {
            return deg_upper[a] > deg_upper[b];
        });

        int index = 0;
        int h = min(par.h_prime, max(0, par.n - 3));
        for (int i = 0; i < h; ++i) {
            int j = i + 1;
            int pos = j + 2;
            if (pos >= par.n) break;
            double lhs = (static_cast<double>(j) / (par.alpha * eps)) *
                         log((par.h_prime + 1.0) / delta);
            if (lhs >= deg_upper[order[pos]]) {
                index = static_cast<int>(floor(j / 2.0));
                break;
            }
        }

        vector<double> sen_prime(par.n), sen_upper(par.n);
        double scale_sen_noise = static_cast<double>(index);  // Mirrors Python code.
        double scale_sen_upper = (index <= 0) ? 0.0 :
            static_cast<double>(index) / ((1.0 - par.alpha) * eps);

        for (int i = 0; i < par.n; ++i) {
            sen_prime[i] = senCnt[i] + laplace(scale_sen_noise);
            sen_upper[i] = lapUpperBound(sen_prime[i], scale_sen_upper, delta_each);
        }

        double maxSen = 0.0;
        for (int j = 0; j <= index && j < par.n; ++j) {
            int idx = order[j];
            double val = floor(min(deg_upper[idx], sen_upper[idx])); // Python int array effect.
            if (val > maxSen) maxSen = val;
        }

        cout << " ++ correlationEstimation: index=" << index
             << " maxSen=" << maxSen << endl;
        return maxSen;
    }

    double privacyAllocation(double eps, double k, double p) {
        double eps_low = 0.0;
        double eps_high = 200.0;
        double eps_middle = 100.0;

        auto epsTemp = [&](double x) -> double {
            double e = exp(x);
            double a = log(1.0 + p * (e - 1.0));
            double kk = max(0.0, k - 2.0);
            double term2 = a * sqrt(max(0.0, 2.0 * kk * log(1.0 / par.delta)));
            double term3_den = p * (e + 1.0) + 2.0;
            double term3 = (term3_den == 0.0) ? 0.0 :
                kk * a * p * (e - 1.0) / term3_den;
            return 2.0 * x + term2 + term3;
        };

        double tmp = epsTemp(eps_middle);
        int guard = 0;
        while (fabs(tmp - eps) >= 1e-5 && guard++ < 10000) {
            if (tmp > eps) eps_high = eps_middle;
            else eps_low = eps_middle;
            eps_middle = (eps_low + eps_high) / 2.0;
            tmp = epsTemp(eps_middle);
        }
        return eps_middle;
    }

    SampledData sampleData(bool need_loc_sen) {
        cout << "+ start subsampling; p=" << par.p << endl;
        SampledData sd;
        sd.tri_per_neighbor.resize(par.n);
        sd.tri_sum.assign(par.n, 0.0);
        sd.loc_sen_max.assign(par.n, 1.0);

        double q = par.p / 2.0; // Mirrors Python PRIEVET smpTriCnt/smpLocSen.

        for (int i = 0; i < par.n; ++i) {
            unordered_map<int, int> cnt = twoHopCounts(i);

            sd.tri_per_neighbor[i].resize(adj[i].size(), 0);
            double row_sum = 0.0;

            for (size_t t = 0; t < adj[i].size(); ++t) {
                int v = adj[i][t];
                int c = 0;
                auto it = cnt.find(v);
                if (it != cnt.end()) c = it->second;
                int s = binomialSample(c, q);
                sd.tri_per_neighbor[i][t] = s;
                row_sum += s;
            }
            sd.tri_sum[i] = row_sum;
            sd.total_tri_sum += row_sum;

            if (need_loc_sen) {
                int mx = 0;
                for (auto& kv : cnt) {
                    int sampled = binomialSample(kv.second, q);
                    if (sampled > mx) mx = sampled;
                }
                sd.loc_sen_max[i] = static_cast<double>(max(mx, 1));
            }

            if (i % 10000 == 0) cout << "  process:" << i << endl;
        }
        cout << "+ finish subsampling. sampled local sum=" << sd.total_tri_sum << endl;
        return sd;
    }

    double sumVec(const vector<double>& x) const {
        return accumulate(x.begin(), x.end(), 0.0);
    }

    string inferredDatasetName() const {
        if (!par.dataset_name.empty()) return par.dataset_name;
        string b = baseName(par.edge_file);
        // If file is edges.csv, use parent directory name when possible.
        if (b == "edges") {
            size_t slash = par.edge_file.find_last_of("/\\");
            if (slash != string::npos) {
                string parent = par.edge_file.substr(0, slash);
                size_t slash2 = parent.find_last_of("/\\");
                if (slash2 != string::npos) return parent.substr(slash2 + 1);
                return parent;
            }
        }
        return b;
    }

    void DDP() {
        cout << "+ executing DDP..." << endl;
        const vector<double>& tri = triCnt();
        double sumTri = sumVec(tri);

        double k = correlationEstimation(par.beta * par.epsilon, par.delta);
        double Delta_f = 3.0 * k;
        double eps2 = (1.0 - par.beta) * par.epsilon;
        double scale = (eps2 <= 0.0) ? 0.0 : Delta_f / eps2;

        cout << " ++ global data correlation (k):" << k
             << "\ttotal privacy budget epsilon:" << par.epsilon
             << "\tfailure rate delta:" << par.delta
             << "\teps_2_prime:" << eps2 << endl;

        double MRE = 0.0;
        double var = 0.0;

        for (int t = 0; t < par.trial_num; ++t) {
            double noisySum = 0.0;
            for (int i = 0; i < par.n; ++i) noisySum += privatizedReport(i, tri[i], scale);

            MRE += fabs(noisySum - sumTri) / max(sumTri, 1e-30);
            double diff = noisySum / 3.0 - sumTri / 3.0;
            var += diff * diff;
        }

        MRE /= par.trial_num;
        var /= par.trial_num;

        cout << " ++ variance for DDP:" << var << endl;
        cout << " ++ MRE for DDP:" << MRE << endl;
    }

    void caliToUpper() {
        cout << "+ executing CaliToUpper..." << endl;
        double eps1 = par.beta * par.epsilon;
        double eps2 = (1.0 - par.beta) * par.epsilon;

        double k0 = correlationEstimation(eps1, par.delta) + 2.0;
        double k = ceil(k0 * par.p + par.r * sqrt(max(0.0, k0 * par.p * (1.0 - par.p))));
        double eps_prime = privacyAllocation(eps2, k, par.p);

        cout << " ++ global data correlation (k):" << k
             << "\ttotal privacy budget epsilon:" << par.epsilon
             << "\tfailure rate delta:" << par.delta
             << "\teps_2_prime:" << eps_prime << endl;

        const vector<double>& tri = triCnt();
        double sumTri = sumVec(tri);

        vector<double> deg_d = nodDeg();
        vector<double> deg_prime(par.n), deg_upper(par.n);
        double scale_deg = 2.0 / (par.alpha * eps1);
        double delta_each = par.delta / (par.h_prime + 1.0);

        for (int i = 0; i < par.n; ++i) {
            deg_prime[i] = deg_d[i] + laplace(scale_deg);
            deg_upper[i] = lapUpperBound(deg_prime[i], scale_deg, delta_each);
        }

        vector<double> smp_loc_sen_upper(par.n);
        double add = par.r * sqrt(max(0.0, k * par.p * (1.0 - par.p)));
        for (int i = 0; i < par.n; ++i) {
            smp_loc_sen_upper[i] = deg_upper[i] * par.p + add;
            if (smp_loc_sen_upper[i] < 0.0) smp_loc_sen_upper[i] = 0.0;
        }

        double avg = sumVec(smp_loc_sen_upper) / max(1, par.n);
        cout << " ++ average local sensitivity after subsampling and perturbation: "
             << avg << endl;

        SampledData sd = sampleData(false);
        double sample_error = fabs(sumTri - sd.total_tri_sum / par.p) / max(sumTri, 1e-30);
        cout << " ++ subsample error:" << sample_error << endl;

        double MRE = 0.0;
        double var = 0.0;

        for (int t = 0; t < par.trial_num; ++t) {
            double noisySum = 0.0;
            for (int i = 0; i < par.n; ++i) {
                double scale = (eps_prime <= 0.0) ? 0.0 : smp_loc_sen_upper[i] / eps_prime;
                noisySum += privatizedReport(i, sd.tri_sum[i], scale);
            }
            MRE += fabs(noisySum / par.p - sumTri) / max(sumTri, 1e-30);

            // Mirrors Python implementation's CaliToUpper variance line.
            double diff = noisySum / par.p / 3.0 - sumTri / 6.0;
            var += diff * diff;
        }

        MRE /= par.trial_num;
        var /= par.trial_num;

        cout << " ++ variance for CaliToUpper:" << var << endl;
        cout << " ++ MRE for CaliToUpper:" << MRE << endl;
    }

    void caliToLS() {
        cout << "+ executing CaliToLS..." << endl;
        double eps1 = par.beta * par.epsilon;
        double eps2 = (1.0 - par.beta) * par.epsilon;

        double k0 = correlationEstimation(eps1, par.delta) + 2.0;
        cout << "test k:" << k0 << endl;
        double k = ceil(k0 * par.p + par.r * sqrt(max(0.0, k0 * par.p * (1.0 - par.p))));

        double eps_prime = privacyAllocation(eps2, k - 2.0, par.p);
        if (eps_prime > log(2.0)) eps_prime -= log(2.0);
        else eps_prime = 0.0;

        cout << " ++ global data correlation (k):" << k
             << "\ttotal privacy budget epsilon:" << par.epsilon
             << "\tfailure rate delta:" << par.delta
             << "\teps_2_prime:" << eps_prime << endl;

        const vector<double>& tri = triCnt();
        double sumTri = sumVec(tri);

        SampledData sd = sampleData(true);
        double sample_error = fabs(sd.total_tri_sum / par.p - sumTri) / max(sumTri, 1e-30);
        cout << " ++ subsample error:" << sample_error << endl;

        double max_sen = *max_element(sd.loc_sen_max.begin(), sd.loc_sen_max.end());
        double min_sen = *min_element(sd.loc_sen_max.begin(), sd.loc_sen_max.end());
        vector<double> tmp = sd.loc_sen_max;
        nth_element(tmp.begin(), tmp.begin() + tmp.size() / 2, tmp.end());
        double median_sen = tmp[tmp.size() / 2];
        double avg_sen = sumVec(sd.loc_sen_max) / max(1, par.n);

        cout << " ++ maximum local sensitivity after subsampling: " << max_sen << endl;
        cout << " ++ minimum local sensitivity after subsampling: " << min_sen << endl;
        cout << " ++ median local sensitivity after subsampling: " << median_sen << endl;
        cout << " ++ average local sensitivity after subsampling: " << avg_sen << endl;

        double MRE = 0.0;
        double var = 0.0;

        if (eps_prime > 0.0) {
            for (int t = 0; t < par.trial_num; ++t) {
                double noisySum = 0.0;
                for (int i = 0; i < par.n; ++i) {
                    double scale = sd.loc_sen_max[i] / eps_prime;
                    noisySum += privatizedReport(i, sd.tri_sum[i], scale);
                }
                MRE += fabs(noisySum / par.p - sumTri) / max(sumTri, 1e-30);
                double diff = noisySum / par.p / 3.0 - sumTri / 3.0;
                var += diff * diff;
            }
            MRE /= par.trial_num;
            var /= par.trial_num;
        }

        cout << " ++ variance for CaliToLS:" << var << endl;
        cout << " ++ MRE for CaliToLS:" << MRE << endl;
    }

    void caliToTrunc() {
        cout << "+ executing CaliToTrunc..." << endl;
        double delta_for_corr = par.delta * 5.0;
        double eps1 = par.beta * par.epsilon;
        double eps2 = (1.0 - par.beta) * par.epsilon;

        double k0 = correlationEstimation(eps1, delta_for_corr) + 2.0;
        double k = ceil(k0 * par.p + par.r * sqrt(max(0.0, k0 * par.p * (1.0 - par.p))));
        cout << k << endl;
        double eps_prime = privacyAllocation(eps2, k, par.p);

        cout << " ++ global data correlation (k):" << k
             << "\ttotal privacy budget epsilon:" << par.epsilon
             << "\tfailure rate delta:" << par.delta
             << "\teps_2_prime:" << eps_prime << endl;

        vector<double> deg_d = nodDeg();
        vector<double> deg_prime(par.n);
        double scale_deg = 2.0 / (eps1 * par.alpha);
        for (int i = 0; i < par.n; ++i) deg_prime[i] = deg_d[i] + laplace(scale_deg);

        const vector<double>& tri = triCnt();
        double sumTri = sumVec(tri);

        SampledData sd = sampleData(false);
        double sample_error = fabs(sd.total_tri_sum / par.p - sumTri) / max(sumTri, 1e-30);
        cout << " ++ subsample error:" << sample_error << endl;

        string dname = inferredDatasetName();
        double divisor = (dname == "facebook" || dname == "IMDB") ? 0.75 : 2.0;

        vector<double> T(par.n, 1.0);
        double positive_const = 2.0 / (eps1 * par.alpha) * log(1.0 / (2.0 * par.delta));
        for (int i = 0; i < par.n; ++i) {
            double val = floor((deg_prime[i] + positive_const) * par.p / divisor);
            if (val < 1.0) val = 1.0;
            T[i] = val;
        }

        double avgT = sumVec(T) / max(1, par.n);
        cout << " ++ the average threshold:" << avgT << endl;

        vector<double> truncated_cnt(par.n, 0.0), thrown_away_cnt(par.n, 0.0);
        for (int i = 0; i < par.n; ++i) {
            double ti = T[i];
            for (int x : sd.tri_per_neighbor[i]) {
                truncated_cnt[i] += min<double>(x, ti);
                thrown_away_cnt[i] += min<double>(max<double>(x - ti, 0.0), ti);
            }
        }

        double truncDetSum = sumVec(truncated_cnt);
        double thrownDetSum = sumVec(thrown_away_cnt);

        eps_prime /= 2.0;

        double MRE = 0.0;
        double var = 0.0;
        double MRE_without_cali = 0.0;
        double truncation_numbers = 0.0;
        double truncation_bias = 0.0;

        for (int t = 0; t < par.trial_num; ++t) {
            if (t % 50 == 0) cout << " +++ at round:" << t << endl;

            double truncated_prime_sum = 0.0;
            double thrown_prime_sum = 0.0;

            for (int i = 0; i < par.n; ++i) {
                double scale = (eps_prime <= 0.0) ? 0.0 : T[i] / eps_prime;
                // CaliToTrunc: only attack the local-count report; do not attack the bias report.
                truncated_prime_sum += privatizedReport(i, truncated_cnt[i], scale, true);
                thrown_prime_sum += thrown_away_cnt[i] + laplace(scale);
            }

            truncation_bias += fabs(truncDetSum / par.p - sumTri) / max(sumTri, 1e-30);
            truncation_numbers += thrownDetSum / par.p / 3.0;
            MRE_without_cali += fabs(truncated_prime_sum / par.p - sumTri) / max(sumTri, 1e-30);

            double total_prime = truncated_prime_sum + thrown_prime_sum;
            MRE += fabs(total_prime / par.p - sumTri) / max(sumTri, 1e-30);
            double diff = total_prime / par.p / 3.0 - sumTri / 3.0;
            var += diff * diff;
        }

        truncation_bias /= par.trial_num;
        MRE_without_cali /= par.trial_num;
        MRE /= par.trial_num;
        var /= par.trial_num;
        truncation_numbers /= par.trial_num;

        cout << " ++ thrown-away triangles for CaliToTrunc:" << truncation_numbers << endl;
        cout << " ++ truncation bias for CaliToTrunc:" << truncation_bias << endl;
        cout << " ++ variance for CaliToTrunc:" << var << endl;
        cout << " ++ MRE without calibration for CaliToTrunc:" << MRE_without_cali << endl;
        cout << " ++ MRE with calibration for CaliToTrunc:" << MRE << endl;
        cout << "row count:" << sumTri / 3.0 << endl;
    }
};

static void usage() {
    cerr << "Usage:\n"
         << "  ./PRIVET_laplace_attack <edge_file> <node_num> <epsilon> <scheme>\n"
         << "           [delta=5e-6] [beta=0.2] [alpha=0.5] [h_prime=100]\n"
         << "           [r=5] [p=0.01] [trial_num=300] [seed=1776] [dataset_name=auto]\n"
         << "           [report_attack=clean] [malicious_ratio=0] [attack_lambda=0]\n"
         << "           [attack_direction=1] [malicious_seed=0]\n\n"
         << "Schemes: CaliToUpper, CaliToLS, CaliToTrunc, DDP\n"
         << "Report attacks: clean, fixed, scale, count\n"
         << "attack_direction: 1 for increase, -1 for decrease\n";
}

int main(int argc, char** argv) {
    if (argc < 5) {
        usage();
        return 1;
    }

    Params par;
    par.edge_file = argv[1];
    par.n = atoi(argv[2]);
    par.epsilon = atof(argv[3]);
    par.scheme = argv[4];

    if (argc > 5) par.delta = atof(argv[5]);
    if (argc > 6) par.beta = atof(argv[6]);
    if (argc > 7) par.alpha = atof(argv[7]);
    if (argc > 8) par.h_prime = atoi(argv[8]);
    if (argc > 9) par.r = atoi(argv[9]);
    if (argc > 10) par.p = atof(argv[10]);
    if (argc > 11) par.trial_num = atoi(argv[11]);
    if (argc > 12) par.seed = static_cast<uint64_t>(strtoull(argv[12], nullptr, 10));
    if (argc > 13) par.dataset_name = argv[13];
    if (argc > 14) par.report_attack = argv[14];
    if (argc > 15) par.malicious_ratio = atof(argv[15]);
    if (argc > 16) par.attack_lambda = atof(argv[16]);
    if (argc > 17) par.attack_direction = atoi(argv[17]);
    if (argc > 18) par.malicious_seed = static_cast<uint64_t>(strtoull(argv[18], nullptr, 10));

    if (par.n <= 0 || par.epsilon <= 0.0) {
        cerr << "Invalid node_num or epsilon." << endl;
        return 1;
    }
    if (par.p <= 0.0 || par.p > 1.0) {
        cerr << "Invalid sampling probability p." << endl;
        return 1;
    }
    if (par.malicious_ratio < 0.0 || par.malicious_ratio > 1.0) {
        cerr << "Invalid malicious_ratio; it should be in [0, 1]." << endl;
        return 1;
    }

    cout << fixed << setprecision(10);
    cout << "+ PRIEVET C++ adaptor\n"
         << "  edge_file=" << par.edge_file
         << "\n  node_num=" << par.n
         << "\n  epsilon=" << par.epsilon
         << "\n  scheme=" << par.scheme
         << "\n  delta=" << par.delta
         << "\n  beta=" << par.beta
         << "\n  alpha=" << par.alpha
         << "\n  h_prime=" << par.h_prime
         << "\n  r=" << par.r
         << "\n  p=" << par.p
         << "\n  trial_num=" << par.trial_num
         << "\n  seed=" << par.seed
         << "\n  dataset_name=" << (par.dataset_name.empty() ? "auto" : par.dataset_name)
         << "\n  report_attack=" << par.report_attack
         << "\n  malicious_ratio=" << par.malicious_ratio
         << "\n  attack_lambda=" << par.attack_lambda
         << "\n  attack_direction=" << par.attack_direction
         << "\n  malicious_seed=" << par.malicious_seed
         << endl;

    PRIEVET app(par);
    app.loadGraph();
    app.showInfo();
    app.run();
    return 0;
}
