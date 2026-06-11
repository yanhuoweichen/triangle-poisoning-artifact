#!/bin/bash
set -euo pipefail

# Run all strict shuffle-DP attack experiments for Gplus and IMDB.
# Put this file under Triangle4CycleShuffle/cpp/ together with:
#   SubgraphShuffle_RRAttack_strict.cpp
#   SubgraphShuffle_ShuffleAttack_strict.cpp
#   run_shuffle_attacks_Gplus_strict_cpp.sh
#   run_shuffle_attacks_IMDB_strict_cpp.sh

chmod +x run_shuffle_attacks_Gplus_strict_cpp.sh run_shuffle_attacks_IMDB_strict_cpp.sh
./run_shuffle_attacks_Gplus_strict_cpp.sh
./run_shuffle_attacks_IMDB_strict_cpp.sh

echo "All strict shuffle-DP attack experiments for Gplus and IMDB finished."
