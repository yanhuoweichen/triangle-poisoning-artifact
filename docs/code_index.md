# Code Index
This file groups the C++ source files by experiment family. File names are kept close to the original names so that the original shell scripts remain recognizable.

## DDP / central or distributed DP robustness
- `src/cpp/DDP_AnomalyDefense.cpp`
- `src/cpp/DDP_Phase2_Robust.cpp`

## EdgeOrient / LEDP attacks
- `src/cpp/EdgeOrientDelta_OriginalDecreaseAttack.cpp`
- `src/cpp/EdgeOrientDelta_OriginalIncreaseAttack.cpp`
- `src/cpp/EdgeOrientDelta_TriangleLDP_LaplaceAttack.cpp`
- `src/cpp/EdgeOrientDelta_TriangleLDP_RRAttack_strict.cpp`
- `src/cpp/EdgeOrientDelta_TriangleLDP_RR_DecreaseAttack.cpp`
- `src/cpp/EdgeOrientDelta_TriangleLDP_RR_IncreaseAttack.cpp`
- `src/cpp/EdgeOrientDelta_TriangleLDP_corrected.cpp`
- `src/cpp/EdgeOrient_AnomalyDefense.cpp`

## LDP triangle-counting attacks
- `src/cpp/LDP2022_ARROneNS_AnomalyDefense.cpp`
- `src/cpp/TriangleCounting.cpp`
- `src/cpp/TriangleCounting_OrigIncreaseAttack.cpp`
- `src/cpp/TriangleCounting_OrigIncrease_ARROneNS.cpp`

## PRIVET / RLDP Laplace-type attacks
- `src/cpp/PRIVET_AnomalyDefense.cpp`
- `src/cpp/PRIVET_laplace_attack.cpp`
- `src/cpp/PRIVET_with_attack.cpp`

## Shuffle DP and GenShuffleDP attacks
- `src/cpp/CCS25ShuffleTriangle.cpp`
- `src/cpp/CCS25ShuffleTriangle_fixed_malpairRR.cpp`
- `src/cpp/GenShuffleDP_AnomalyDefense.cpp`
- `src/cpp/SubgraphShuffle.cpp`
- `src/cpp/SubgraphShuffle_OriginalDataAttack_strict.cpp`
- `src/cpp/SubgraphShuffle_RRAttack_strict.cpp`
- `src/cpp/SubgraphShuffle_ShuffleAttack_strict.cpp`

## TDP-VC / 2025 robust protocol
- `src/cpp/TDPVC_AnomalyDefense.cpp`
- `src/cpp/TDP_VC_Attack.cpp`
