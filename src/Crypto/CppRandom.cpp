#include "CppRandom.hpp"

namespace Dissent {
namespace Crypto {
  CppRandom::CppRandom(const QByteArray &seed, uint index)
  {
    if(seed.isEmpty()) {
      try {
        _rng.reset(new CryptoPP::AutoSeededX917RNG<CryptoPP::AES>());
      } catch (CryptoPP::OS_RNG_Err &ex) {
        qFatal("Ran out of file descriptors, when creating a CppRandom.");
      }
      return;
    }

    QByteArray seed_tmp(seed);
    seed_tmp.resize(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::BlockTransformation *bt = new CryptoPP::AES::Encryption(
        reinterpret_cast<byte *>(seed_tmp.data()), seed_tmp.size());

    QByteArray zero(CryptoPP::AES::DEFAULT_KEYLENGTH, 0);
    const byte *zerob = reinterpret_cast<const byte *>(zero.data());
    _rng.reset(new CryptoPP::X917RNG(bt, zerob, zerob));

    ResetByteCount();

    if(index) {
      MoveRngPosition(index);
    }
  }

  int CppRandom::GetInt(int min, int max)
  {
    if(min == max) {
      return min;
    }
    IncrementByteCount(4);
    return _rng->GenerateWord32(min, max - 1);
  }

  void CppRandom::GenerateBlock(QByteArray &data)
  {
    _rng->GenerateBlock(reinterpret_cast<byte *>(data.data()), data.size());
    IncrementByteCount(data.size());
  }
}
}
