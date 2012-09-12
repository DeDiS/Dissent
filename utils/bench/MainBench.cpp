#include "Benchmark.hpp"

GTEST_API_ int main(int argc, char **argv)
{
  QCoreApplication qca(argc, argv);
  Logging::UseFile("bench.log");
  qDebug() << "Beginning benchmarking";
  testing::InitGoogleTest(&argc, argv);
  int res = RUN_ALL_TESTS();
  return res;
}

