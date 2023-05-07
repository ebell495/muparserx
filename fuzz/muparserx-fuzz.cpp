#define _USE_MATH_DEFINES
#include <string>
#include <vector>
#include "../parser/mpParser.h"
#include "../parser/mpDefines.h"
#include "../parser/mpError.h"
#include "fuzzer/FuzzedDataProvider.h"

mup::Value vals[8196];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);
    size_t valIdx = 0;
    try
    {   
        mup::ParserX parser(mup::pckALL_COMPLEX);
        parser.EnableAutoCreateVar(true);
        std::string res = fdp.ConsumeRandomLengthString(50);

        std::string varName;
        float floatVal;
        int intVal;
        std::string stringVal;
        std::complex<double> complexVal;

        while (fdp.remaining_bytes() > 0 && valIdx < 8196) {
            uint8_t opt = fdp.ConsumeIntegralInRange<uint8_t>(0, 3);
            switch (opt) {
                case 0:
                    floatVal = fdp.ConsumeFloatingPoint<float>();
                    varName = fdp.ConsumeRandomLengthString(5);
                    vals[valIdx] = mup::Value((mup::float_type)floatVal);
                    parser.DefineVar(varName, mup::Variable(&vals[valIdx]));
                    valIdx++;
                    break;
                case 1:
                    intVal = fdp.ConsumeIntegral<int>();
                    varName = fdp.ConsumeRandomLengthString(5);
                    vals[valIdx] = mup::Value((mup::int_type)intVal);
                    parser.DefineVar(varName, mup::Variable(&vals[valIdx]));
                    valIdx++;
                    break;
                case 2:
                    stringVal = fdp.ConsumeRandomLengthString(10);
                    varName = fdp.ConsumeRandomLengthString(5);
                    vals[valIdx] = mup::Value((mup::string_type)stringVal);
                    parser.DefineVar(varName, mup::Variable(&vals[valIdx]));
                    valIdx++;
                    break;
                case 3:
                    complexVal = std::complex<double>(fdp.ConsumeFloatingPoint<double>(), fdp.ConsumeFloatingPoint<double>());
                    varName = fdp.ConsumeRandomLengthString(5);
                    vals[valIdx] = mup::Value((mup::cmplx_type)complexVal);
                    parser.DefineVar(varName, mup::Variable(&vals[valIdx]));
                    valIdx++;
                    break;
            }
        }
        parser.SetExpr(res);
        parser.Eval();
    }
    catch (mup::ParserError &e)
    {
    }

    return 0;
}