/** @file
 *****************************************************************************
 Unit tests for gadgetlib2 - tests for specific gadgets
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <iostream>
#include <sstream>
#include <vector>
#include <string.h>

#include <gtest/gtest.h>
#include <libsnark/gadgetlib2/gadget.hpp>
#include <libsnark/gadgetlib2/pp.hpp>
#include <libsnark/gadgetlib2/protoboard.hpp>
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib2/integration.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include "libff/algebra/fields/field_utils.hpp"
#include <libff/common/profiling.hpp>

#include "gadget2.hpp"
#include "goLayer.h"
extern char PKEY_VALUE[];
extern char VKEY_VALUE[];
extern bool GenGadget(std::vector<std::string> &vectInput);

using ::std::cerr;
using ::std::cout;
using ::std::endl;
using ::std::stringstream;
using namespace gadgetlib2;
using namespace libsnark;
using namespace std;

typedef libff::Fr<libff::default_ec_pp> FieldT;

using ::std::cerr;
using ::std::cout;
using ::std::endl;
using ::std::stringstream;
using namespace gadgetlib2;
using namespace libsnark;
using namespace std;

typedef libff::Fr<libff::default_ec_pp> FieldT;
extern int64_t g_RetIndex;

/// deserialization pkey
	void Deserial_pkey(r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> &pk, const std::string &pkey) {
		std::istringstream istr(pkey); 
		istr >> pk;
	}

/// deserialization vkey
	void Deserial_vkey(r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> &vk, const std::string &vkey) {
		std::istringstream istr(vkey); 
		istr >> vk;
	}

/// deserialization proof
	void Deserial_proof(r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> &r1cs_proof, const std::string &proof) {
		std::istringstream istr(proof); 
		istr >> r1cs_proof;
	}


int main() {
    std::vector<std::string> vectInput;
    vectInput.push_back("240");

    // 1) init gadget env
    gadget_initEnv();

    // 2) create gadgets
    GenGadget(vectInput);

    // 3) gen witness
    gadget_generateWitness();

    // 4) gen proof and result
    string strPKey = PKEY_VALUE;
    string strVKey = VKEY_VALUE;
    #define PROOR_BUF_SIZE 0x400
    #define RES_BUF_SIZE 0x100
    char Proof[PROOR_BUF_SIZE + 1] = {0};
    char Result[RES_BUF_SIZE + 1] = {0};
    unsigned char Success = true;
    Success &= GenerateProof(strPKey.c_str(), Proof, PROOR_BUF_SIZE);
    Success &= GenerateResult(g_RetIndex, Result, RES_BUF_SIZE);

    if (!Success)
      cout << ("Gen proof & result fail...\n");
    else
      cout << ("Gen proof & result success...\n");
    cout << "Result is " << Result << "\n";

    string inputs;
    for(unsigned i = 0; i < vectInput.size(); i++)
      inputs = inputs + vectInput[i] + '$';
    inputs.pop_back();


    Success &= Verify(strVKey.c_str(), Proof, inputs.c_str(), Result);
    if (!Success) {
      cout << "verify fail.\n";
    } else {
      cout << "verify pass.\n";
    }

    return 0;
}
