#include <cassert>
#include <cstdio>
#include <string>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <fstream>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/fields/field_utils.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib2/gadget.hpp>
#include <libsnark/gadgetlib2/protoboard.hpp>
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include "../goLayer.h"

using namespace libsnark;
using namespace gadgetlib2;
using namespace std;
typedef libff::Fr<libff::default_ec_pp> FieldT;


/// libcsnark function decl
extern "C" ProtoboardPtr g_pbp;
extern "C" void Serial_pkey(const r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> &pk, std::string &pkey);
extern "C" void Serial_vkey(const r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> &vk, std::string &vkey);


/// VKEY & PKEY generator
bool GenerateKeypair() {
    // gadget init
    gadget_initEnv();

    // create gadgets. 
    // the follow code must be auto generate by vc compiler
    // $create_gadgets$
    // create pb variables
    gadget_createPBVar(1);
//    gadget_createPBVar(2);
    gadget_createPBVar(3);

    // create gadget
    if (!gadget_createGadget(1, 0, 0, 3, E_GType::G_NOT)) {
        cout << "create or gadget fail." << endl;
        return false;
    }
    
    // generate constraints.
    gadget_generateConstraints();

    // translate constraint system to libsnark format.
    r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*g_pbp);
    cs.primary_input_size = 2;  //num:2 must be replace $input_output count$
    cs.auxiliary_input_size -= cs.primary_input_size;

    // translate full variable assignment to libsnark format
    const r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*g_pbp);

    // extract primary and auxiliary input
    const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(), full_assignment.begin() + cs.num_inputs());

    // generate key pair
    r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keyPair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(cs);

    // serial key pair
    string pkey, vkey;
    Serial_pkey(keyPair.pk, pkey);
    Serial_vkey(keyPair.vk, vkey);

    // write pkey & vkey data to file
    std::fstream fpk, fvk;
    fpk.open("./pk.txt", std::ios::out);
    if (!fpk.is_open()) {
        cout << "can't open ./pk.txt, generate pkey fail..." << endl;
        return false;
    }
    fpk << pkey.c_str();
    fpk.close();
    cout << "generate pkey ok..." << endl;
    fvk.open("./vk.txt", std::ios::out);
    if (!fvk.is_open()) {
        cout << "can't open ./vk.txt, generate vkey fail..." << endl;
        return false;
    }
    fvk << vkey.c_str();
    fvk.close();
    cout << "generate vkey ok..." << endl;
    
    return true;    
}


int main() {
    return !GenerateKeypair();
}
