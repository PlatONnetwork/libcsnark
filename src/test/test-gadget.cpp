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


using ::std::cerr;
using ::std::cout;
using ::std::endl;
using ::std::stringstream;
using namespace gadgetlib2;
using namespace libsnark;

typedef libff::Fr<libff::default_ec_pp> FieldT;
int prove_test(ProtoboardPtr pb, size_t input_size)
{
    libff::enter_block("Call to prove_test");

    r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
    //assert(cs.is_valid());
    // translate full variable assignment to libsnark format
    r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
    // extract primary and auxiliary input
    cs.primary_input_size = input_size;
    cs.auxiliary_input_size -= input_size;
    const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(), full_assignment.begin() + cs.num_inputs());
    const r1cs_auxiliary_input<FieldT> auxiliary_input(full_assignment.begin() + cs.num_inputs(), full_assignment.end());
    r1cs_variable_assignment<FieldT>().swap(full_assignment);

    assert(cs.is_satisfied(primary_input, auxiliary_input));

    libff::enter_block("Call to r1cs_ppzksnark_generator");
    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(cs);
    libff::leave_block("Call to r1cs_ppzksnark_generator");

    libff::enter_block("Call to r1cs_ppzksnark_prover");
    const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, primary_input, auxiliary_input);
    libff::leave_block("Call to r1cs_ppzksnark_prover");

    libff::enter_block("Call to r1cs_ppzksnark_verifier_strong_IC");
    bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, primary_input, proof);
    libff::leave_block("Call to r1cs_ppzksnark_verifier_strong_IC");

    cout << "Number of R1CS constraints: " << cs.num_constraints() << endl;
    cout << "Primary (public) input: " << primary_input << endl;
    //cout << "Auxiliary (private) input: " << auxiliary_input << endl;
    cout << "result status: " << primary_input.at(input_size-1) << endl;
    cout << "Verification status: " << verified << endl;

    const r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk = keypair.vk;

    //print_vk_to_file<default_r1cs_ppzksnark_pp>(vk, "../build/vk_data");
    //print_proof_to_file<default_r1cs_ppzksnark_pp>(proof, "../build/proof_data");
    libff::leave_block("leave  prove_test");
    return verified;
}


void test_selectgadget()
{
    initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable toggle("toggle");
    Variable oneValue("oneValue");
    Variable zeroValue("zeroValue");
    Variable result("result");
    auto selectGadget = Select_Gadget::create(pb, toggle, oneValue, zeroValue, result);
    selectGadget->generateConstraints();
    pb->val(toggle) = 0;
    pb->val(oneValue) = 3;
    pb->val(zeroValue) = 0;
    selectGadget->generateWitness();
    ASSERT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    prove_test(pb, 4);

    ASSERT_EQ(pb->val(result), 0);
    pb->val(result) = 0;
    ASSERT_FALSE(pb->isSatisfied());
    pb->val(result) = 1;
    ASSERT_CONSTRAINTS_SATISFIED(pb);
}

void test_orgadget()
{
    initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable input1("input1");
    Variable input2("input2");
    Variable result("result");
    auto orGadget = OR_Gadget::create(pb, input1, input2, result);
    orGadget->generateConstraints();
    pb->val(input1) = pb->val(input2) = 1;
    orGadget->generateWitness();
    ASSERT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    prove_test(pb, 3);

    ASSERT_EQ(pb->val(result), 1);
    pb->val(result) = 0;
    pb->val(input1) = 1;
    ASSERT_FALSE(pb->isSatisfied());
    pb->val(result) = 1;
    ASSERT_CONSTRAINTS_SATISFIED(pb);
    pb->val(input2) = 1;
    orGadget->generateWitness();
    ASSERT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    ASSERT_EQ(pb->val(result), 1);
}


void test_mingadget()
{
    initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    size_t wordBitSize = 32;
    PackedWord lhs("lhs");
    PackedWord rhs("rhs");
    Variable result("result");
    auto minGadget = MIN_Gadget::create(pb, wordBitSize, lhs, rhs, result);
    minGadget->generateConstraints();

    pb->val(lhs) = 4444;
    pb->val(rhs) = 88888;

    minGadget->generateWitness();
    prove_test(pb, 3);

    pb->val(result) = 4444;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
}

void test_modgadget()
{
    libff::enter_block("Call to test_modgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable B("B");
    Variable result("result");

    auto remGadget = SREM_Gadget::create(pb, A, B, result);
    remGadget->generateConstraints();

    pb->val(A) = 100;
    pb->val(B) = 7;

    remGadget->generateWitness();
    prove_test(pb, 3);

    pb->val(result) = 2;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_modgadget");
}

void test_divgadget()
{
    libff::enter_block("Call to test_divgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable B("B");
    Variable result("result");

    auto divGadget = SDIV_Gadget::create(pb, A, B, result);
    divGadget->generateConstraints();

    pb->val(A) = 100;
    pb->val(B) = 200;

    divGadget->generateWitness();
    prove_test(pb, 3);

    pb->val(result) = 0;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_divgadget");
}

void test_notgadget()
{
    libff::enter_block("Call to test_notgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable result("result");

    auto modGadget = NOT_Gadget::create(pb, A, result);
    modGadget->generateConstraints();

    pb->val(A) = 100;

    modGadget->generateWitness();
    prove_test(pb, 2);

    pb->val(result) = 0;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_notgadget");
}

void test_addgadget()
{
    libff::enter_block("Call to test_addgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable B("B");
    Variable result("result");

    auto addGadget = ADD_Gadget::create(pb, A, B, result);
    addGadget->generateConstraints();

    pb->val(A) = 0;
    pb->val(B) = 0;

    addGadget->generateWitness();
    prove_test(pb, 3);

    pb->val(result) = 0;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_addgadget");
}

void test_subgadget()
{
    libff::enter_block("Call to test_subgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable B("B");
    Variable result("result");

    auto subGadget = SUB_Gadget::create(pb, A, B, result);
    subGadget->generateConstraints();

    pb->val(A) = 13;
    pb->val(B) = 6;

    subGadget->generateWitness();
    prove_test(pb, 3);

    pb->val(result) = 7;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_subgadget");
}

void test_bitwise_orgadget()
{
    libff::enter_block("Call to test_bitwise_orgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable B("B");
    Variable result("result");

    auto bworGadget = BITWISE_OR_Gadget::create(pb, A, B, result);
    bworGadget->generateConstraints();

    pb->val(A) = 0x0F;
    pb->val(B) = 0xF0;

    bworGadget->generateWitness();
    prove_test(pb, 3);

    pb->val(result) = 0xFF;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_bitwise_orgadget");
}

void test_bitwise_xorgadget()
{
    libff::enter_block("Call to test_bitwise_xorgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable B("B");
    Variable result("result");

    auto bwxorGadget = BITWISE_XOR_Gadget::create(pb, A, B, result);
    bwxorGadget->generateConstraints();

    pb->val(A) = 0xFF;
    pb->val(B) = 0xF0;

    bwxorGadget->generateWitness();
    prove_test(pb, 3);

    pb->val(result) = 0x0F;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_bitwise_xorgadget");
}

void test_bitwise_andgadget()
{
    libff::enter_block("Call to test_bitwise_andgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable B("B");
    Variable result("result");

    auto bwandGadget = BITWISE_AND_Gadget::create(pb, A, B, result);
    bwandGadget->generateConstraints();

    pb->val(A) = 0x0F;
    pb->val(B) = 0xF0;

    bwandGadget->generateWitness();
    prove_test(pb, 3);

    pb->val(result) = 0x00;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_bitwise_andrgadget");
}


void test_zextgadget(long a, long res)
{
    libff::enter_block("Call to test_zextgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable result("result");

    auto zextGadget = ZEXT_Gadget::create(pb, A, 8, 32, result);
    zextGadget->generateConstraints();

    pb->val(A) = a;
    zextGadget->generateWitness();
    prove_test(pb, 2);

    pb->val(result) = res;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_zextgadget");
}

void test_sextgadget(long a, long res)
{
    libff::enter_block("Call to test_sextgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable result("result");

    auto sextGadget = SEXT_Gadget::create(pb, A, 8, 32, result);
    sextGadget->generateConstraints();

    pb->val(A) = a;
    sextGadget->generateWitness();
    prove_test(pb, 2);

    pb->val(result) = res;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_sextgadget");
}

void test_truncgadget(long a, long res)
{
    libff::enter_block("Call to test_truncgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable result("result");

    auto truncGadget = TRUNC_Gadget::create(pb, A, 32, 8, result);
    truncGadget->generateConstraints();

    pb->val(A) = a;
    truncGadget->generateWitness();
    prove_test(pb, 2);

    pb->val(result) = res;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_truncgadget");
}

void unit_test_eqgadget(long a, long b, long res)
{
    libff::enter_block("Call to test_eqgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable B("B");
    Variable result("result");

    auto eqGadget = EQ_Gadget::create(pb, A, B, result);
    eqGadget->generateConstraints();

    pb->val(A) = a;
    pb->val(B) = b;
    eqGadget->generateWitness();
    prove_test(pb, 3);

    pb->val(result) = res;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_eqgadget");
}

void unit_test_neqgadget(long a, long b, long res)
{
    libff::enter_block("Call to test_neqgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable B("B");
    Variable result("result");

    auto neqGadget = NEQ_Gadget::create(pb, A, B, result);
    neqGadget->generateConstraints();

    pb->val(A) = a;
    pb->val(B) = b;
    neqGadget->generateWitness();
    prove_test(pb, 3);

    pb->val(result) = res;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_neqgadget");
}

void unit_test_gtgadget(int64_t a, int64_t b, int res)
{
    libff::enter_block("Call to test_gtgadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable B("B");
    Variable result("result");

    auto gtGadget = SGT_Gadget::create(pb, A, B, result);
    gtGadget->generateConstraints();

    pb->val(A) = a;
    pb->val(B) = b;
    gtGadget->generateWitness();
    prove_test(pb, 3);

    pb->val(result) = res;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_gtgadget");
}

void unit_test_gegadget(int64_t a, int64_t b, int res)
{
    libff::enter_block("Call to test_gegadget");
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);
    Variable A("A");
    Variable B("B");
    Variable result("result");

    auto geGadget = SGE_Gadget::create(pb, A, B, result);
    geGadget->generateConstraints();

    pb->val(A) = a;
    pb->val(B) = b;
    geGadget->generateWitness();
    prove_test(pb, 3);

    pb->val(result) = res;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    libff::leave_block("leave  test_gegadget");
}


void exhaustive_test(ProtoboardPtr pb_, size_t num_input)
{
    initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();
    const size_t n = num_input*3+1;
    Variable A("A");
    Variable B("B");
    Variable C("C");
    Variable result("result");
    VariableArray arr(n, "arr");


    auto pb = Protoboard::create(R1P);
    ::std::vector<GadgetPtr> computeResult;

    for(unsigned int i = 0; i < n - 3; ){
        auto mulGadget = MUL_Gadget::create(pb, A, arr[i], arr[i+1]);
        computeResult.push_back(mulGadget);
        auto remGadget = SREM_Gadget::create(pb, arr[i+1], B, arr[i+2]);
        computeResult.push_back(remGadget);
        auto mulGadget1 = MUL_Gadget::create(pb, arr[i+2], C, arr[i+3]);
        computeResult.push_back(mulGadget1);
        i+=3;
    }

    libff::enter_block("Call to generateConstraints");
    for(auto& curGadget : computeResult) {
        curGadget->generateConstraints();
    }
    libff::leave_block("Call to generateConstraints");
    libff::enter_block("Call to generateWitness");
    pb->val(A) = 8;
    pb->val(B) = 5;
    pb->val(C) = 3;
    pb->val(arr[0]) = 1;
    for(auto& curGadget : computeResult) {
        curGadget->generateWitness();
    }
    pb->val(result) = pb->val(arr[n-1]);
    libff::leave_block("Call to generateWitness");

    ::std::vector<GadgetPtr>().swap(computeResult);
    VariableArray().swap(arr);
    prove_test(pb,4);

    pb->val(result) = 6;
    EXPECT_TRUE(pb->isSatisfied(PrintOptions::DBG_PRINT_IF_NOT_SATISFIED));
    return;
}

void test_eqgadget() {
    unit_test_eqgadget(0, 1, 0);
    unit_test_eqgadget(0, 0, 1);
    unit_test_eqgadget(0x81002011, 0x01002011, 0);
    unit_test_eqgadget(0x81002011, 0x81002011, 1);
}

void test_neqgadget() {
    unit_test_neqgadget(0, 1, 1);
    unit_test_neqgadget(0, 0, 0);
    unit_test_neqgadget(-1, -2, 1);
    unit_test_neqgadget(0x81222011, 0x81222011, 0);
    unit_test_neqgadget(0x81002011, 0x81002012, 1);
}

void test_gtgadget() {
    unit_test_gtgadget(0, 1, 0);
    unit_test_gtgadget(0, 0, 0);
    unit_test_gtgadget(-1, 0, 0);
    unit_test_gtgadget(-1, -2, 1);
    unit_test_gtgadget(2, -1, 1);
    unit_test_gtgadget(0x81222011, 0x81222011, 0);
    unit_test_gtgadget(0x81002012, 0x81002011, 1);
}

void test_gegadget() {
    unit_test_gegadget(0, 1, 0);
    unit_test_gegadget(0, 0, 1);
    unit_test_gegadget(-1, 0, 0);
    unit_test_gegadget(-1, -2, 1);
    unit_test_gegadget(-1, -1, 1);
    unit_test_gegadget(0x81222011, 0x81222011, 1);
    unit_test_gegadget(0x81002012, 0x81002011, 1);
    unit_test_gegadget(0x81002012, 0x81002080, 0);
}


#include<stdio.h>
#include<unistd.h>
#include<getopt.h>

int main(int argc, char *argv[])
{
    int opt;
    char *string = "t:z:s:m:";
    char   *stop_at  = NULL ;
    while ((opt = getopt(argc, argv, string))!= -1)
    {
        printf("opt = %c\t\t", opt);
        printf("optarg = %s\t\t",optarg);
        printf("argv[optind] = %s\n",argv[optind]);
        switch (opt) {
        case 't':
            //test-gadget -s0xFFFFFF01 0x01
            test_truncgadget(strtoul(optarg, &stop_at,0), strtoul(argv[optind], &stop_at,0));
            break;
        case 'z':
            //test-gadget -z0x81 0x00000081
            test_zextgadget(strtoul(optarg, &stop_at,0), strtoul(argv[optind], &stop_at,0));
            break;
        case 's':
            //test-gadget -s0x81 0xFFFFFF81
            test_sextgadget(strtoul(optarg, &stop_at,0), strtoul(argv[optind], &stop_at,0));
            break;
        case 'm':
            test_modgadget();
            break;
        default:
            printf("no this opt = %c\t\t", opt);
            break;
        }
    }
    //exhaustive_test(NULL, 5000);
    //test_modgadget();
    //test_orgadget();
    //test_selectgadget();
    //test_notgadget();
    //test_addgadget();
    //test_subgadget();
    //test_divgadget();
    //test_bitwise_orgadget();
    //test_bitwise_xorgadget();
    //test_bitwise_andgadget();
    //test_truncgadget();
    //test_zextgadget();
    //test_sextgadget();
    //test_eqgadget();
    //test_neqgadget();
    //test_gtgadget();
    //test_gegadget();
    
    return 0;
}
