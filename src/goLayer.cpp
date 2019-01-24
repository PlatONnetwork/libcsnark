// system header
#include <cassert>
#include <cstdio>
#include <string>
#include <cstdlib>
#include <iostream>
#include <sstream>

// libsnark header
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
#include <libsnark/gadgetlib2/adapters.hpp>
#include "goLayer.h"
#include "gadget2.hpp"

using namespace libsnark;
using namespace gadgetlib2;
using namespace std;
typedef libff::Fr<libff::default_ec_pp> FieldT;

#define INPUT_DELIM "#"

#ifdef  DEBUG    
#define DBG_MSG(...)	printf(__VA_ARGS__)
#else    
#define DBG_MSG(...)    
#endif 


extern bool libff::inhibit_profiling_info;
extern bool libff::inhibit_profiling_counters;


extern "C" 
{
	/// golbal var define
	ProtoboardPtr g_pbp;	
	map<void*, Variable*> g_mapVar;
	vector<GadgetPtr> g_vectGadgets;
	int64_t g_RetIndex;
	
	/// forward declaration
	uint64 AssignVar2SSANode(void* ptr);

	void Serial_pkey(const r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> &pk, std::string &pkey);
	void Deserial_pkey(r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> &pk, const std::string &pkey);
	void Serial_vkey(const r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> &vk, std::string &vkey);
	void Deserial_vkey(r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> &vk, const std::string &vkey);
	void Serial_proof(const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> &r1cs_proof, std::string &proof);
	void Deserial_proof(r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> &r1cs_proof, const std::string &proof);
	void split(const string& str, const string& delim, vector<string > &vectRet);
	void Serial_output(const FieldT output, std::string &strOutput);

	SSA_Node* CreateSSANode(int64_t input0, int64_t input1, int64_t input2, int64_t result, int32 Type);
	ProtoboardPtr getPBP() { return g_pbp; };

	/// create gadget declaration
	void CreateAddGadget(SSA_Node* pNode);
	void CreateSubGadget(SSA_Node* pNode);
	void CreateMulGadget(SSA_Node* pNode);
	void CreateSDivGadget(SSA_Node* pNode);
	void CreateSRemGadget(SSA_Node* pNode);
	void CreateUDivGadget(SSA_Node* pNode);
	void CreateURemGadget(SSA_Node* pNode);
	void CreateAndGadget(SSA_Node* pNode);
	void CreateOrGadget(SSA_Node* pNode);
	void CreateNotGadget(SSA_Node* pNode);
	void CreateSelectGadget(SSA_Node* pNode);
	void CreateBitwiseOrGadget(SSA_Node* pNode);
	void CreateBitwiseXorGadget(SSA_Node* pNode);
	void CreateBitwiseAndGadget(SSA_Node* pNode);
	void CreateTruncGadget(SSA_Node* pNode, size_t srcSize, size_t destSize);
	void CreateZeroExtGadget(SSA_Node* pNode, size_t srcSize, size_t destSize);
	void CreateSignedExtGadget(SSA_Node* pNode, size_t srcSize, size_t destSize);
	void CreateEqGadget(SSA_Node* pNode);
	void CreateNeqGadget(SSA_Node* pNode);
	void CreateSgtGadget(SSA_Node* pNode);
	void CreateSgeGadget(SSA_Node* pNode);
	void CreateUgtGadget(SSA_Node* pNode);
	void CreateUgeGadget(SSA_Node* pNode);

	/// init gadget env
	void gadget_initEnv() {
		initPublicParamsFromDefaultPp();
		GadgetLibAdapter::resetVariableIndex();
		g_pbp = Protoboard::create(R1P);
		cout << "call gadget_initEnv success ..." << endl;

    libff::inhibit_profiling_info = true;
    libff::inhibit_profiling_counters = true;
	}

	/// uninit gadget env
	void gadget_uninitEnv() {
		//delete pb variable
		for (auto ItemV : g_mapVar)
			delete ItemV.second;
		g_mapVar.clear();

		//delete gadget(auto release)
		g_vectGadgets.clear();
		cout << "call gadget_uninitEnv success ..." << endl;
	}
	
  uint64 gadget_createPBVar(int64_t ptr) {
	assert(ptr);
    Variable *pbvar = nullptr;

    // find or new variable
    map<void*, Variable*>::iterator it = g_mapVar.find((void *)ptr);
    
    if (it == g_mapVar.end()) {
    	pbvar = new Variable;
    	g_mapVar[(void *)ptr] = pbvar;
    	cout << "create variable  " << ptr  << " success." << endl;
    } else {
      pbvar = it->second;
    	cout << "the variable " << ptr << " has been created." << endl; 
    }
    return (uint64)pbvar;
  }

	/// create binary op gadget object(OK=1,Fail=0)
	unsigned char gadget_createGadget(int64_t input0, int64_t input1, int64_t input2, int64_t result, int32 Type) {		
		assert(input0);
		assert(result);

		// create ssa node
    	SSA_Node* pNode = CreateSSANode(input0, input1, input2, result, Type);

		if (!pNode) {
			cout << "create ssa node fail, ssa node type is " << Type << endl;
			return 0;
		}
		
		// create gadget
		switch (pNode->type) {
			case G_ADD:
			CreateAddGadget(pNode);
			break;
			
			case G_SUB:
			CreateSubGadget(pNode);
			break;
			
			case G_MUL:
			CreateMulGadget(pNode);
			break;
			
			case G_SDIV:
			CreateSDivGadget(pNode);
			break;

			case G_SREM:
			CreateSRemGadget(pNode);
			break;
	
			case G_UDIV:
			CreateUDivGadget(pNode);
			break;

			case G_UREM:
			CreateURemGadget(pNode);
			break;

			case G_AND:
			CreateAndGadget(pNode);
			break;
			
			case G_OR:
			CreateOrGadget(pNode);
			break;

			case G_NOT:
			CreateNotGadget(pNode);
			break;

			case G_SELECT:
			CreateSelectGadget(pNode);
			break;

			case G_BITW_OR:
			CreateBitwiseOrGadget(pNode);
			break;

			case G_BITW_XOR:
			CreateBitwiseXorGadget(pNode);
			break;

			case G_BITW_AND:
			CreateBitwiseAndGadget(pNode);
			break;

			case G_TRUNC:
			CreateTruncGadget(pNode, input1, input2);
			break;

			case G_ZEXT:
			CreateZeroExtGadget(pNode, input1, input2);
			break;

			case G_SEXT:
			CreateSignedExtGadget(pNode, input1, input2);
			break;

			case G_EQ:
			CreateEqGadget(pNode);
			break;

			case G_NEQ:
			CreateNeqGadget(pNode);
			break;

			case G_SGT:
			CreateSgtGadget(pNode);
			break;

			case G_SGE:
			CreateSgeGadget(pNode);
			break;
	
			case G_UGT:
			CreateUgtGadget(pNode);
			break;

			case G_UGE:
			CreateUgeGadget(pNode);
			break;		
			default:
			cout << "unkown ssa type " << Type << endl;
			return 0;
			break;
		}
		
		return 1;
	}
	
	/// assign variable
	void gadget_setVar(int64_t ptr, int64 Val, unsigned char is_unsigned) {
		assert(ptr);
		cout << "set var " << ptr << " value " << Val << endl;
		map<void*, Variable*>::iterator it = g_mapVar.find((void *)ptr);
		if (it != g_mapVar.end()) 
			g_pbp->val(*(it->second)) = Val;
		else
			cout << "PB Variable " << ptr << " not exist." << endl;
	}
	
	/// get variable value
	long gadget_getVar(int64_t ptr){
		assert(ptr);
		long destVal = 0;
		map<void*, Variable*>::iterator it = g_mapVar.find((void *)ptr);
		if (it != g_mapVar.end()) 
		destVal = g_pbp->val(*(it->second)).asLong();
		else
		cout << "PB Variable " << ptr << " not exist." << endl;

		cout << "get var " << ptr << " value " << destVal << endl;
		return destVal;
	}

	/// set reture address
	void gadget_setRetIndex(int64_t ptr) {
		g_RetIndex = ptr;
	}

	/// generate R1cs
	void gadget_generateConstraints() {	
		for (auto Item : g_vectGadgets)
			Item->generateConstraints();
	}

	/// generate witness
	void gadget_generateWitness() {	
		// generate witness
		for (auto Item : g_vectGadgets)
			Item->generateWitness();
	}
	
	///	generate proof and result(1=OK, 0=Fail)
	unsigned char GenerateProof(const char *pPKEY, char *pProof, unsigned prSize){
		assert(pPKEY);
		assert(pProof);
		
		// deserialization pk
		cout << "entry GenerateProof func" << endl;
		r1cs_ppzksnark_proving_key<libff::default_ec_pp> pk;
		const string strpk = pPKEY;
		Deserial_pkey(pk, strpk);
		cout << "call Deserial_pkey success..." << endl;
		cout << "Number of R1CS constraints: " << pk.constraint_system.num_constraints() << endl;
		
		// get var assignment
		const r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*g_pbp);
        
    cout << "call get_variable_assignment_from_gadgetlib2 success..." << endl;

		// get primary and auxiliary input
		r1cs_primary_input<FieldT> primary_input(full_assignment.begin(), full_assignment.begin() + pk.constraint_system.num_inputs());
		r1cs_auxiliary_input<FieldT> auxiliary_input(full_assignment.begin() + pk.constraint_system.num_inputs(), full_assignment.end());
		
		
		// call libsnark prover to generate proof
		r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(pk, primary_input, auxiliary_input);
		cout << "call r1cs_ppzksnark_prover success..." << endl;

		// serialization proof and result
		string strProof;
		Serial_proof(proof, strProof);
		cout << "call Serial_proof success..." << endl;
		cout << "proof buffer size=" << strProof.size() << endl;
		if (strProof.size() > prSize) {
			cout << "proof buffer sizes or result buffer sizes not enough." << endl; 
			return 0;
		}
		strcpy(pProof, strProof.c_str());
		return 1;
	}

  unsigned char GenerateResult(int64_t RetIndex, char *pResult, unsigned resSize){

    long RetValue = gadget_getVar(RetIndex);
    sprintf(pResult, "%lx", RetValue);
    return 1;
  }

  unsigned char GenerateProofAndResult(const char *pPKEY, char *pProof, unsigned prSize, 
                          char *pResult, unsigned resSize) {

    int Success = true;
    Success &= GenerateProof(pPKEY, pProof, prSize);
    Success &= GenerateResult(g_RetIndex, pResult, resSize);
    return Success;
  }
	
	/// verify result(1=OK, 0=Fail)
	unsigned char Verify(const char *pVKEY, const char *pPoorf, const char *pInput, const char *pOutput) {
		assert(pVKEY);
		assert(pPoorf);
		assert(pInput);
		assert(pOutput);
		cout << "Verify param, input:" << pInput << ", result " << pOutput << endl;

		// Initialize prime field parameters. This is always needed for R1P.
		initPublicParamsFromDefaultPp();

		// get input value
		const string strInput = pInput;
		const string strOutput= pOutput;
		vector<string> vectVal;
		r1cs_primary_input<FieldT> pinput;
		
		// spilt input value
		split(strInput, INPUT_DELIM, vectVal);
		for (auto Item : vectVal)
			pinput.emplace_back(strtol(Item.c_str(), nullptr, 10));
		vectVal.clear();
		
		// spilt output value 
		split(strOutput, INPUT_DELIM, vectVal);

    typedef gadgetlib2::GadgetLibAdapter GLA;
    const GLA adapter;

		for (auto Item : vectVal){
      FElem FE = strtoul(Item.c_str(), nullptr, 16);
			pinput.emplace_back(adapter.convert(FE));
    }
		vectVal.clear();
		cout << "Real primary (public) input: " << pinput << endl;
		
		// deserialization vk
		r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk;
		string strvk = pVKEY;
		Deserial_vkey(vk, strvk);
		
		// deserialization proof
		r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof;
		string strProof = pPoorf;
		Deserial_proof(proof, strProof);
					
		// cal libsnark verify and reture
		return r1cs_ppzksnark_verifier_strong_IC(vk, pinput, proof);
	}

	/// create add gadget
	void CreateAddGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
    	auto addGadget = ADD_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(addGadget);
	}

	/// create sub gadget
	void CreateSubGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
    	auto subGadget = SUB_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(subGadget);
	}

	/// create mul gadget
	void CreateMulGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
      auto mulGadget = MUL_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(mulGadget);
	}

	/// create div gadget
	void CreateSDivGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
    	auto divGadget = SDIV_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(divGadget);
	}

	/// create mod gadget
	void CreateSRemGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
    	auto modGadget = SREM_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(modGadget);
	}

	/// create div gadget
	void CreateUDivGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
    	auto divGadget = UDIV_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(divGadget);
	}

	/// create mod gadget
	void CreateURemGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
    	auto modGadget = UREM_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(modGadget);
	}

	/// create logic and gadget
	void CreateAndGadget(SSA_Node* pNode) {
		VariableArray vaInput;
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
		vaInput.emplace_back(*plhsVar);
		vaInput.emplace_back(*prhsVar);
		auto andGadget = AND_Gadget::create(g_pbp, vaInput, *presVar);
		g_vectGadgets.emplace_back(andGadget);
	}

	/// create logic or gadget
	void CreateOrGadget(SSA_Node* pNode) {
		VariableArray vaInput;
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
		vaInput.emplace_back(*plhsVar);
		vaInput.emplace_back(*prhsVar);
		auto orGadget = OR_Gadget::create(g_pbp, vaInput, *presVar);
		g_vectGadgets.emplace_back(orGadget);
	}

	/// create logic not gadget
	void CreateNotGadget(SSA_Node* pNode) {
		Variable *pVar = (Variable*)(pNode->Input[0]);
		Variable *presVar = (Variable*)(pNode->Result);
		auto notGadget = NOT_Gadget::create(g_pbp, *pVar, *presVar);
		g_vectGadgets.emplace_back(notGadget);
	}

	/// create select gadget
	void CreateSelectGadget(SSA_Node* pNode) {
		Variable *toggleVar = (Variable*)(pNode->Input[0]);
		Variable *oneVar  = (Variable*)(pNode->Input[1]);
		Variable *zeroVar = (Variable*)(pNode->Input[2]);
		Variable *resVar  = (Variable*)(pNode->Result);
		auto selectGadget = Select_Gadget::create(g_pbp, *toggleVar, *oneVar, *zeroVar, *resVar);
		g_vectGadgets.emplace_back(selectGadget);
	}

	/// create bitwise or gadget
	void CreateBitwiseOrGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
		auto bitorGadget = BITWISE_OR_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(bitorGadget);
	}

	/// create bitwise xor gadget
	void CreateBitwiseXorGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
		auto bitxorGadget = BITWISE_XOR_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(bitxorGadget);
	}

	/// create bitwise and gadget
	void CreateBitwiseAndGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
		auto bitandGadget = BITWISE_AND_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(bitandGadget);
	}

	/// create trunc gadget
	void CreateTruncGadget(SSA_Node* pNode, size_t srcSize, size_t destSize) {
		Variable *psrcVar = (Variable*)(pNode->Input[0]);
		Variable *presVar = (Variable*)(pNode->Result);
		auto truncGadget = TRUNC_Gadget::create(g_pbp, *psrcVar, srcSize, destSize, *presVar);
		g_vectGadgets.emplace_back(truncGadget);
	}

	/// create zero extension gadget
	void CreateZeroExtGadget(SSA_Node* pNode, size_t srcSize, size_t destSize) {
		Variable *psrcVar = (Variable*)(pNode->Input[0]);
		Variable *presVar = (Variable*)(pNode->Result);
		auto zextGadget = ZEXT_Gadget::create(g_pbp, *psrcVar, srcSize, destSize, *presVar);
		g_vectGadgets.emplace_back(zextGadget);
	}

	/// create signed extension gadget
	void CreateSignedExtGadget(SSA_Node* pNode, size_t srcSize, size_t destSize) {
		Variable *psrcVar = (Variable*)(pNode->Input[0]);
		Variable *presVar = (Variable*)(pNode->Result);
		auto sextGadget = SEXT_Gadget::create(g_pbp, *psrcVar, srcSize, destSize, *presVar);
		g_vectGadgets.emplace_back(sextGadget);
	}

	/// create equal gadget
	void CreateEqGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
		auto eqGadget = EQ_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(eqGadget);
	}

	/// create neq gadget
	void CreateNeqGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
		auto neqGadget = NEQ_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(neqGadget);
	}

	/// create signed gt gadget
	void CreateSgtGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
		auto sgtGadget = SGT_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(sgtGadget);
	}

	/// create signed ge gadget
	void CreateSgeGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
		auto sgeGadget = SGE_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(sgeGadget);
	}

	/// create signed gt gadget
	void CreateUgtGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
		auto ugtGadget = UGT_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(ugtGadget);
	}

	/// create signed ge gadget
	void CreateUgeGadget(SSA_Node* pNode) {
		Variable *plhsVar = (Variable*)(pNode->Input[0]);
		Variable *prhsVar = (Variable*)(pNode->Input[1]);
		Variable *presVar = (Variable*)(pNode->Result);
		auto ugeGadget = UGE_Gadget::create(g_pbp, *plhsVar, *prhsVar, *presVar);
		g_vectGadgets.emplace_back(ugeGadget);
	}

	/// create ssa node
	SSA_Node* CreateSSANode(int64_t input0, int64_t input1, int64_t input2, int64_t result, int32 Type) {		
		// create SSA_Node
		SSA_Node *pNode = new SSA_Node;
		assert(pNode);
		pNode->type = Type;
		
		// find or new input0 variable
		if (input0) {
			pNode->Input[0] = gadget_createPBVar(input0);
		}
		
		// find or new input1 variable
		if (input1) {
			pNode->Input[1] = gadget_createPBVar(input1);
		}
		
		// find or new input2 variable
		if (input2) {
			pNode->Input[2] = gadget_createPBVar(input2);
		}

		// find or new result variable
		if (result) {
			pNode->Result = gadget_createPBVar(result);
		}
		
		// return SSA_Node
		return pNode;
	}
	
	/// serialization pkey
    void Serial_pkey(const r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> &pk, std::string &pkey) {
        std::ostringstream ostr; 
        ostr << pk;
        pkey = ostr.str();
    }
	
	/// deserialization pkey
	void Deserial_pkey(r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> &pk, const std::string &pkey) {
		std::istringstream istr(pkey); 
		istr >> pk;
	}

	/// Serialization vkey
    void Serial_vkey(const r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> &vk, std::string &vkey) {
        std::ostringstream ostr; 
        ostr << vk;
        vkey = ostr.str();
    }
	
	/// deserialization vkey
	void Deserial_vkey(r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> &vk, const std::string &vkey) {
		std::istringstream istr(vkey); 
		istr >> vk;
	}
	
	/// serialization proof
	void Serial_proof(const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> &r1cs_proof, std::string &proof) {
		std::ostringstream ostr; 
		ostr << r1cs_proof;
		proof = ostr.str();
	}
	
	/// deserialization proof
	void Deserial_proof(r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> &r1cs_proof, const std::string &proof) {
		std::istringstream istr(proof); 
		istr >> r1cs_proof;
	}

	/// Serialization output
    void Serial_output(const FieldT output, std::string &strOutput) {
        std::ostringstream ostr; 
        ostr << output;
        strOutput = ostr.str();
    }
	
	///	split string by delim
	void split(const string& str, const string& delim, vector<string > &vectRet)
	{
		size_t nLast  = 0;
		size_t nIndex = str.find_first_of(delim, nLast);
		while (nIndex != string::npos)
		{
			vectRet.push_back(str.substr(nLast, nIndex-nLast));
			nLast = nIndex + delim.size();
			nIndex = str.find_first_of(delim, nLast);
		}
		if ((nIndex - nLast) > 0)
		{
			vectRet.push_back(str.substr(nLast, nIndex-nLast));
		}
	}

  void keypairGen(unsigned primary_input_size, std::string pkey, std::string vkey){

    // translate constraint system to libsnark format.
    r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*g_pbp);
    cs.primary_input_size = primary_input_size;  //num:3 must be replace $input_output count$
    cs.auxiliary_input_size -= cs.primary_input_size;

    // generate key pair
    r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keyPair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(cs);
    Serial_pkey(keyPair.pk, pkey);
    Serial_vkey(keyPair.vk, vkey);
  }
};

