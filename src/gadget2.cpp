/** @file
 *****************************************************************************
 Declarations of the interfaces and junzhen gadgets for R1P (Rank 1 prime characteristic)
 constraint systems.

 See details in gadget.hpp .
 *****************************************************************************
 * @author     chegvra.
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <cmath>
#include <memory>

#include <gadget2.hpp>

namespace gadgetlib2
{
/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_ADD_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
ADD_GadgetBase::~ADD_GadgetBase() {}

R1P_ADD_Gadget::R1P_ADD_Gadget(ProtoboardPtr pb,
                               const Variable &A,
                               const Variable &B,
                               const Variable &result)
    : Gadget(pb), ADD_GadgetBase(pb), R1P_Gadget(pb),
      lhs_(A), rhs_(B), result_(result) {}

void R1P_ADD_Gadget::init() {}

/*
    Constraint breakdown:
    (1) (A + B) * 1 = result
*/
void R1P_ADD_Gadget::generateConstraints()
{
    addRank1Constraint(lhs_ + rhs_, 1, result_, "(lhs_ + rhs) * 1 = result_");
}

void R1P_ADD_Gadget::generateWitness()
{
    val(result_) = val(lhs_) + val(rhs_);
    printf("!!! %ld = %ld + %ld\n", val(result_).asLong(), val(lhs_).asLong(), val(rhs_).asLong());
}
/*********************************/
/***    END OF R1P_ADD_Gadget  ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_SUB_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
SUB_GadgetBase::~SUB_GadgetBase() {}

R1P_SUB_Gadget::R1P_SUB_Gadget(ProtoboardPtr pb,
                               const Variable &A,
                               const Variable &B,
                               const Variable &result)
    : Gadget(pb), SUB_GadgetBase(pb), R1P_Gadget(pb),
      lhs_(A), rhs_(B), result_(result) {}

void R1P_SUB_Gadget::init() {}

/*
    Constraint breakdown:
    (1) (A - B) * 1 = result
*/
void R1P_SUB_Gadget::generateConstraints()
{
    addRank1Constraint(lhs_ - rhs_, 1, result_, "(lhs_ - rhs) * 1 = result_");
}

void R1P_SUB_Gadget::generateWitness()
{
    val(result_) = val(lhs_) - val(rhs_);

    printf("!!! %ld = %ld - %ld\n", val(result_).asLong(), val(lhs_).asLong(), val(rhs_).asLong());
}
/*********************************/
/***    END OF R1P_SUB_Gadget  ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_NOT_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
NOT_GadgetBase::~NOT_GadgetBase() {}

R1P_NOT_Gadget::R1P_NOT_Gadget(ProtoboardPtr pb,
                               const Variable &input,
                               const Variable &result)
    : Gadget(pb), NOT_GadgetBase(pb), R1P_Gadget(pb),
      input_(input), result_(result) {}

void R1P_NOT_Gadget::init() {}

/*
    Constraint breakdown:
    (1) input * result = 0
    (2) 1 - input * inputInverse = result
*/
void R1P_NOT_Gadget::generateConstraints()
{
    addRank1Constraint(input_, result_, 0, "input*result = 0");
    addRank1Constraint(input_, inputInverse_, temp1_,
                       "input_ * result_ = temp1_");
    addRank1Constraint(1 - temp1_, 1, result_,
                       "1-temp1_ * 1 = result");
}

void R1P_NOT_Gadget::generateWitness()
{
    FElem inputVal = val(input_);
    if (val(inputVal) == 0) {
        val(inputInverse_) = 0;
        val(temp1_) = 0;
        val(result_) = 1;
    }
    else {
        val(inputInverse_) = inputVal.inverse(R1P);
        val(temp1_) = 1;
        val(result_) = 0;
    }
    printf("!!! %ld = ! %ld\n", val(result_).asLong(), val(inputVal).asLong());
}
/*********************************/
/***    END OF R1P_NOT_Gadget  ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_MIN_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

MIN_GadgetBase::~MIN_GadgetBase() {}

R1P_MIN_Gadget::R1P_MIN_Gadget(ProtoboardPtr pb,
                               const size_t &wordBitSize,
                               const PackedWord &lhs,
                               const PackedWord &rhs,
                               const Variable &result)
    : Gadget(pb), MIN_GadgetBase(pb), R1P_Gadget(pb), wordBitSize_(wordBitSize),
      lhs_(lhs), rhs_(rhs), result_(result),comparsionGadget_(){}

void R1P_MIN_Gadget::init()
{
    comparsionGadget_ = Comparison_Gadget::create(pb_, wordBitSize_, lhs_, rhs_, less_, lessOrEqual_);
}
/*
    Constraint breakdown:

    for succinctness we shall define:
    (1) wordBitSize == n
    (2) lhs == A
    (3) rhs == B

    if A < B then less = 1;
    if A >= B then less = 0;
    result =  less*A+ (1-less)*B
*/
void R1P_MIN_Gadget::generateConstraints()
{
    comparsionGadget_->generateConstraints();

    addRank1Constraint(lhs_, less_, sym_1_, "lhs*less = sym_1");
    addRank1Constraint(rhs_, 1 - less_, sym_2_,
                       "rhs * (1-less) = sym_2");
    addRank1Constraint(sym_1_ + sym_2_, 1, result_,
                       "sym_1 + sym_2 * 1 = result");
}

void R1P_MIN_Gadget::generateWitness()
{
    comparsionGadget_->generateWitness();
    val(sym_1_) = val(lhs_) * val(less_);
    val(sym_2_) = val(rhs_) * (1 - val(less_));
    val(result_) = val(sym_1_) + val(sym_2_);

    printf("!!! %ld = min %ld %ld\n", val(result_).asLong(), val(lhs_).asLong(), val(rhs_).asLong());
/*
    std::cout << "lhs:" << val(lhs_).asLong() << std::endl;
    std::cout << "rhs:" << val(rhs_).asLong() << std::endl;
    std::cout << "less:" << val(less_).asLong() << std::endl;
    std::cout << "sym_1_:" << val(sym_1_).asLong() << std::endl;
    std::cout << "sym_2_:" << val(sym_2_).asLong() << std::endl;
    std::cout << "result_:" << val(result_).asLong() << std::endl;
*/
}

/*********************************/
/***    END OF R1P_MIN_Gadget  ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_SREM_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
SREM_GadgetBase::~SREM_GadgetBase() {}

R1P_SREM_Gadget::R1P_SREM_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result)
    : Gadget(pb), SREM_GadgetBase(pb), R1P_Gadget(pb), A_(A), B_(B), result_(result),
       comparsionGadget1_(),comparsionGadget2_(){}

void R1P_SREM_Gadget::init()
{
//    comparsionGadget1_ = GETBIT_Gadget::create(pb_, result_, BIT_SIZE-1, Zero);
//    comparsionGadget2_ = SGT_Gadget::create(pb_, B_, result_, One);
}

//A=B*C+result
//0 <= result
//result < B
void R1P_SREM_Gadget::generateConstraints()
{
    addRank1Constraint(B_, C_, A_ - result_,
                       "B*C = A-result");
    /*
    comparsionGadget1_->generateConstraints();
    comparsionGadget2_->generateConstraints();
    addRank1Constraint(Zero, 1, 0, "Zero = 0");
    addRank1Constraint(One, 1, 1, "Zero = 0");
    */
}

void R1P_SREM_Gadget::generateWitness()
{
  if(val(B_)==0){
    val(result_) = val(A_);
    val(C_) = 0;
    printf("!!! skip %ld %% %ld\n", val(A_).asLong(), val(B_).asLong());
  }else{
    val(C_) = val(A_).asLong() / val(B_).asLong();
    val(result_) = val(A_) - val(C_) * val(B_);

   // comparsionGadget1_->generateWitness();
   // comparsionGadget2_->generateWitness();

    printf("!!! %ld = %ld % %ld\n", val(result_).asLong(), val(A_).asLong(), val(B_).asLong());
  }
}
/*********************************/
/***    END OF R1P_SREM_Gadget  ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_SDIV_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
SDIV_GadgetBase::~SDIV_GadgetBase() {}

R1P_SDIV_Gadget::R1P_SDIV_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result)
    : Gadget(pb), SDIV_GadgetBase(pb), R1P_Gadget(pb), A_(A), B_(B), result_(result),
       comparsionGadget1_(),comparsionGadget2_(){}

void R1P_SDIV_Gadget::init()
{
//    comparsionGadget1_ = Comparison_Gadget::create(pb_, wordBitSize_, ZERO_, result_, less1_, lessOrEqual1_);
 //   comparsionGadget2_ = Comparison_Gadget::create(pb_, wordBitSize_, result_, C_, less2_, lessOrEqual2_);
}

void R1P_SDIV_Gadget::generateConstraints()
{
    addRank1Constraint(result_, B_, A_-C_, "result * B = A - C");
  //  comparsionGadget1_->generateConstraints();
  //  comparsionGadget2_->generateConstraints();
}

void R1P_SDIV_Gadget::generateWitness()
{
  if(val(B_)==0){
    val(C_) = val(A_);
    val(result_) = 0;
    printf("!!! skip %ld / %ld\n", val(A_).asLong(), val(B_).asLong());
  }else{
    val(result_) = val(A_).asLong() / val(B_).asLong();
    val(C_) = val(A_) - val(result_) * val(B_);
    printf("!!! %ld = %ld / %ld\n", val(result_).asLong(), val(A_).asLong(), val(B_).asLong());
  }
}
/*********************************/
/***    END OF R1P_SDIV_Gadget  ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                       R1P_UREM_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
UREM_GadgetBase::~UREM_GadgetBase() {}

R1P_UREM_Gadget::R1P_UREM_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& R)
    : Gadget(pb), UREM_GadgetBase(pb), R1P_Gadget(pb), A_(A), B_(B), R_(R) {}

void R1P_UREM_Gadget::init()
{
    udivision_Gadget = UDivision_Gadget::create(pb_, A_, B_, Q_, R_);
}

//A=B*C+result
//0 <= result
//result < B
void R1P_UREM_Gadget::generateConstraints()
{
  udivision_Gadget->generateConstraints();
    
}

void R1P_UREM_Gadget::generateWitness()
{

  udivision_Gadget->generateWitness();
  printf("!!! %lu = %lu %% %lu\n", val(R_).asLong(), val(A_).asLong(), val(B_).asLong());
}

/*********************************/
/***   END OF R1P_UREM_Gadget  ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                       R1P_UDIV_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
UDIV_GadgetBase::~UDIV_GadgetBase() {}

R1P_UDIV_Gadget::R1P_UDIV_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& Q)
    : Gadget(pb), UDIV_GadgetBase(pb), R1P_Gadget(pb), A_(A), B_(B), Q_(Q) {}

void R1P_UDIV_Gadget::init()
{
    udivision_Gadget = UDivision_Gadget::create(pb_, A_, B_, Q_, R_);
}

//A=B*C+result
//0 <= result
//result < B
void R1P_UDIV_Gadget::generateConstraints()
{
  udivision_Gadget->generateConstraints();
    
}

void R1P_UDIV_Gadget::generateWitness()
{

  udivision_Gadget->generateWitness();
  printf("!!! %lu = %lu / %lu\n", val(Q_).asLong(), val(A_).asLong(), val(B_).asLong());
}

/*********************************/
/***   END OF R1P_UDIV_Gadget  ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_MUL_Gadget                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/


MUL_GadgetBase::~MUL_GadgetBase() {}

R1P_MUL_Gadget::R1P_MUL_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result)
    : Gadget(pb), MUL_GadgetBase(pb), R1P_Gadget(pb), A_(A), B_(B), result_(result){}

void R1P_MUL_Gadget::init()
{
}

//A=C*B+result
//0 <= result
//result < B
void R1P_MUL_Gadget::generateConstraints()
{
    addRank1Constraint(A_, B_, result_, "A*B = result");
}

void R1P_MUL_Gadget::generateWitness()
{
    val(result_) = val(A_).asLong() * val(B_).asLong();
    printf("!!! %ld = %ld * %ld\n", val(result_).asLong(), val(A_).asLong(), val(B_).asLong());
}
/*********************************/
/***    END OF R1P_MUIT_Gadget  ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_BITWISE_OR_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
BITWISE_OR_GadgetBase::~BITWISE_OR_GadgetBase() {}

R1P_BITWISE_OR_Gadget::R1P_BITWISE_OR_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result)
    : Gadget(pb), BITWISE_OR_GadgetBase(pb), R1P_Gadget(pb), A_(A), B_(B), result_(result),
    A_alpha_u_(BIT_SIZE,  "A_alpha"), B_alpha_u_(BIT_SIZE,  "B_alpha"), sym_(BIT_SIZE, ""){}

void R1P_BITWISE_OR_Gadget::init()
{
    alphaDualVariablePacker1_ = Packing_Gadget::create(pb_, A_alpha_u_, A_, false);
    alphaDualVariablePacker2_ = Packing_Gadget::create(pb_, B_alpha_u_, B_, false);
    alphaDualVariablePacker3_ = Packing_Gadget::create(pb_, sym_, result_, true);
    for (auto i = 0; i < BIT_SIZE; i++) 
       orGadget_[i] = OR_Gadget::create(pb_, A_alpha_u_[i], B_alpha_u_[i], sym_[i]);
}

//bit0 = (A.O + B.O) > 0 ? 1 : 0
//bit1 = (A.1 + B.1) > 0 ? 1 : 0
//......
//bitn = (A.n + B.n) > 0 ? 1 : 0
//result = bit0 + bit1*2^1 + bit2*2^2 + bitn*2^n
//opt:=>
//sum_bit0 = (A.O + B.O) > 0 ? 2^0 : 0
//sum_bit1 = (A.1 + B.1) > 0 ? 2^1 : 0
//......
//sum_bitn = (A.n + B.n) > 0 ? 2^n : 0
//result = sum_bit0 + sum_bit1 + ... + sum_bitn

void R1P_BITWISE_OR_Gadget::generateConstraints()
{
    alphaDualVariablePacker1_->generateConstraints();
    alphaDualVariablePacker2_->generateConstraints();
    for (auto i = 0; i < BIT_SIZE; i++)
        orGadget_[i]->generateConstraints();
    alphaDualVariablePacker3_->generateConstraints();
}

void R1P_BITWISE_OR_Gadget::generateWitness()
{
    alphaDualVariablePacker1_->generateWitness();
    alphaDualVariablePacker2_->generateWitness();
    for (auto i = 0; i < BIT_SIZE; i++)
        orGadget_[i]->generateWitness();
    alphaDualVariablePacker3_->generateWitness();

    printf("!!! %ld = %ld | %ld\n", val(result_).asLong(), val(A_).asLong(), val(B_).asLong());
}
/*********************************/
/***    END OF R1P_BITWISE_OR_Gadget  ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_BITWISE_XOR_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
BITWISE_XOR_GadgetBase::~BITWISE_XOR_GadgetBase() {}

R1P_BITWISE_XOR_Gadget::R1P_BITWISE_XOR_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result)
    : Gadget(pb), BITWISE_XOR_GadgetBase(pb), R1P_Gadget(pb), A_(A), B_(B), result_(result),
    A_alpha_u_(BIT_SIZE,  "A_alpha"), B_alpha_u_(BIT_SIZE,  "B_alpha"), sym_(BIT_SIZE, ""){}

void R1P_BITWISE_XOR_Gadget::init()
{
    alphaDualVariablePacker1_ = Packing_Gadget::create(pb_, A_alpha_u_, A_, false);
    alphaDualVariablePacker2_ = Packing_Gadget::create(pb_, B_alpha_u_, B_, false);
    alphaDualVariablePacker3_ = Packing_Gadget::create(pb_, sym_, result_, true);
    for (auto i = 0; i < BIT_SIZE; i++) 
       neqGadget_[i] = NEQ_Gadget::create(pb_, A_alpha_u_[i], B_alpha_u_[i], sym_[i]);
}


//bit0 = (A.O + B.O) == 1 ? 1 : 0
//bit1 = (A.1 + B.1) == 1 ? 1 : 0
//......
//bitn = (A.n + B.n) == 1 ? 1 : 0
//result = bit0 + bit1*2^1 + bit2*2^2 + bitn*2^n
//opt:=>
//sum_bit0 = (A.O + B.O) == 1 ? 2^0 : 0
//sum_bit1 = (A.1 + B.1) == 1 ? 2^1 : 0
//......
//sum_bitn = (A.n + B.n) == 1 ? 2^n : 0
//result = sum_bit0 + sum_bit1 + ... + sum_bitn

void R1P_BITWISE_XOR_Gadget::generateConstraints()
{
    alphaDualVariablePacker1_->generateConstraints();
    alphaDualVariablePacker2_->generateConstraints();
    for (auto i = 0; i < BIT_SIZE; i++)
        neqGadget_[i]->generateConstraints();
    alphaDualVariablePacker3_->generateConstraints();
}

void R1P_BITWISE_XOR_Gadget::generateWitness()
{
    alphaDualVariablePacker1_->generateWitness();
    alphaDualVariablePacker2_->generateWitness();
    for (auto i = 0; i < BIT_SIZE; i++)
        neqGadget_[i]->generateWitness();
    alphaDualVariablePacker3_->generateWitness();


    printf("!!! %ld = %ld ^ %ld\n", val(result_).asLong(), val(A_).asLong(), val(B_).asLong());
}
/*********************************/
/*** END OF R1P_BITWISE_XOR_Gadget ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_BITWISE_AND_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
BITWISE_AND_GadgetBase::~BITWISE_AND_GadgetBase() {}

R1P_BITWISE_AND_Gadget::R1P_BITWISE_AND_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result)
    : Gadget(pb), BITWISE_AND_GadgetBase(pb), R1P_Gadget(pb), A_(A), B_(B), result_(result),
    A_alpha_u_(BIT_SIZE,  "A_alpha"), B_alpha_u_(BIT_SIZE,  "B_alpha"), sym_(BIT_SIZE, ""){}

void R1P_BITWISE_AND_Gadget::init()
{
    alphaDualVariablePacker1_ = Packing_Gadget::create(pb_, A_alpha_u_, A_, false);
    alphaDualVariablePacker2_ = Packing_Gadget::create(pb_, B_alpha_u_, B_, false);
    alphaDualVariablePacker3_ = Packing_Gadget::create(pb_, sym_, result_, true);
    for (auto i = 0; i < BIT_SIZE; i++) 
       andGadget_[i] = AND_Gadget::create(pb_, A_alpha_u_[i], B_alpha_u_[i], sym_[i]);
}

//bit0 = (A.O + B.O) == 2 ? 1 : 0
//bit1 = (A.1 + B.1) == 2 ? 1 : 0
//......
//bitn = (A.n + B.n) == 2 ? 1 : 0
//result = bit0 + bit1*2^1 + bit2*2^2 + bitn*2^n
//opt:=>
//sum_bit0 = (A.O + B.O) == 2 ? 2^0 : 0
//sum_bit1 = (A.1 + B.1) == 2 ? 2^1 : 0
//......
//sum_bitn = (A.n + B.n) == 2 ? 2^n : 0
//result = sum_bit0 + sum_bit1 + ... + sum_bitn

void R1P_BITWISE_AND_Gadget::generateConstraints()
{
    alphaDualVariablePacker1_->generateConstraints();
    alphaDualVariablePacker2_->generateConstraints();
    for (auto i = 0; i < BIT_SIZE; i++)
        andGadget_[i]->generateConstraints();
    alphaDualVariablePacker3_->generateConstraints();
}

void R1P_BITWISE_AND_Gadget::generateWitness()
{
    alphaDualVariablePacker1_->generateWitness();
    alphaDualVariablePacker2_->generateWitness();
    for (auto i = 0; i < BIT_SIZE; i++)
        andGadget_[i]->generateWitness();
    alphaDualVariablePacker3_->generateWitness();


    printf("!!! %ld = %ld & %ld\n", val(result_).asLong(), val(A_).asLong(), val(B_).asLong());
}
/*********************************/
/*** END OF R1P_BITWISE_AND_Gadget ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_TRUNC_Gadget                    ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
TRUNC_GadgetBase::~TRUNC_GadgetBase() {}

R1P_TRUNC_Gadget::R1P_TRUNC_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const size_t &srcSize,
                               const size_t &dstSize,
                               const Variable& result)
    : Gadget(pb), TRUNC_GadgetBase(pb), srcSize_(srcSize), dstSize_(dstSize),R1P_Gadget(pb), A_(A), result_(result),
    A_alpha_u_(BIT_SIZE,  "A_alpha"), sym_(BIT_SIZE, ""){}

void R1P_TRUNC_Gadget::init()
{
    GADGETLIB_ASSERT(srcSize_ <= BIT_SIZE , "Attempted to create gadget srcSize > BIT_SIZE.");
    GADGETLIB_ASSERT(dstSize_ <= BIT_SIZE , "Attempted to create gadget dstSize > BIT_SIZE.");
    alphaDualVariablePacker1_ = Packing_Gadget::create(pb_, A_alpha_u_, A_, false);
    alphaDualVariablePacker2_ = Packing_Gadget::create(pb_, sym_, result_, true);
}

//sym[0] = A[0]
//sym[1] = A[1]
//......
//sym[dstSize-1] = A[dstSize-1]
//sym[dstSize] = 0
//......
//sym[srcSize-1] = 0
/*
Constraint breakdown:
A_alpha_u_ = A.unpacked
sym_[i] = A_alpha_u_[i] (i < dstSize)
result = syms_.packed
*/

void R1P_TRUNC_Gadget::generateConstraints()
{
    alphaDualVariablePacker1_->generateConstraints();
    for (int i=0; i < dstSize_; i++)
        addRank1Constraint(sym_[i] , 1, A_alpha_u_[i], "sym_[i] * 1 = A_alpha_u_[i]");
    alphaDualVariablePacker2_->generateConstraints();
}

void R1P_TRUNC_Gadget::generateWitness()
{
    alphaDualVariablePacker1_->generateWitness();
    for (int i = 0; i < dstSize_; i++) {
        val(sym_[i]) = val(A_alpha_u_[i]).asLong();
    }
    alphaDualVariablePacker2_->generateWitness();
    printf("!!! %ld = trunc %ld %ld %ld\n", val(result_).asLong(), val(A_).asLong(), srcSize_, dstSize_);
}
/*********************************/
/***    END OF R1P_TRUNC_Gadget  ***/
/*********************************/



/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_ZEXT_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
ZEXT_GadgetBase::~ZEXT_GadgetBase() {}

R1P_ZEXT_Gadget::R1P_ZEXT_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const size_t &srcSize,
                               const size_t &dstSize,
                               const Variable& result)
    : Gadget(pb), ZEXT_GadgetBase(pb), srcSize_(srcSize), dstSize_(dstSize), R1P_Gadget(pb), A_(A), result_(result),
     A_alpha_u_(BIT_SIZE,  "A_alpha"),sym_(BIT_SIZE, ""){}

void R1P_ZEXT_Gadget::init()
{
    GADGETLIB_ASSERT(srcSize_ <= BIT_SIZE , "Attempted to create gadget srcSize > BIT_SIZE.");
    GADGETLIB_ASSERT(dstSize_ <= BIT_SIZE , "Attempted to create gadget dstSize > BIT_SIZE.");
    alphaDualVariablePacker1_ = Packing_Gadget::create(pb_, A_alpha_u_, A_, false);
    alphaDualVariablePacker2_ = Packing_Gadget::create(pb_, sym_, result_, true);
}

//sym[0] = A[0]
//sym[1] = A[1]
//......
//sym[srcSize-1] = A[srcSize-1]
//sym[srcSize] = 0
//......
//sym[dstSize-1] = 0

/*
Constraint breakdown:
result = sum(sym[i])
*/
void R1P_ZEXT_Gadget::generateConstraints()
{
    alphaDualVariablePacker1_->generateConstraints();
    for (int i=0; i < srcSize_; i++)
        addRank1Constraint(sym_[i] , 1, A_alpha_u_[i], "sym_[i] * 1 = A_alpha_u_[i]");
    alphaDualVariablePacker2_->generateConstraints();
}

void R1P_ZEXT_Gadget::generateWitness()
{
    alphaDualVariablePacker1_->generateWitness();
    for (int i = 0; i < srcSize_; i++) {
        val(sym_[i]) = val(A_alpha_u_[i]).asLong();
    }
    alphaDualVariablePacker2_->generateWitness();
    printf("!!! %ld = zext %ld %ld %ld\n", val(result_).asLong(), val(A_).asLong(), srcSize_, dstSize_);
}
/*********************************/
/***    END OF R1P_ZEXT_Gadget  ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_SEXT_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
SEXT_GadgetBase::~SEXT_GadgetBase() {}

R1P_SEXT_Gadget::R1P_SEXT_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const size_t &srcSize,
                               const size_t &dstSize,
                               const Variable& result)
    : Gadget(pb), SEXT_GadgetBase(pb), srcSize_(srcSize), dstSize_(dstSize), R1P_Gadget(pb), A_(A), result_(result),
    A_alpha_u_(BIT_SIZE,  "A_alpha"), sym_(BIT_SIZE, ""){}

void R1P_SEXT_Gadget::init()
{
    GADGETLIB_ASSERT(srcSize_ <= BIT_SIZE , "Attempted to create gadget srcSize > BIT_SIZE.");
    GADGETLIB_ASSERT(dstSize_ <= BIT_SIZE , "Attempted to create gadget dstSize > BIT_SIZE.");
    alphaDualVariablePacker1_ = Packing_Gadget::create(pb_, A_alpha_u_, A_, false);
    alphaDualVariablePacker2_ = Packing_Gadget::create(pb_, sym_, result_, true);
}

/*
Constraint breakdown:
A_alpha_u_ = A.unpacked
sym_[i] = A_alpha_u_[i] (i < srcSize)
sym_[i] = A_alpha_u_[srcSize-1]  (i >= srcSize)
result = syms_.packed
*/
void R1P_SEXT_Gadget::generateConstraints()
{
    alphaDualVariablePacker1_->generateConstraints();
    for (int i = 0; i < srcSize_ ; i++)
        addRank1Constraint(sym_[i] - A_alpha_u_[i], 1, 0, "(sym[i] - A[i]) * 1 = 0");
    for (int i = srcSize_; i < dstSize_; i++)
        addRank1Constraint(sym_[i] - A_alpha_u_[srcSize_-1], 1, 0, "(sym[i] - A[srcSize_-1]) * 1 = 0");
    alphaDualVariablePacker2_->generateConstraints();
}

void R1P_SEXT_Gadget::generateWitness()
{
    alphaDualVariablePacker1_->generateWitness();
    for (int i = 0; i < srcSize_ ; i++)
          val(sym_[i]) = val(A_alpha_u_[i]);
    for (int i = srcSize_; i < dstSize_ ; i++)
          val(sym_[i]) = val(A_alpha_u_[srcSize_ - 1]);
    alphaDualVariablePacker2_->generateWitness();
    printf("!!! %ld = SExt %ld %ld %ld\n", val(result_).asLong(), val(A_).asLong(), srcSize_, dstSize_);
}
/*********************************/
/***   END OF R1P_SEXT_Gadget  ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_EQ_Gadget                       ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
EQ_GadgetBase::~EQ_GadgetBase() {}

R1P_EQ_Gadget::R1P_EQ_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result)
: Gadget(pb), EQ_GadgetBase(pb), R1P_Gadget(pb), A_(A), B_(B), result_(result), aux_(){}

void R1P_EQ_Gadget::init()
{

}

/*
    Constraint breakdown:

    (1) (A - B) * result = 0
    (2) (A - B) * aux = 1 - result

    [ A == B ] ==> [result == 1]    (aux can any value)
    [ A != B ] ==> [result == 0]    (aux == inverse(A - B))
*/
void R1P_EQ_Gadget::generateConstraints()
{
    addRank1Constraint(A_ - B_, result_, 0, "(A - B) * result = 0");
    addRank1Constraint(A_ - B_, aux_, 1 - result_, "(A - B) * aux = 1 - result");
}

void R1P_EQ_Gadget::generateWitness()
{
    if (val(A_) == val(B_))
        val(aux_) = 0;
    else
        val(aux_) = (val(A_) - val(B_)).inverse(R1P);
    val(result_) = (val(A_) == val(B_) ? 1 : 0) ;
    printf("!!! %ld = %ld == %ld\n", val(result_).asLong(), val(A_).asLong(), val(B_).asLong());
}
/*********************************/
/***    END OF R1P_EQ_Gadget   ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        R1P_NEQ_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
NEQ_GadgetBase::~NEQ_GadgetBase() {}

R1P_NEQ_Gadget::R1P_NEQ_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result)
: Gadget(pb), NEQ_GadgetBase(pb), R1P_Gadget(pb), A_(A), B_(B), result_(result), aux_(){}

void R1P_NEQ_Gadget::init()
{

}

/*
    Constraint breakdown:

    (1) (A - B) * aux = result

    [ A != B ] ==> [result == 1]    (aux can any value)
    [ A == B ] ==> [result == 0]    (aux == inverse(A - B))
*/
void R1P_NEQ_Gadget::generateConstraints()
{
    addRank1Constraint(A_ - B_, aux_, result_, "(A - B) * aux = result");
    addRank1Constraint(A_ - B_, 1 - result_, 0, "(A - B) * (1 - result) = 0");
}

void R1P_NEQ_Gadget::generateWitness()
{
    if (val(A_) == val(B_))
        val(aux_) = 0;
    else
        val(aux_) = (val(A_) - val(B_)).inverse(R1P);
    val(result_) = (val(A_) != val(B_) ? 1 : 0) ;
    printf("!!! %ld = %ld != %ld\n", val(result_).asLong(), val(A_).asLong(), val(B_).asLong());
}
/*********************************/
/***   END OF R1P_NEQ_Gadget   ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                         SGT_Gadget                         ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

SGT_Gadget::SGT_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result)
: Gadget(pb), A_(A), B_(B), result_(result) {}

void SGT_Gadget::init()
{
	getbitGadget = GETBIT_Gadget::create(pb_, C_, BIT_SIZE-1, result_);
}

GadgetPtr SGT_Gadget::create(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result){
    GadgetPtr pGadget(new SGT_Gadget(pb, A, B, result));
    pGadget->init();
    return pGadget;
}

void SGT_Gadget::generateConstraints()
{    
    addRank1Constraint(1, B_ - A_, C_, "B_ - A_ = C_");
    getbitGadget->generateConstraints();
}

void SGT_Gadget::generateWitness()
{
    val(C_) = val(B_) - val(A_);
    getbitGadget->generateWitness();

    printf("!!! %ld = %ld > %ld\n", val(result_).asLong(), val(A_).asLong(), val(B_).asLong());
}
/*********************************/
/***    END OF SGT_Gadget      ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                          SGE_Gadget                        ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

SGE_Gadget::SGE_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result)
: Gadget(pb), A_(A), B_(B), result_(result) {}

void SGE_Gadget::init()
{
    sgtGadget_ = SGT_Gadget::create(pb_, A_, B_, great_);
    eqGadget_ =  EQ_Gadget::create(pb_, A_, B_, eq_);
}

GadgetPtr SGE_Gadget::create(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result){
    GadgetPtr pGadget(new SGE_Gadget(pb, A, B, result));
    pGadget->init();
    return pGadget;
}

void SGE_Gadget::generateConstraints()
{
    sgtGadget_->generateConstraints();
    eqGadget_->generateConstraints();

    addRank1Constraint(great_ + eq_, 1, result_, "great_ + eq__ = result");
}

void SGE_Gadget::generateWitness()
{
    sgtGadget_->generateWitness();
    eqGadget_->generateWitness();

    val(result_)  = val(great_) + val(eq_);
    printf("!!! %ld = %ld >= %ld\n", val(result_).asLong(), val(A_).asLong(), val(B_).asLong());
}
/*********************************/
/***   END OF R1P_GE_Gadget    ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                         UGT_Gadget                         ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

UGT_Gadget::UGT_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result)
: Gadget(pb), A_(A), B_(B), result_(result) {}

void UGT_Gadget::init()
{
	A_SIGN_GADGET = GETBIT_Gadget::create(pb_, A_, BIT_SIZE-1, A_sign);
	B_SIGN_GADGET = GETBIT_Gadget::create(pb_, B_, BIT_SIZE-1, B_sign);
	C_SIGN_GADGET = GETBIT_Gadget::create(pb_, C_, BIT_SIZE-1, C_sign);

  EQ_GADGET = EQ_Gadget::create(pb_, A_sign, B_sign, sign_eq);
  
  Select_GADGET = Select_Gadget::create(pb_, sign_eq, C_sign, A_sign, result_);
}

GadgetPtr UGT_Gadget::create(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result){
    GadgetPtr pGadget(new UGT_Gadget(pb, A, B, result));
    pGadget->init();
    return pGadget;
}

void UGT_Gadget::generateConstraints()
{    
    addRank1Constraint(1, B_ - A_, C_, "B_ - A_ = C_");
    A_SIGN_GADGET->generateConstraints();
    B_SIGN_GADGET->generateConstraints();
    C_SIGN_GADGET->generateConstraints();
    EQ_GADGET->generateConstraints();
    Select_GADGET->generateConstraints();
}

void UGT_Gadget::generateWitness()
{
    val(C_) = val(B_) - val(A_);
    A_SIGN_GADGET->generateWitness();
    B_SIGN_GADGET->generateWitness();
    C_SIGN_GADGET->generateWitness();
    EQ_GADGET->generateWitness();
    Select_GADGET->generateWitness();

    printf("!!! %lu = %lu > %lu\n", val(result_).asLong(), val(A_).asLong(), val(B_).asLong());
}
/*********************************/
/***    END OF UGT_Gadget      ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                          UGE_Gadget                        ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

UGE_Gadget::UGE_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result)
: Gadget(pb), A_(A), B_(B), result_(result) {}

void UGE_Gadget::init()
{
    ugtGadget_ = SGT_Gadget::create(pb_, A_, B_, great_);
    eqGadget_ =  EQ_Gadget::create(pb_, A_, B_, eq_);
}

GadgetPtr UGE_Gadget::create(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& result){
    GadgetPtr pGadget(new UGE_Gadget(pb, A, B, result));
    pGadget->init();
    return pGadget;
}

void UGE_Gadget::generateConstraints()
{
    ugtGadget_->generateConstraints();
    eqGadget_->generateConstraints();

    addRank1Constraint(great_ + eq_, 1, result_, "great_ + eq__ = result");
}

void UGE_Gadget::generateWitness()
{
    ugtGadget_->generateWitness();
    eqGadget_->generateWitness();

    val(result_)  = val(great_) + val(eq_);
    printf("!!! %lu = %lu >= %lu\n", val(result_).asLong(), val(A_).asLong(), val(B_).asLong());
}
/*********************************/
/***   END OF R1P_GE_Gadget    ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      R1P_Select_Gadget                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

/*
    Constraint breakdown:

    (1) result = (1 - toggle) * zeroValue + toggle * oneValue
        (rank 1 format) ==> toggle * (oneValue - zeroValue) = result - zeroValue

*/

Select_Gadget::Select_Gadget(ProtoboardPtr pb,
                             const FlagVariable& toggle,
                             const LinearCombination& oneValue,
                             const LinearCombination& zeroValue,
                             const Variable& result)
        : Gadget(pb), toggle_(toggle), zeroValue_(zeroValue), oneValue_(oneValue),
          result_(result) {}

GadgetPtr Select_Gadget::create(ProtoboardPtr pb,
                                const FlagVariable& toggle,
                                const LinearCombination& oneValue,
                                const LinearCombination& zeroValue,
                                const Variable& result) {
    GadgetPtr pGadget(new Select_Gadget(pb, toggle, oneValue, zeroValue, result));
    pGadget->init();
    return pGadget;
}

void Select_Gadget::generateConstraints() {
    addRank1Constraint(toggle_, oneValue_ - zeroValue_, result_ - zeroValue_,
                            "result = (1 - toggle) * zeroValue + toggle * oneValue");
}

void Select_Gadget::generateWitness() {
    if (val(toggle_) == 0) {
        val(result_) = val(zeroValue_);
    } else if (val(toggle_) == 1) {
        val(result_) = val(oneValue_);
    } else {
        GADGETLIB_FATAL("Toggle value must be Boolean.");
    }

    printf("!!! %ld = %ld ? %ld : %ld\n", val(result_).asLong(), val(toggle_).asLong(), val(oneValue_).asLong(), val(zeroValue_).asLong());
}


/*********************************/
/***  END OF R1P_Select_Gadget ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                     Packing Gadgets                        ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

Packing_Gadget::Packing_Gadget(ProtoboardPtr pb,
                               const VariableArray& unpacked,
                               const Variable& packed,
                               bool ispacking)
    : Gadget(pb), unpacked_(unpacked), packed_(packed), ispacking(ispacking) {
    GADGETLIB_ASSERT(unpacked.size() > 0, "Attempted to pack 0 bits in R1P.")
}

GadgetPtr Packing_Gadget::create(ProtoboardPtr pb,
                       const VariableArray& unpacked,
                       const Variable& packed,
                       bool ispacking) {
    GadgetPtr pGadget(new Packing_Gadget(pb, unpacked, packed, ispacking));
    pGadget->init();
    return pGadget;
}


void Packing_Gadget::generateConstraints() {
    const int n = unpacked_.size();
    LinearCombination packed;
    FElem two_i(1); // Will hold 2^i
    
    for (int i = 0; i < n; ++i) {
        packed += unpacked_[i]*two_i;
        two_i += two_i;
        if (!ispacking) {enforceBooleanity(unpacked_[i]);}
    }
    addRank1Constraint(packed_, 1, packed, "packed = sum(2^i * unpacked[i])");
    
}

void Packing_Gadget::generateWitness() {
    const int n = unpacked_.size();
    if (ispacking) {
        FElem packedVal = 0;
        FElem two_i(1); // will hold 2^i
        for(int i = 0; i < n; ++i) {
            GADGETLIB_ASSERT(val(unpacked_[i]).asLong() == 0 || val(unpacked_[i]).asLong() == 1,
                         GADGETLIB2_FMT("unpacked[%u]  = %u. Expected a Boolean value.", i,
                             val(unpacked_[i]).asLong()));
            packedVal += two_i * val(unpacked_[i]).asLong();
            two_i += two_i;
        }
        val(packed_) = packedVal;
    } else {
        for(int i = 0; i < n; ++i) {
            val(unpacked_[i]) = (val(packed_).asLong() >> i) & 1;
        }
    }
}

/*****************************************/
/***      End of Packing Gadgets       ***/
/*****************************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      GETBIT_Gadget                         ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

GETBIT_Gadget::GETBIT_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const unsigned i,
                               const Variable& result)
: Gadget(pb), A_(A), i(i), result_(result), A_alpha_u_(BIT_SIZE,  "A_alpha"){}

void GETBIT_Gadget::init(){
    alphaDualVariablePacker1_ = Packing_Gadget::create(pb_, A_alpha_u_, A_, false);
}

GadgetPtr GETBIT_Gadget::create(ProtoboardPtr pb,
                               const Variable& A,
                               const unsigned i,
                               const Variable& result){
    GadgetPtr pGadget(new GETBIT_Gadget(pb, A, i, result));
    pGadget->init();
    return pGadget;
}

void GETBIT_Gadget::generateConstraints()
{
  alphaDualVariablePacker1_->generateConstraints();

  addRank1Constraint(A_alpha_u_[i] , 1, result_, "result_ = A_alpha_u_[i]");
}

void GETBIT_Gadget::generateWitness()
{
  alphaDualVariablePacker1_->generateWitness();
  val(result_) = val(A_alpha_u_[i]);
  
//  printf("!!! %ld = %ld[%u]\n", val(result_).asLong(), val(A_).asLong(), i);
}

/*********************************/
/***   END OF GETBIT_Gadget    ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      UDivision_Gadget                      ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

UDivision_Gadget::UDivision_Gadget(ProtoboardPtr pb,
                               const Variable& A,
                               const Variable& B,
                               const Variable& Q,
                               const Variable& R)
    : Gadget(pb), A_(A), B_(B), Q_(Q), R_(R) {}

void UDivision_Gadget::init()
{
    comparsionGadget_ = UGT_Gadget::create(pb_, B_, R_, less_);
}

GadgetPtr UDivision_Gadget::create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& Q,
                            const Variable& R){
    GadgetPtr pGadget(new UDivision_Gadget(pb, A, B, Q, R));
    pGadget->init();
    return pGadget;
}


void UDivision_Gadget::generateConstraints()
{
 //   addRank1Constraint(B_, Q_, A_-R_, "B * Q = A - R");
    comparsionGadget_->generateConstraints();

    addRank1Constraint(less_ , 1, 1, "less = 1");
}

void UDivision_Gadget::generateWitness()
{
  if(val(B_)==0){
    val(R_) = val(A_);
    val(Q_) = 0;
  }else{
    val(Q_) = (unsigned long)(val(A_).asLong()) / (unsigned long)(val(B_).asLong());
    val(R_) = (unsigned long)(val(A_).asLong()) % (unsigned long)(val(B_).asLong());


//    printf("@@@ A_ - R_ = %ld\n", val(A_).asLong() - val(R_).asLong());
//    printf("@@@ B_ * Q_ = %ld\n", val(B_).asLong() * val(Q_).asLong());


    comparsionGadget_->generateWitness();

    //printf("!!! %ld = %ld / %ld\n", val(result_).asLong(), val(A_).asLong(), val(B_).asLong());
  }
}
/*********************************/
/***  END OF UDivision_Gadget  ***/
/*********************************/




} // namespace gadgetlib2
