/** @file
 *****************************************************************************
 *****************************************************************************
 * @author     chegvra.
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_VCGADGET_HPP_
#define LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_VCGADGET_HPP_

#include <vector>

#include <libsnark/gadgetlib2/gadgetMacros.hpp>
#include <libsnark/gadgetlib2/protoboard.hpp>
#include <libsnark/gadgetlib2/variable.hpp>
#include <libsnark/gadgetlib2/gadget.hpp>


#define WORD_BIT_SIZE  (sizeof(long) * 8)


namespace gadgetlib2
{
/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                         class VCGadget                       ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
CREATE_GADGET_BASE_CLASS(ADD_GadgetBase);
class R1P_ADD_Gadget : public ADD_GadgetBase, public R1P_Gadget
{
  private:
    R1P_ADD_Gadget(ProtoboardPtr pb, const Variable& A, const Variable& B,
                   const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

    friend class ADD_Gadget;

  private:
    //external variables
    const Variable lhs_;
    const Variable rhs_;
    const Variable result_;
    DISALLOW_COPY_AND_ASSIGN(R1P_ADD_Gadget);
};
CREATE_GADGET_FACTORY_CLASS_3(ADD_Gadget,
                              Variable, A,
                              Variable, B,
                              Variable, result);


CREATE_GADGET_BASE_CLASS(SUB_GadgetBase);
class R1P_SUB_Gadget : public SUB_GadgetBase, public R1P_Gadget
{
  private:
    R1P_SUB_Gadget(ProtoboardPtr pb, const Variable& A, const Variable& B,
                   const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

    friend class SUB_Gadget;

  private:
    //external variables
    const Variable lhs_;
    const Variable rhs_;
    const Variable result_;
    DISALLOW_COPY_AND_ASSIGN(R1P_SUB_Gadget);
};
CREATE_GADGET_FACTORY_CLASS_3(SUB_Gadget,
                              Variable, A,
                              Variable, B,
                              Variable, result);



CREATE_GADGET_BASE_CLASS(NOT_GadgetBase);
class R1P_NOT_Gadget : public NOT_GadgetBase, public R1P_Gadget
{
  private:
    R1P_NOT_Gadget(ProtoboardPtr pb, const Variable& A,
                   const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& result);

    friend class NOT_Gadget;

  private:
    //external variables
    const Variable input_;
    const Variable inputInverse_;
    const Variable temp1_;
    const Variable result_;
    DISALLOW_COPY_AND_ASSIGN(R1P_NOT_Gadget);
};
CREATE_GADGET_FACTORY_CLASS_2(NOT_Gadget,
                              Variable, input,
                              Variable, result);


CREATE_GADGET_BASE_CLASS(MUL_GadgetBase);

class R1P_MUL_Gadget : public MUL_GadgetBase, public R1P_Gadget
{
  private:
    R1P_MUL_Gadget(ProtoboardPtr pb, const Variable& A,
                            const Variable& B,
                            const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

    friend class MUL_Gadget;

  private:
    //external variables
    const Variable A_;
    const Variable B_;
    const Variable result_;
    DISALLOW_COPY_AND_ASSIGN(R1P_MUL_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(MUL_Gadget, // TODO uncomment this
                              Variable, A,
                              Variable, B,
                              Variable, result);



// TODO create unit test
CREATE_GADGET_BASE_CLASS(MIN_GadgetBase);

class R1P_MIN_Gadget : public MIN_GadgetBase, public R1P_Gadget
{
  private:
    R1P_MIN_Gadget(ProtoboardPtr pb, const size_t &wordBitSize,
               const PackedWord &lhs,
               const PackedWord &rhs, const Variable &result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const size_t &wordBitSize,
                            const PackedWord &lhs,
                            const PackedWord &rhs,
                            const Variable &result);

    friend class MIN_Gadget;

  private:
    //external variables
    const size_t wordBitSize_;
    const PackedWord lhs_;
    const PackedWord rhs_;
    const FlagVariable less_;
    const FlagVariable lessOrEqual_;

    const PackedWord sym_1_;
    const PackedWord sym_2_;
    Variable result_;

    GadgetPtr comparsionGadget_;


    DISALLOW_COPY_AND_ASSIGN(R1P_MIN_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_4(MIN_Gadget, // TODO uncomment this
                              size_t, wordBitSize,
                              PackedWord, lhs,
                              PackedWord, rhs,
                              Variable, result);

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                    SREM_Gadget classes                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

// TODO create unit test
CREATE_GADGET_BASE_CLASS(SREM_GadgetBase);

class R1P_SREM_Gadget : public SREM_GadgetBase, public R1P_Gadget
{
  private:
    R1P_SREM_Gadget(ProtoboardPtr pb, const Variable& A,
                            const Variable& B,
                            const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

    friend class SREM_Gadget;

  private:

    //external variables
    const Variable A_;
    const Variable B_;
    const Variable C_;

    const Variable result_;

    GadgetPtr comparsionGadget1_;
    GadgetPtr comparsionGadget2_;

    DISALLOW_COPY_AND_ASSIGN(R1P_SREM_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(SREM_Gadget, // TODO uncomment this
                            Variable, A,
                            Variable, B,
                            Variable, result);
/*********************************/
/***     END OF SREM_Gadget    ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                     SDIV_Gadget classes                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
// TODO create unit test
CREATE_GADGET_BASE_CLASS(SDIV_GadgetBase);

class R1P_SDIV_Gadget : public SDIV_GadgetBase, public R1P_Gadget
{
  private:
    R1P_SDIV_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const Variable& B,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

    friend class SDIV_Gadget;

  private:
    const Variable A_;
    const Variable B_;
    const Variable C_;

    const Variable result_;

    GadgetPtr comparsionGadget1_;
    GadgetPtr comparsionGadget2_;

    DISALLOW_COPY_AND_ASSIGN(R1P_SDIV_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(SDIV_Gadget, // TODO uncomment this
                            Variable, A,
                            Variable, B,
                            Variable, result);
/*********************************/
/***      END OF SDIV_Gadget   ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                    UREM_Gadget classes                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

// TODO create unit test
CREATE_GADGET_BASE_CLASS(UREM_GadgetBase);

class R1P_UREM_Gadget : public UREM_GadgetBase, public R1P_Gadget
{
  private:
    R1P_UREM_Gadget(ProtoboardPtr pb, const Variable& A,
                            const Variable& B,
                            const Variable& R);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& R);

    friend class UREM_Gadget;

  private:

    //external variables
    const Variable A_;
    const Variable B_;
    const Variable Q_;
    const Variable R_;

    GadgetPtr udivision_Gadget;

    DISALLOW_COPY_AND_ASSIGN(R1P_UREM_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(UREM_Gadget, // TODO uncomment this
                            Variable, A,
                            Variable, B,
                            Variable, result);
/*********************************/
/***      END OF UREM_Gadget   ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                    UDIV_Gadget classes                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
// TODO create unit test
CREATE_GADGET_BASE_CLASS(UDIV_GadgetBase);

class R1P_UDIV_Gadget : public UDIV_GadgetBase, public R1P_Gadget
{
  private:
    R1P_UDIV_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const Variable& B,
                  const Variable& Q);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& Q);

    friend class UDIV_Gadget;

  private:
    const Variable A_;
    const Variable B_;
    const Variable Q_;
    const Variable R_;

    GadgetPtr udivision_Gadget;

    DISALLOW_COPY_AND_ASSIGN(R1P_UDIV_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(UDIV_Gadget, // TODO uncomment this
                            Variable, A,
                            Variable, B,
                            Variable, Q);
/*********************************/
/***      END OF UDIV_Gadget   ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                  BITWISE_OR_Gadget classes                 ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
// TODO create unit test
CREATE_GADGET_BASE_CLASS(BITWISE_OR_GadgetBase);

class R1P_BITWISE_OR_Gadget : public BITWISE_OR_GadgetBase, public R1P_Gadget
{
  private:
    R1P_BITWISE_OR_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const Variable& B,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

    friend class BITWISE_OR_Gadget;

  private:
    //external variables
    static const int BIT_SIZE = WORD_BIT_SIZE;
    const Variable A_;
    const Variable B_;
    const Variable result_;
    UnpackedWord A_alpha_u_;
    UnpackedWord B_alpha_u_;
    UnpackedWord sym_;
    GadgetPtr alphaDualVariablePacker1_;
    GadgetPtr alphaDualVariablePacker2_;
    GadgetPtr alphaDualVariablePacker3_;
    GadgetPtr orGadget_[BIT_SIZE];

    DISALLOW_COPY_AND_ASSIGN(R1P_BITWISE_OR_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(BITWISE_OR_Gadget, // TODO uncomment this
                            Variable, A,
                            Variable, B,
                            Variable, result);
/*********************************/
/***  END OF BITWISE_OR_Gadget ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                  BITWISE_XOR_Gadget classes                 ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
// TODO create unit test
CREATE_GADGET_BASE_CLASS(BITWISE_XOR_GadgetBase);

class R1P_BITWISE_XOR_Gadget : public BITWISE_XOR_GadgetBase, public R1P_Gadget
{
  private:
    R1P_BITWISE_XOR_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const Variable& B,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

    friend class BITWISE_XOR_Gadget;

  private:
    //external variables
    static const int BIT_SIZE = WORD_BIT_SIZE;
    const Variable A_;
    const Variable B_;
    const Variable result_;
    UnpackedWord A_alpha_u_;
    UnpackedWord B_alpha_u_;
    UnpackedWord sym_;
    GadgetPtr alphaDualVariablePacker1_;
    GadgetPtr alphaDualVariablePacker2_;
    GadgetPtr alphaDualVariablePacker3_;
    GadgetPtr neqGadget_[BIT_SIZE];

    DISALLOW_COPY_AND_ASSIGN(R1P_BITWISE_XOR_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(BITWISE_XOR_Gadget, // TODO uncomment this
                            Variable, A,
                            Variable, B,
                            Variable, result);
/*********************************/
/***  END OF BITWISE_XOR_Gadget ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                  BITWISE_AND_Gadget classes                 ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
// TODO create unit test
CREATE_GADGET_BASE_CLASS(BITWISE_AND_GadgetBase);

class R1P_BITWISE_AND_Gadget : public BITWISE_AND_GadgetBase, public R1P_Gadget
{
  private:
    R1P_BITWISE_AND_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const Variable& B,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

    friend class BITWISE_AND_Gadget;

  private:
    //external variables
    static const int BIT_SIZE = WORD_BIT_SIZE;
    const Variable A_;
    const Variable B_;
    const Variable result_;
    UnpackedWord A_alpha_u_;
    UnpackedWord B_alpha_u_;
    UnpackedWord sym_;
    GadgetPtr alphaDualVariablePacker1_;
    GadgetPtr alphaDualVariablePacker2_;
    GadgetPtr alphaDualVariablePacker3_;
    GadgetPtr andGadget_[BIT_SIZE];

    DISALLOW_COPY_AND_ASSIGN(R1P_BITWISE_AND_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(BITWISE_AND_Gadget, // TODO uncomment this
                            Variable, A,
                            Variable, B,
                            Variable, result);
/*********************************/
/***  END OF BITWISE_AND_Gadget ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                 TRUNC_Gadget classes                 ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
// TODO create unit test
CREATE_GADGET_BASE_CLASS(TRUNC_GadgetBase);

class R1P_TRUNC_Gadget : public TRUNC_GadgetBase, public R1P_Gadget
{
  private:
    R1P_TRUNC_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const size_t &srcSize,
		              const size_t &dstSize,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                          const Variable& A,
                          const size_t &srcSize,
		                      const size_t &dstSize,
                          const Variable& result);

    friend class TRUNC_Gadget;

  private:
    //external variables
    static const int BIT_SIZE = WORD_BIT_SIZE;
    const Variable A_;
    const Variable result_;
    UnpackedWord A_alpha_u_;
    UnpackedWord sym_;
    GadgetPtr alphaDualVariablePacker1_;
    GadgetPtr alphaDualVariablePacker2_;
    size_t srcSize_;
    size_t dstSize_;

    DISALLOW_COPY_AND_ASSIGN(R1P_TRUNC_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_4(TRUNC_Gadget, // TODO uncomment this
                            Variable, A,
                            size_t ,srcSize,
		                        size_t ,dstSize,
                            Variable, result);

/*********************************/
/***  END OF TRUNC_Gadget ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                 ZEXT_Gadget classes                 ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
// TODO create unit test
CREATE_GADGET_BASE_CLASS(ZEXT_GadgetBase);

class R1P_ZEXT_Gadget : public ZEXT_GadgetBase, public R1P_Gadget
{
  private:
    R1P_ZEXT_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const size_t &srcSize,
		              const size_t &dstSize,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const size_t &srcSize,
		                        const size_t &dstSize,
                            const Variable& result);

    friend class ZEXT_Gadget;

  private:
    //external variables
    static const int BIT_SIZE = WORD_BIT_SIZE;
    const Variable A_;
    const Variable result_;
    UnpackedWord A_alpha_u_;
    UnpackedWord sym_;
    GadgetPtr alphaDualVariablePacker1_;
    GadgetPtr alphaDualVariablePacker2_;
    size_t srcSize_;
    size_t dstSize_;

    DISALLOW_COPY_AND_ASSIGN(R1P_ZEXT_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_4(ZEXT_Gadget, // TODO uncomment this
                            Variable, A,
                            size_t ,srcSize,
                            size_t ,dstSize,
                            Variable, result);
/*********************************/
/***  END OF ZEXTGadget ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                 SEXT_Gadget classes                 ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
// TODO create unit test
CREATE_GADGET_BASE_CLASS(SEXT_GadgetBase);

class R1P_SEXT_Gadget : public SEXT_GadgetBase, public R1P_Gadget
{
  private:
    R1P_SEXT_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const size_t &srcSize,
		              const size_t &dstSize,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const size_t &srcSize,
		                        const size_t &dstSize,
                            const Variable& result);

    friend class SEXT_Gadget;

  private:
    //external variables
    static const int BIT_SIZE = WORD_BIT_SIZE;
    const Variable A_;
    const Variable result_;
    UnpackedWord A_alpha_u_;
    UnpackedWord sym_;
    GadgetPtr alphaDualVariablePacker1_;
    GadgetPtr alphaDualVariablePacker2_;
    size_t srcSize_;
    size_t dstSize_;

    DISALLOW_COPY_AND_ASSIGN(R1P_SEXT_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_4(SEXT_Gadget, // TODO uncomment this
                            Variable, A,
                            size_t ,srcSize,
                            size_t ,dstSize,
                            Variable, result);
/*********************************/
/***  END OF SEXT_Gadget ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      EQ_Gadget classes                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
// TODO create unit test
CREATE_GADGET_BASE_CLASS(EQ_GadgetBase);

class R1P_EQ_Gadget : public EQ_GadgetBase, public R1P_Gadget
{
  private:
    R1P_EQ_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const Variable& B,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

    friend class EQ_Gadget;

  private:
    //external variables
    const Variable A_;
    const Variable B_;
    const Variable result_;
    const Variable aux_;

    DISALLOW_COPY_AND_ASSIGN(R1P_EQ_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(EQ_Gadget, // TODO uncomment this
                            Variable, A,
                            Variable, B,
                            Variable, result);
/*********************************/
/***     END OF EQ_Gadget      ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      NEQ_Gadget classes                    ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/
// TODO create unit test
CREATE_GADGET_BASE_CLASS(NEQ_GadgetBase);

class R1P_NEQ_Gadget : public NEQ_GadgetBase, public R1P_Gadget
{
  private:
    R1P_NEQ_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const Variable& B,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

    friend class NEQ_Gadget;

  private:
    //external variables
    const Variable A_;
    const Variable B_;
    const Variable result_;
    const Variable aux_;

    DISALLOW_COPY_AND_ASSIGN(R1P_NEQ_Gadget);
};

CREATE_GADGET_FACTORY_CLASS_3(NEQ_Gadget, // TODO uncomment this
                            Variable, A,
                            Variable, B,
                            Variable, result);
/*********************************/
/***     END OF NEQ_Gadget     ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      SGT_Gadget classes                    ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

class SGT_Gadget : public Gadget
{
  private:
    SGT_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const Variable& B,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

  private:
    static const int BIT_SIZE = WORD_BIT_SIZE;
    //external variables
    const Variable A_;
    const Variable B_;
    const Variable result_;

    const Variable C_;

    GadgetPtr getbitGadget;
    
    DISALLOW_COPY_AND_ASSIGN(SGT_Gadget);
};

/*********************************/
/***     END OF SGT_Gadget     ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      SGE_Gadget classes                    ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

class SGE_Gadget : public Gadget
{
  private:
    SGE_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const Variable& B,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

  private:
    const Variable A_;
    const Variable B_;
    const Variable result_;

    const Variable great_;
    const Variable eq_;

    GadgetPtr sgtGadget_;
    GadgetPtr eqGadget_;

    DISALLOW_COPY_AND_ASSIGN(SGE_Gadget);
};

/*********************************/
/***     END OF SGE_Gadget      ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      UGT_Gadget classes                    ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

class UGT_Gadget : public Gadget
{
  private:
    UGT_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const Variable& B,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

  private:
    static const int BIT_SIZE = WORD_BIT_SIZE;
    //external variables
    const Variable A_;
    const Variable B_;
    const Variable result_;

    const Variable C_;
    const Variable A_sign;
    const Variable B_sign;
    const Variable C_sign;
    const Variable sign_eq;

    GadgetPtr getbitGadget;
    GadgetPtr A_SIGN_GADGET;
    GadgetPtr B_SIGN_GADGET;
    GadgetPtr C_SIGN_GADGET;
    GadgetPtr EQ_GADGET;
    GadgetPtr Select_GADGET;
    
    DISALLOW_COPY_AND_ASSIGN(UGT_Gadget);
};

/*********************************/
/***     END OF UGT_Gadget     ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                      UGE_Gadget classes                    ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

class UGE_Gadget : public Gadget
{
  private:
    UGE_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const Variable& B,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& result);

  private:
    const Variable A_;
    const Variable B_;
    const Variable result_;

    const Variable great_;
    const Variable eq_;

    GadgetPtr ugtGadget_;
    GadgetPtr eqGadget_;

    DISALLOW_COPY_AND_ASSIGN(UGE_Gadget);
};

/*********************************/
/***     END OF UGE_Gadget     ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                        Select_Gadget                       ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

//TODO add test

/// A gadget for the following semantics:
/// If toggle is 0, zeroValue --> result
/// If toggle is 1, oneValue --> result
/// Uses 1 constraint

class Select_Gadget : public Gadget {
private:
    FlagVariable toggle_;
    LinearCombination zeroValue_;
    LinearCombination oneValue_;
    Variable result_;

    Select_Gadget(ProtoboardPtr pb,
                  const FlagVariable& toggle,
                  const LinearCombination& oneValue,
                  const LinearCombination& zeroValue,
                  const Variable& result);

    virtual void init() {}
    DISALLOW_COPY_AND_ASSIGN(Select_Gadget);
public:
    static GadgetPtr create(ProtoboardPtr pb,
                            const FlagVariable& toggle,
                            const LinearCombination& oneValue,
                            const LinearCombination& zeroValue,
                            const Variable& result);

    void generateConstraints();
    void generateWitness();
};

/*********************************/
/***       END OF Gadget       ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                       Packing_Gadget                       ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

class Packing_Gadget : public Gadget {
private:
    VariableArray unpacked_;
    Variable packed_;
    bool ispacking;

    Packing_Gadget(ProtoboardPtr pb,
                   const VariableArray& unpacked,
                   const Variable& packed,
                   bool ispacking);

    virtual void init() {}
    DISALLOW_COPY_AND_ASSIGN(Packing_Gadget);
public:

    static GadgetPtr create(ProtoboardPtr pb,
                       const VariableArray& unpacked,
                       const Variable& packed,
                       bool ispacking);

    void generateConstraints();
    void generateWitness();
};

/*********************************/
/***       END OF Gadget       ***/
/*********************************/

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                     GETBIT_Gadget classes                  ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

class GETBIT_Gadget : public Gadget
{
  private:
    GETBIT_Gadget(ProtoboardPtr pb,
                  const Variable& A,
                  const unsigned i,
                  const Variable& result);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const unsigned i,
                            const Variable& result);

  private:

    static const int BIT_SIZE = WORD_BIT_SIZE;
    //external variables
    const Variable A_;
    const unsigned i;
    const Variable result_;
    UnpackedWord A_alpha_u_;

    GadgetPtr alphaDualVariablePacker1_;
    DISALLOW_COPY_AND_ASSIGN(GETBIT_Gadget);
};

/*********************************/
/***   END OF GETBIT_Gadget    ***/
/*********************************/


/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************               UDivision_Gadget classes                     ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

class UDivision_Gadget: public Gadget
{
  private:
    UDivision_Gadget(ProtoboardPtr pb, 
                            const Variable& A,
                            const Variable& B,
                            const Variable& Q,
                            const Variable& R);
    virtual void init();

  public:
    void generateConstraints();
    void generateWitness();
    static GadgetPtr create(ProtoboardPtr pb,
                            const Variable& A,
                            const Variable& B,
                            const Variable& Q,
                            const Variable& R);

  private:
    static const int BIT_SIZE = WORD_BIT_SIZE;

    const Variable A_;
    const Variable B_;
    const Variable Q_;
    const Variable R_;
    const Variable sign_;
    const Variable less_;

    GadgetPtr comparsionGadget1_;
    GadgetPtr comparsionGadget2_;

    DISALLOW_COPY_AND_ASSIGN(UDivision_Gadget);
};

/*********************************/
/***  END OF UDivision_Gadget  ***/
/*********************************/



/*********************************/
/***       END OF VCGadget      ***/
/*********************************/

} // namespace gadgetlib2

#endif // LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_VCGADGET_HPP_
