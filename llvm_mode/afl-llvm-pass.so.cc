/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

uint64_t id = 2;

namespace
{

  class AFLCoverage : public ModulePass
  {

  public:
    static char ID;
    AFLCoverage() : ModulePass(ID) {}

    bool runOnModule(Module &M) override;

    int getPointerType(const Value *ptrValue);

    void getAnalysisUsage(AnalysisUsage &AU) const override
    {
      AU.addRequired<LoopInfoWrapperPass>();
      AU.setPreservesAll();
    }

    bool isPointerPointer(Value *val);
    Value *getGepOriginalPtr(Instruction *);

    void insertAflCompare(IRBuilder<> &IRB, Value *curId,
                          Value *arraySize, Value *index, LLVMContext &C, Module &M, Function *compareFunc);

    // StringRef getPassName() const override {
    //  return "American Fuzzy Lop Instrumentation";
    // }
  };

}

char AFLCoverage::ID = 0;

int AFLCoverage::getPointerType(const Value *ptrValue)
{
  // 获取指针指向元素的类型
  Type *elementType = ptrValue->getType()->getPointerElementType();
  if (elementType->isIntegerTy(32))
    return 4;
  if (elementType->isIntegerTy(64))
    return 8;
  if (elementType->isIntegerTy(8))
    return 1;
  if (elementType->isIntegerTy(16))
    return 2;

  // 其他类型不处理
  return -1;
}

bool AFLCoverage::isPointerPointer(Value *val)
{
  PointerType *ptrType = dyn_cast<PointerType>(val->getType());
  // 如果操作数是指针的指针
  if (ptrType->getElementType()->isPointerTy())
    return true;
  return false;
}

Value *AFLCoverage::getGepOriginalPtr(Instruction *Inst)
{
  auto *gep = dyn_cast<GetElementPtrInst>(Inst);
  LoadInst *loadInst = dyn_cast<LoadInst>(gep->getOperand(0));

  if (!loadInst)
    return nullptr;

  return loadInst->getPointerOperand();
}

void AFLCoverage::insertAflCompare(IRBuilder<> &IRB, Value *curId,
                                   Value *arraySize, Value *index, LLVMContext &C, Module &M, Function *compareFunc)
{
  Value *compareFuncArgID = {curId};
  Value *compareFuncArgSize = {arraySize};
  Value *compareFuncArgIndex = {index};
  IRB.CreateCall(compareFunc, {compareFuncArgID,
                               compareFuncArgSize,
                               compareFuncArgIndex});
}

bool AFLCoverage::runOnModule(Module &M)
{

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET"))
  {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");
  }
  else
    be_quiet = 1;

  /* Decide instrumentation ratio */

  char *inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str)
  {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");
  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

  // GlobalVariable *GlobalGepIndexPtr =
  //     new GlobalVariable(M, PointerType::get(Int64Ty, 0), false,
  //                        GlobalValue::ExternalLinkage, 0, "__afl_gep_index_ptr");

  // GlobalVariable *GlobalGepSizePtr =
  //     new GlobalVariable(M, PointerType::get(Int64Ty, 0), false,
  //                        GlobalValue::ExternalLinkage, 0, "__afl_gep_size_ptr");

  DenseMap<Instruction *, uint64_t> ptrMapConst;
  DenseMap<Instruction *, Instruction *> ptrMapVar;

  FunctionType *compareFuncType = FunctionType::get(
      Type::getVoidTy(C),                                              // return type
      {Type::getInt64Ty(C), Type::getInt64Ty(C), Type::getInt64Ty(C)}, // argument types
      false                                                            // variadic function
  );
  Function *compareFunc = Function::Create(
      compareFuncType, GlobalValue::ExternalLinkage, "__afl_compare", &M);

  /* 扫描所有的全局变量 */

  for (auto &G : M.globals())
  {
    if (G.isDeclaration() || G.isThreadLocal() || G.isExternallyInitialized() || llvm::GlobalValue::isExternalLinkage(G.getLinkage()))
      continue;

    StringRef Name = G.getName();
    Type *Ty = G.getType();
    // errs() << "Global variable: " << Name << ", type: " << *Ty << "\n";

    PointerType *ptrType = dyn_cast<PointerType>(G.getType());
    // 如果操作数是指针的指针
    if (ptrType->getElementType()->isPointerTy())
    {
      Instruction *ptrInst = dyn_cast<Instruction>(&G);
      if (!ptrMapConst.count(ptrInst) && !ptrMapVar.count(ptrInst))
      {
        // 默认访存大小先设置成0
        ptrMapConst[ptrInst] = 0;
        ptrMapVar[ptrInst] = nullptr;
      }
    }
  }

  /* Our Instrument before afl's */

  int inst_afl_compare = 0;

  for (auto &F : M)
  {
    // 防止对外链的afl函数进行插桩
    if (F.getName().startswith("__afl"))
      continue;

    for (auto &BB : F)
    {
      for (auto &Inst : BB)
      {
        if (auto *allocate = dyn_cast<AllocaInst>(&Inst))
        {
          // 找到分配指针变量的
          if (allocate->getAllocatedType()->isPointerTy())
          {

            /*
               由于不知道给这个指针分配的内存大小是常量还是变量，
               因此两个map里面，先暂时都加一下
            */
            if (ptrMapConst.count(&Inst) > 0 || ptrMapVar.count(&Inst))
              continue;

            // 默认访存大小先设置成0
            ptrMapConst[&Inst] = 0;
            ptrMapVar[&Inst] = nullptr;
          }
        }

        // 处理通过指针赋值的情况
        else if (auto *loadInst = dyn_cast<LoadInst>(&Inst))
        {
          // 判断操作数是否为指针
          Value *loadPtr = loadInst->getPointerOperand();
          if (!loadPtr)
            continue;

          // 进一步判断load的操作数
          if (PointerType *ptrType = dyn_cast<PointerType>(loadPtr->getType()))
          {
            // 如果操作数是指针的指针
            if (ptrType->getElementType()->isPointerTy())
            {
              // 双重保证，找到接下来的指令，并且在load的user list里面
              // 其实不用保证也行
              Instruction *nextInst = loadInst->getNextNode();
              Instruction *nextnextInst = nextInst->getNextNode();
              StoreInst *storeInst = nullptr;

              if (auto *bitCastInst = dyn_cast<BitCastInst>(nextInst))
              {
                if (StoreInst *storeInstTemp = dyn_cast<StoreInst>(nextnextInst))
                  storeInst = storeInstTemp;
              }
              else if (StoreInst *storeInstTemp = dyn_cast<StoreInst>(nextInst))
              {
                storeInst = storeInstTemp;
              }

              if (storeInst)
              {
                // 获取store的目的指针地址
                Value *pointerValue = storeInst->getPointerOperand();
                Instruction *pointerValueInst = dyn_cast<Instruction>(pointerValue);

                // 并且store的目的地址是指针的指针类型
                if (isPointerPointer(pointerValue))
                {
                  errs() << "指针赋值！\n";

                  // 找到=号右边变量的map，看一下访存大小是变量还是常量
                  Instruction *oldPtrInst = dyn_cast<Instruction>(loadPtr);
                  bool isConst = false;
                  uint64_t size = 0;
                  Instruction *sizeValueInst = nullptr;

                  // 这个指针，前面一定allocte过，所以肯定在map中
                  if (ptrMapConst.count(oldPtrInst) && ptrMapConst[oldPtrInst] != 0)
                  {
                    isConst = true;
                    size = ptrMapConst[oldPtrInst];
                    errs() << "5555 " << size << "\n";
                  }
                  else if (ptrMapVar.count(oldPtrInst) && ptrMapVar[oldPtrInst] != nullptr)
                  {
                    sizeValueInst = ptrMapVar[oldPtrInst];
                  }

                  // 更新=号左边变量的访存大小
                  if (isConst)
                    // ptrMapConst[allocaInst] = size;
                    ptrMapConst[pointerValueInst] = size;
                  else
                    // ptrMapVar[allocaInst] = sizeValueInst;
                    ptrMapVar[pointerValueInst] = sizeValueInst;
                }
              }
            }
          }
        }

        else if (auto *callInst = dyn_cast<CallInst>(&Inst))
        {
          Function *function = callInst->getCalledFunction();

          if (!function)
            continue;

          // malloc 或者 new
          if ((function->getName() == "malloc") || (function->getName() == "_Znam"))
          {
            Value *sizeValue = callInst->getArgOperand(0);

            // 访存大小是常量
            if (ConstantInt *sizeConst = dyn_cast<ConstantInt>(sizeValue))
            {
              int size = sizeConst->getZExtValue();
              // 找下一条指令
              Instruction *nextInst = callInst->getNextNode();
              Instruction *nextNextInst = nextInst->getNextNode();
              // 找到store
              StoreInst *storeInst = nullptr;

              if (auto *bitCastInst = dyn_cast<BitCastInst>(nextInst))
              {
                if (StoreInst *storeInstTemp = dyn_cast<StoreInst>(nextNextInst))
                  storeInst = storeInstTemp;
              }
              else if (StoreInst *storeInstTemp = dyn_cast<StoreInst>(nextInst))
              {
                storeInst = storeInstTemp;
              }

              if (storeInst)
              {
                // 把malloc的入参存如store的第二个操作数
                Value *storedPointer = storeInst->getPointerOperand();
                if (auto *pointerValue = dyn_cast<Instruction>(storedPointer))
                {
                  if (pointerValue->getOpcode() == Instruction::Alloca)
                  {
                    // Found %4: store i32* %11, i32** %4, align 8
                    // 开辟二维数组...n维数组，这些情况都可以包含：
                    // store i32** %21, i32*** %7, align 8
                    Instruction *allocaInst = pointerValue;
                    errs() << "Const:" << *allocaInst << "  Size:  " << size << '\n';
                    if (ptrMapConst.count(allocaInst))
                    {
                      ptrMapConst[allocaInst] = size;
                      errs() << "store size: " << size << "\n";
                    }
                  }
                }
              }
            }
            // 访存大小是变量
            else if (Instruction *sizeVar = dyn_cast<Instruction>(sizeValue))
            {
              // 找下一条指令
              Instruction *nextInst = callInst->getNextNode();
              Instruction *nextNextInst = nextInst->getNextNode();
              // 找到store
              StoreInst *storeInst = nullptr;

              if (auto *bitCastInst = dyn_cast<BitCastInst>(nextInst))
              {
                if (StoreInst *storeInstTemp = dyn_cast<StoreInst>(nextNextInst))
                  storeInst = storeInstTemp;
              }
              else if (StoreInst *storeInstTemp = dyn_cast<StoreInst>(nextInst))
              {
                storeInst = storeInstTemp;
              }

              if (storeInst)
              {
                // 把malloc的入参存如store的第二个操作数
                Value *storedPointer = storeInst->getPointerOperand();
                if (auto *pointerValue = dyn_cast<Instruction>(storedPointer))
                {
                  if (pointerValue->getOpcode() == Instruction::Alloca)
                  {
                    // Found %4: store i32* %11, i32** %4, align 8
                    Instruction *allocaInst = pointerValue;
                    errs() << "Var:" << *allocaInst << "  Size:  " << *sizeVar << '\n';
                    if (ptrMapVar.count(allocaInst))
                    {
                      ptrMapVar[allocaInst] = sizeVar;
                    }
                  }
                }
              }
            }
          }
        }

        else if (auto *GEP = dyn_cast<GetElementPtrInst>(&Inst))
        {
          // errs() << "Find a GEP! number of operands:";
          // errs() << GEP->getNumOperands() << '\n';

          /* 栈数组和全局数组访问 */

          if (GEP->getSourceElementType()->isArrayTy())
          {
            // 例：%14 = getelementptr inbounds [20 x [10 x i32]], [20 x [10 x i32]]* %5, i64 0, i64 8
            // 这种都是有三个操作数的，其实不判断==3也可以，因为不可能有其他情况
            if (GEP->getNumOperands() == 3)
            {
              if (!dyn_cast<ConstantInt>(GEP->getOperand(2)))
              {
                // errs() << "Find a variable stack GEP! \n";

                IRBuilder<> IRB(&Inst);
                
                // if the source type is not array type, continue
                const Type *GepSourceType = GEP->getSourceElementType();
                if (!ArrayType::classof(GepSourceType))
                  continue;

                uint64_t array_size = GepSourceType->getArrayNumElements();
                ConstantInt *arraySize = ConstantInt::get(Int64Ty, array_size);

                uint64_t cur_id = id ++;
                ConstantInt *CurId = ConstantInt::get(Int64Ty, cur_id);
              
                /* call compare function */

                insertAflCompare(IRB, CurId,
                                 arraySize, GEP->getOperand(2), C, M, compareFunc);
                
                inst_afl_compare ++;

                errs() << "0000\n";
              }
            }
          }

          // 指针访问（包含堆变量）
          else if (GEP->getOperand(0)->getType()->isPointerTy())
          {
            // errs() << "指针访问！\n";
            // %27 = getelementptr inbounds i32, i32* %24, i64 %26
            // 如果是通过指针访问变量，那么%24这个位置的变量，应该是指针类型
            // %26这个位置的变量，应该是个变量
            // 像%31 = getelementptr inbounds i32, i32* %30, i64 5这种，就应该被剔除
            if (GEP->getNumOperands() == 2)
            {
              // 获取指针
              Value *ptrValue = GEP->getOperand(0);
              // 获取指针指向元素的类型
              Type *elementType = ptrValue->getType()->getPointerElementType();
              // 获取指针指向类型的大小
              int elementSize = getPointerType(ptrValue);
              // errs() << elementSize << '\n';

              // 获取gep的下一条指令
              Instruction *nextInst = GEP->getNextNode();

              // 如果下一条指令是store，并且store的第一个操作数是指针，第二个操作数是指针的指针，
              // 则是指针运算之后的赋值
              // %27 = load i32*, i32** %6, align 8
              // %28 = getelementptr inbounds i32, i32* %27, i64 200
              // store i32* %28, i32** %11, align 8
              StoreInst *storeInst = dyn_cast<StoreInst>(nextInst);
              PointerType *valPtrType = nullptr;
              PointerType *destPtrType = nullptr;
              if (storeInst)
              {
                valPtrType = dyn_cast<PointerType>(storeInst->getValueOperand()->getType());
                destPtrType = dyn_cast<PointerType>(storeInst->getPointerOperand()->getType());
              }

              // if (!valPtrType || !destPtrType) 
              //   continue;

              if (valPtrType && destPtrType && isPointerPointer(storeInst->getPointerOperand()))
              {
                // 获取200
                if (auto *offset = dyn_cast<ConstantInt>(GEP->getOperand(1)))
                {
                  // 获取到gep操作的原始的ptr
                  Value *originPtrValue = getGepOriginalPtr(&Inst);
                  if (!originPtrValue) 
                    continue;

                  Instruction *originPtr = dyn_cast<Instruction>(originPtrValue);

                  if (!originPtr)
                    continue;

                  // errs() << ptrMapConst.count(originPtr) << '\n';
                  // 去map里面获取指针对应的size，可能是常量，也可能是变量
                  if (ptrMapConst.count(originPtr) && ptrMapConst[originPtr])
                  {
                    uint64_t arrayByteSize = ptrMapConst[originPtr];
                    ConstantInt *arraySize = ConstantInt::get(Int64Ty, arrayByteSize / elementSize);
                    // 更新%11的访存大小
                    // 1. 首先获取到%11
                    Instruction *destPtr = dyn_cast<Instruction>(storeInst->getPointerOperand());
                    // 2. 更新map里对应的value
                    // 有没有可能这里减完小于0了，其实也可以加个判断
                    ptrMapConst[destPtr] = (arrayByteSize - elementSize * offset->getZExtValue());
                    // errs() << ptrMapConst[destPtr] << "xixi\n";
                  }
                  // 访存大小是变量的情况先跳过不处理
                  else
                    continue;
                }
              }

              // 否则，就是内存访问操作了，寻找访存偏移是变量的
              else if (!dyn_cast<ConstantInt>(GEP->getOperand(1)))
              {
                // errs() << "Find a variable heap GEP! \n";

                IRBuilder<> IRB(&Inst);

                // 正常的指针访问
                // int *ptr3 = (int *)malloc(40 * sizeof(int));
                // ptr3[i] = 6;
                // 对应IR：
                //   %10 = call noalias i8* @malloc(i64 160) #3
                //   %11 = bitcast i8* %10 to i32*
                //   store i32* %11, i32** %6, align 8
                //   %12 = load i32*, i32** %6, align 8
                //   %13 = load i32, i32* %3, align 4
                //   %14 = sext i32 %13 to i64
                //   %15 = getelementptr inbounds i32, i32* %12, i64 %14
                //   store i32 6, i32* %15, align 4
                if (auto *loadPtrInst = dyn_cast<LoadInst>(ptrValue))
                {
                  Value *ptrValue = loadPtrInst->getPointerOperand();
                  if (!ptrValue)
                    continue;

                  Instruction *ptrValueInst = dyn_cast<Instruction>(ptrValue);

                  // 去map里面获取指针对应的size，可能是常量，也可能是变量
                  if (ptrMapConst.count(ptrValueInst) && ptrMapConst[ptrValueInst])
                  {
                    uint64_t arrayByteSize = ptrMapConst[ptrValueInst];
                    ConstantInt *arraySize = ConstantInt::get(Int64Ty, arrayByteSize / elementSize);
                    uint64_t cur_id = id++;
                    ConstantInt *CurId = ConstantInt::get(Int64Ty, cur_id);

                    insertAflCompare(IRB, CurId, arraySize, GEP->getOperand(1), C, M, compareFunc);
                    inst_afl_compare ++;
                    errs() << "1111\n";
                  }
                  // 访存大小是变量
                  else if (ptrMapVar.count(ptrValueInst) && ptrMapVar[ptrValueInst])
                  {
                    errs() << "2222\n";
                  }
                  // 按理来说，永远不会出现这种情况，因为正确的程序，指针要么被存到Const的Map
                  // 要么就是被存到Var的Map，但是咱们这也考虑一下错误的程序的情况
                  else
                  {
                    errs() << "3333" << ptrMapConst.count(ptrValueInst) << " " << ptrMapConst[ptrValueInst] << "\n";
                    continue;
                  }
                }
                // 通过指针访问数组元素
                // int a[10];
                // int f = *(a + i);
                // 对应IR：
                // %8 = getelementptr inbounds [10 x i32], [10 x i32]* %5, i32 0, i32 0
                // %9 = load i32, i32* %3, align 4
                // %10 = sext i32 %9 to i64
                // %11 = getelementptr inbounds i32, i32* %8, i64 %10
                else if (auto *gepPtrInst = dyn_cast<GetElementPtrInst>(ptrValue))
                {
                  // if the source type is not array type, continue
                  const Type *gepSourceType = gepPtrInst->getSourceElementType();
                  if (!ArrayType::classof(gepSourceType))
                    continue;

                  uint64_t arrayNumElements = gepSourceType->getArrayNumElements();
                  ConstantInt *arraySize = ConstantInt::get(Int64Ty, arrayNumElements);
                  uint64_t cur_id = id++;
                  ConstantInt *CurId = ConstantInt::get(Int64Ty, cur_id);

                  insertAflCompare(IRB, CurId, arraySize, GEP->getOperand(1), C, M, compareFunc);
                  inst_afl_compare ++;
                  errs() << "4444\n";
                }
              }
            }
          }
        }
      }
    }
  }

  OKF("Instrumented %u afl compare locations.", inst_afl_compare);

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M)
    for (auto &BB : F)
    {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      if (AFL_R(100) >= inst_ratio)
        continue;

      /* Make up cur_loc */

      unsigned int cur_loc = AFL_R(MAP_SIZE);

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

      /* Update bitmap */

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;
    }

  /* Say something nice. */

  if (!be_quiet)
  {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else
      OKF("Instrumented %u locations (%s mode, ratio %u%%).",
          inst_blocks, getenv("AFL_HARDEN") ? "hardened" : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ? "ASAN/MSAN" : "non-hardened"), inst_ratio);
  }

  return true;
}

static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM)
{

  PM.add(new AFLCoverage());
}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
