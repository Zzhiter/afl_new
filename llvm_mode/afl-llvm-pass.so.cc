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
uint64_t cmpId = 2;

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
    BasicBlock *getNextBasicBlock(BasicBlock *currentBB, Function &F);

    void insertAflCompare(IRBuilder<> &IRB, Value *curId,
                          Value *arraySize, Value *index, LLVMContext &C, Module &M, Function *compareFunc);

    void insertAflGepStatus(IRBuilder<> &IRB, Value *curId,
                            Value *index, LLVMContext &C, Module &M, Function *gepStatusFunc);

    void insertGetCmpStatus(IRBuilder<> &IRB, Value *curId,
                            Value *value, LLVMContext &C, Module &M, Function *getCmpStatusFunc);
    
    // StringRef getPassName() const override {
    //  return "American Fuzzy Lop Instrumentation";
    // }
  };

}

char AFLCoverage::ID = 0;

static bool isIgnoreFunction(const llvm::Function *F) {

  // Starting from "LLVMFuzzer" these are functions used in libfuzzer based
  // fuzzing campaign installations, e.g. oss-fuzz

  static constexpr const char *ignoreList[] = {
      "asan.",
      "llvm.",
      "sancov.",
      "__ubsan",
      "ign.",
      "__afl",
      "_fini",
      "__libc_",
      "__asan",
      "__msan",
      "__cmplog",
      "__sancov",
      "__san",
      "__cxx_",
      "__decide_deferred",
      "_GLOBAL",
      "_ZZN6__asan",
      "_ZZN6__lsan",
      "msan.",
      "LLVMFuzzerM",
      "LLVMFuzzerC",
      "LLVMFuzzerI",
      "maybe_duplicate_stderr",
      "discard_output",
      "close_stdout",
      "dup_and_close_stderr",
      "maybe_close_fd_mask",
      "ExecuteFilesOnyByOne"
  };

  for (auto const &ignoreListFunc : ignoreList) {

    if (F->getName().startswith(ignoreListFunc)) { return true; }

  }

  static constexpr const char *ignoreSubstringList[] = {

      "__asan", "__msan",       "__ubsan",    "__lsan",  "__san", "__sanitize",
      "__cxx",  "DebugCounter", "DwarfDebug", "DebugLoc"

  };

  for (auto const &ignoreListFunc : ignoreSubstringList) {

    // hexcoder: F->getName().contains() not avaiilable in llvm 3.8.0
    if (StringRef::npos != F->getName().find(ignoreListFunc)) { return true; }

  }

  return false;

}

// 函数用于获取当前基本块后面的基本块
BasicBlock *AFLCoverage::getNextBasicBlock(BasicBlock *currentBB, Function &F)
{
  // 获取当前基本块的迭代器
  Function::iterator it = currentBB->getIterator();

  // 在函数的基本块列表中找到当前基本块
  while (it != F.end() && &*it != currentBB)
  {
    ++it;
  }

  // 如果找到了当前基本块
  if (it != F.end())
  {
    // 移动到下一个基本块
    ++it;

    // 检查是否有下一个基本块
    if (it != F.end())
    {
      return &*it;
    }
  }

  // 没有找到当前基本块或没有后续基本块
  return nullptr;
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

void AFLCoverage::insertAflGepStatus(IRBuilder<> &IRB, Value *curId,
                                     Value *index, LLVMContext &C, Module &M, Function *gepStatusFunc)
{
  Value *compareFuncArgID = {curId};
  Value *compareFuncArgIndex = {index};
  IRB.CreateCall(gepStatusFunc, {compareFuncArgID,
                                compareFuncArgIndex});
  errs() << "成功插装！\n";
}

void AFLCoverage::insertGetCmpStatus(IRBuilder<> &IRB, Value *curId,
                                     Value *value, LLVMContext &C, Module &M, Function *getCmpStatusFunc)
{
  Value *compareFuncArgID = {curId};
  Value *compareFuncArgValue = {value};
  IRB.CreateCall(getCmpStatusFunc, {compareFuncArgID,
                                    compareFuncArgValue});
  errs() << "Insert cmp func success!\n";
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

  FunctionType *gepStatusFuncType = FunctionType::get(
      Type::getVoidTy(C),                                              // return type
      {Type::getInt64Ty(C), Type::getInt64Ty(C)}, // argument types
      false                                                            // variadic function
  );
  Function *gepStatusFunc = Function::Create(
      gepStatusFuncType, GlobalValue::ExternalLinkage, "__afl_gep_status", &M);

  FunctionType *getCmpStatusFuncType = FunctionType::get(
      Type::getVoidTy(C),                                              // return type
      {Type::getInt64Ty(C), Type::getInt64Ty(C)}, // argument types
      false                                                            // variadic function
  );
  Function *getCmpStatusFunc = Function::Create(
      getCmpStatusFuncType, GlobalValue::ExternalLinkage, "__afl_cmp_status", &M);

  /* Our Instrument before afl's */

  int gepStatusInsertCnt = 0;
  int cmpStatusInsertCnt = 0;

  for (auto &F : M)
  {
    // 过滤不插桩的函数
    if (!F.size() || isIgnoreFunction(&F))
      continue;

    for (auto &BB : F)
    {
      for (auto &Inst : BB)
      {
        if (auto *GEP = dyn_cast<GetElementPtrInst>(&Inst))
        {
          /* New simple instrument strategy start */

          if (GEP->getNumOperands() != 3)
            continue;

          if (dyn_cast<ConstantInt>(GEP->getOperand(2)))
            continue;
          
          if (gepStatusInsertCnt >= 10000) 
            continue;

          IRBuilder<> IRB(&Inst);
          uint64_t cur_id = id ++;
          ConstantInt *curId = ConstantInt::get(Int64Ty, cur_id);

          insertAflGepStatus(IRB, curId,
                              GEP->getOperand(2), C, M, gepStatusFunc);
          gepStatusInsertCnt ++;

          /* New simple instrument strategy end */
        } else if (Inst.getOpcode() == Instruction::ICmp) 
        {
          // 判断后面跟着的是不是if.then

          BasicBlock *currentBB = Inst.getParent();
          // 获取当前基本块后面的基本块
          BasicBlock *nextBB = getNextBasicBlock(currentBB, F);

          if (!nextBB) continue;
          if (nextBB->getName().str().find("if.then") != 0) continue;

          // 获取到icmp里面的变量
          errs() << "Yes!!!" << "\n";

          // 准备插桩！一个变量插一个！

          if (cmpStatusInsertCnt >= 10000) 
            continue;

          // It only operates on integers or pointers. 
          // The operands must be identical types.
          ICmpInst *icmpInst = cast<ICmpInst>(&Inst);
          // 获取icmp指令的操作数
          Value *op1 = icmpInst->getOperand(0);
          Value *op2 = icmpInst->getOperand(1);

          // if (dyn_cast<ConstantInt>(op1) && dyn_cast<ConstantInt>(op2))
          //   continue;
          
          IRBuilder<> IRB(&Inst);
          uint64_t curId;

          if (!dyn_cast<ConstantInt>(op1)) {
            curId = cmpId++;
            ConstantInt *curIdValue = ConstantInt::get(Int64Ty, curId);
            insertGetCmpStatus(IRB, curIdValue, op1, C, M, getCmpStatusFunc);
            cmpStatusInsertCnt ++;
          }

          if (!dyn_cast<ConstantInt>(op2)) {
            curId = cmpId++;
            ConstantInt *curIdValue = ConstantInt::get(Int64Ty, curId);
            insertGetCmpStatus(IRB, curIdValue, op2, C, M, getCmpStatusFunc);
            cmpStatusInsertCnt ++;
          }
        }
      }
    }
  }

  OKF("Instrumented %u gepStatus locations.", gepStatusInsertCnt);
  OKF("Instrumented %u cmpStatus locations.", cmpStatusInsertCnt);

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
