
#include <stdio.h>

#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/ForceFunctionAttrs.h>
#include <llvm/Transforms/IPO/FunctionAttrs.h>
#include <llvm/Transforms/IPO/InferFunctionAttrs.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Scalar/InstSimplifyPass.h>
#include <llvm/Transforms/Utils.h>

#include <llvm/Analysis/GlobalsModRef.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>

#include "retdec/common/address.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/io/log.h"
#include "retdec/utils/string.h"
#include <llvm/CodeGen/CommandFlags.inc>
#include <llvm/IR/Module.h>
#include <llvm/Support/CodeGen.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/Object/COFF.h>

#include <llvm/Target/TargetMachine.h>

#include "retdec/capstone2llvmir/capstone2llvmir.h"

// add byte ptr [0x12345678], 0x11
// add byte ptr [0x00401000], 0xBB
auto CODE = retdec::utils::hexStringToBytes("80 05 78 56 34 12 11 80 05 00 10 40 00 BB");

// je xx
// jne xx
auto CODE2 = retdec::utils::hexStringToBytes("74 00 75 FC");

using namespace retdec::utils::io;
using namespace retdec::capstone2llvmir;

void test_capstone2llvmir_1()
{
	printf("test_capstone2llvmir_1: begin\n");

	llvm::LLVMContext ctx;
	llvm::Module module("test_capstone2llvmir_1", ctx);

	auto* f = llvm::Function::Create(
		llvm::FunctionType::get(llvm::Type::getVoidTy(ctx), false),
		llvm::GlobalValue::ExternalLinkage,
		"root",
		&module);
	llvm::BasicBlock::Create(module.getContext(), "entry", f);
	llvm::IRBuilder<> irb(&f->front());

	auto* ret = irb.CreateRetVoid();
	irb.SetInsertPoint(ret);


	try
	{
		// Test X86:32 mode

		auto BASEADDR = 0x1000;

		// create arch (capstone)
		auto c2l = Capstone2LlvmIrTranslator::createArch(CS_ARCH_X86, &module, CS_MODE_32, CS_MODE_LITTLE_ENDIAN);

		// binary code -> LLVM IR
		// generatint address
		c2l->translate(CODE.data(), CODE.size(), BASEADDR, irb, 0, false, true);

		//// binary code -> LLVM IR
		// no generating address
		// c2l->translate(CODE.data(), CODE.size(), BASEADDR, irb, 0, false, false);
	}
	catch (const BaseError& e)
	{
		Log::error() << e.what() << std::endl;
		assert(false);
	}
	catch (...)
	{
		Log::error() << "Some unhandled exception" << std::endl;
	}

	for (auto& F: module)
	{
		// filter declaration
		if (F.isDeclaration())
		{
			continue;
		}

		auto FuncName = std::string(F.getName());
		std::cout << "FuncName=" << FuncName << std::endl;
	}

	std::error_code ec;
	llvm::raw_fd_ostream out(CAPSTONE2LLVMIR_SRC_DIR "/sample/test_capstone2llvmir_1.ll", ec, llvm::sys::fs::F_None);
	module.print(out, nullptr);


	printf("test_capstone2llvmir_1: end\n");
}

void test_capstone2llvmir_2()
{
	printf("test_capstone2llvmir_2: begin\n");

	llvm::LLVMContext ctx;
	llvm::Module module("test_capstone2llvmir_2", ctx);

	auto* f = llvm::Function::Create(
		llvm::FunctionType::get(llvm::Type::getVoidTy(ctx), false),
		llvm::GlobalValue::ExternalLinkage,
		"root",
		&module);
	llvm::BasicBlock::Create(module.getContext(), "entry", f);
	llvm::IRBuilder<> irb(&f->front());

	auto* ret = irb.CreateRetVoid();
	irb.SetInsertPoint(ret);


	try
	{
		// Test X86:32 mode

		auto BASEADDR = 0x1000;

		// create arch (capstone)
		auto c2l = Capstone2LlvmIrTranslator::createArch(CS_ARCH_X86, &module, CS_MODE_32, CS_MODE_LITTLE_ENDIAN);

		// binary code -> LLVM IR
		// generatint address
		// c2l->translate(CODE2.data(), CODE2.size(), BASEADDR, irb, 0, false, true);

		//// binary code -> LLVM IR
		// no generating address
		c2l->translate(CODE2.data(), CODE2.size(), BASEADDR, irb, 0, false, false);
	}
	catch (const BaseError& e)
	{
		Log::error() << e.what() << std::endl;
		assert(false);
	}
	catch (...)
	{
		Log::error() << "Some unhandled exception" << std::endl;
	}

	for (auto& F: module)
	{
		// filter declaration
		if (F.isDeclaration())
		{
			continue;
		}

		auto FuncName = std::string(F.getName());
		std::cout << "FuncName=" << FuncName << std::endl;
	}

	std::error_code ec;
	llvm::raw_fd_ostream out(CAPSTONE2LLVMIR_SRC_DIR "/sample/test_capstone2llvmir_2.ll", ec, llvm::sys::fs::F_None);
	module.print(out, nullptr);


	printf("test_capstone2llvmir_2: end\n");
}


void test_read_coff()
{
	/*ErrorOr<std::unique_ptr<MemoryBuffer>> FileOrErr =
		MemoryBuffer::getFileOrSTDIN(CAPSTONE2LLVMIR_SRC_DIR "/sample/test_capstone2llvmir_1_o3.obj");*/
	ErrorOr<std::unique_ptr<MemoryBuffer>> FileOrErr =
		MemoryBuffer::getFileOrSTDIN(CAPSTONE2LLVMIR_SRC_DIR "/sample/test_capstone2llvmir_2.obj");
	if (std::error_code EC = FileOrErr.getError())
	{
		printf("test_read_coff read file failed:%s \n", EC.message().c_str());
		return;
	}
	auto parser = llvm::object::COFFObjectFile::createCOFFObjectFile(FileOrErr.get()->getMemBufferRef());

	for (const auto& exp: parser.get()->import_directories())
	{
		printf("import\n");
		StringRef symbolName = "";
		exp.getName(symbolName);
		if (symbolName.empty()) continue;
		printf("symbolName=%s", symbolName.data());
	}

	for (const auto& exp: parser.get()->export_directories())
	{
		printf("export\n");
		StringRef dllName = "", symbolName = "";
		uint32_t exportRVA = 0;
		exp.getDllName(dllName);
		exp.getSymbolName(symbolName);
		exp.getExportRVA(exportRVA);
		if (symbolName.empty()) continue;
		printf("dllname=%s,symbolName=%s,exportRVA=0x%x", dllName.data(), symbolName.data(), exportRVA);
	}


	{
		const object::coff_section* coff_sec = nullptr;
		parser.get()->getSection(".text", coff_sec);
		if (coff_sec)
		{
			printf("qqq:%s\n", coff_sec->Name);
			// b4
			auto PointerToRawData = coff_sec->PointerToRawData;
			printf("PointerToRawData:%p\n", PointerToRawData);
		}
	}

	for (auto& Section: parser.get()->sections())
	{
		StringRef Name = "";
		Section.getName(Name);
		auto sectionaddr = Section.getAddress();
		StringRef Contents = "";
		Section.getContents(Contents);
		if (!Name.empty())
		{
			printf("Section.name=%s,Contents=%s,addr=%p\n\t", Name.data(), Contents.data(), sectionaddr);
		}


		for (auto& relocitem: Section.relocations())
		{
			auto offset = relocitem.getOffset();
			printf("relocitem:offset=%p\n\t", offset);
		}
	}

	{
		for (uint32_t i = 0; i < parser.get()->getRawNumberOfSymbols(); ++i)
		{
			auto sym = parser.get()->getSymbol(i);
			if (!sym)
			{
				continue;
			}

			object::COFFSymbolRef SymRef = *sym;
			// printf("shortname:%s\n", SymRef.getShortName());
			StringRef symname = "";
			auto ec = parser.get()->getSymbolName(SymRef, symname);
			if (ec.value() == 0)
			{
				printf("symname:%s\n", symname.data());
			}


			// printf("SymRef.getValue()=%p", SymRef.getGeneric()->Value);
			/*ArrayRef<uint8_t> AuxData = parser.get()->getSymbolAuxData(SymRef);
			for (auto x: AuxData)
			{
				printf("%x\n", x);
			}*/
			// printf("getStringTableOffset=%p", SymRef.getStringTableOffset().Offset);

			/*auto bufferstart = (unsigned char*)FileOrErr.get()->getMemBufferRef().getBufferStart();
			printf("bufferstart=%p", bufferstart);
			auto ratptr = (unsigned char*)SymRef.getRawPtr();
			printf("rawptr=%p", ratptr);
			auto of = ratptr - bufferstart;
			printf("of=%p\n", of);

			auto coffsectionheader = (object::coff_section*)ratptr;
			printf("PointerToRawData:%p\n", coffsectionheader->PointerToRawData);

			unsigned char* coffsectionheaderVA = coffsectionheader->PointerToRawData + bufferstart;
			printf("coffsectionheaderVA:%p\n", coffsectionheaderVA);*/
		}
	}


	{
		for (auto& sym: parser.get()->symbols())
		{
			auto addr = sym.getAddress();
			auto name = sym.getName();
			auto val = sym.getValue();
			auto raw = sym.getRawDataRefImpl().p;
			if (!name)
			{
				continue;
			}


			printf("name=%s,addr=%p,val=%p\n", name.get().data(), addr.get(), val);
		}
	}
}


//auto CODE444 = retdec::utils::hexStringToBytes("50 8B 44 24 04 87 05 41 F0 41 00 58 83 C4 04 50 B8 CC CC CC CC 8D 80 9C 8F DB 74 87 05 24 F0 41 00 58 90 90 90 90 90 90 00 90 90 90 90 90 90 90 90 90 90 90 50 66 B8 EB E9 66 87 05 24 F0 41 00 B8 BB BB BB BB 87 04 24 C3");
auto CODE444 = retdec::utils::hexStringToBytes("C2 08 00");

void test_capstone2llvmir_func()
{
	printf("test_capstone2llvmir_func: begin\n");

	llvm::LLVMContext ctx;
	llvm::Module module("test_capstone2llvmir_func", ctx);

	auto* f = llvm::Function::Create(
		llvm::FunctionType::get(llvm::Type::getVoidTy(ctx), false),
		llvm::GlobalValue::ExternalLinkage,
		"root",
		&module);
	llvm::BasicBlock::Create(module.getContext(), "entry", f);
	llvm::IRBuilder<> irb(&f->front());

	auto* ret = irb.CreateRetVoid();
	irb.SetInsertPoint(ret);


	try
	{
		auto BASEADDR = 0x41F000;
		// create arch (capstone)
		auto c2l = Capstone2LlvmIrTranslator::createArch(CS_ARCH_X86, &module, CS_MODE_32, CS_MODE_LITTLE_ENDIAN);
		c2l->translate(CODE444.data(), CODE444.size(), BASEADDR, irb, 0, false, false);
	}
	catch (const BaseError& e)
	{
		Log::error() << e.what() << std::endl;
		assert(false);
	}
	catch (...)
	{
		Log::error() << "Some unhandled exception" << std::endl;
	}

	for (auto& F: module)
	{
		// filter declaration
		if (F.isDeclaration())
		{
			continue;
		}

		auto FuncName = std::string(F.getName());
		std::cout << "FuncName=" << FuncName << std::endl;
	}

	std::error_code ec;
	llvm::raw_fd_ostream out(CAPSTONE2LLVMIR_SRC_DIR "/sample/test_capstone2llvmir_func.ll", ec, llvm::sys::fs::F_None);
	module.print(out, nullptr);


	printf("test_capstone2llvmir_func: end\n");
}

int main()
{
	// test_capstone2llvmir_1();
	// test_capstone2llvmir_2();
	// test_read_coff();
	test_capstone2llvmir_func();
	system("pause");
	return 0;
}
