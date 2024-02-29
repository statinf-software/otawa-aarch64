/*
 *	arm2 -- OTAWA loader to support ARMv5 ISA with GLISS2
 *	PowerPC OTAWA plugin
 *
 *	This file is part of OTAWA
 *	Copyright (c) 2011, IRIT UPS.
 *
 *	OTAWA is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	OTAWA is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with OTAWA; if not, write to the Free Software
 *	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <cxxabi.h>

#include <otawa/prog/Loader.h>
#include <otawa/proc/ProcessorPlugin.h>
#include <otawa/hard.h>
#include <otawa/program.h>
#include <otawa/prog/sem.h>
#include <otawa/loader/aarch64.h>
// #include <otawa/prog/features.h>

#include <elm/stree/MarkerBuilder.h>
#include <elm/stree/SegmentBuilder.h>

#include <gel++.h>
#include <gel++/DebugLine.h>

extern "C" {
#	include <aarch64/grt.h>
#	include <aarch64/api.h>
#	include <aarch64/config.h>
#	include <aarch64/used_regs.h>
#	include <../extra/myfile.h>
}

namespace otawa {

namespace aarch64 {

/*
 * Configuration
 * * AARCH64_SIM -- integrate functional simulator in ARM plugin.
 */

#define VERSION "0.1"

/**
 * @class Info
 * Information provided by an ARM loader supporting GLISS2 engine.
 */

/**
 * @fn void *Info::decode(Inst *inst);
 * Get the decode instruction by GLISS2.
 * The obtained data must be fried with free() method.
 * @param inst	Instruction to decode.
 * @return		Decoded data castable to aarch64_inst_t *.
 */

/**
 * @fn void Info::free(void *decoded);
 * Free an instruction previously obtained by decode() method.
 * @paramd decoded	Result of decode.
 */


/**
 * t::uint16 Info::multiMask(Inst *inst);
 * For a multiple register memory instruction,
 * get the mask of processed register (1 bit per register).
 * @param inst	Concerned instruction.
 * @return		Mask of processed registers.
 */


/**
 * Identifier used to retrieve ARM specific information.
 * Must be accessed dynamically because ARM loader is a plugin !
 *
 * @par Hooks
 * @li Process from ARM loader.
 */
Identifier <Info *> Info::ID("otawa::aarch64::Info::ID", 0);


/**
 */
Info::~Info(void) {
}

}

namespace aarch64_2 {

#include "otawa_kind.h"
#include "otawa_target.h"
#include "otawa_multi.h"


/****** Platform definition ******/

// registers
static hard::PlainBank gpr("X", hard::Register::INT, 64, "x%d", 31);
static const hard::RegBank *banks_tab[] = { &gpr };
static Array<const hard::RegBank *> banks_table(1, banks_tab);

static hard::Register *pc = new hard::Register("pc", hard::Register::INT, 64);
static hard::Register *sp = new hard::Register("sp", hard::Register::INT, 64);

// register decoding
class RegisterDecoder {
public:
	RegisterDecoder(void) {

		// // clear the map
		// for(int i = 0; i < AARCH64_REG_COUNT; i++)
		// 	map[i] = 0;

		// // initialize it
		// 	map[AARCH64_REG_GPR(i)] = gpr[i];
	}

	inline hard::Register *operator[](int i) const { ASSERT(i < AARCH64_REG_COUNT); return map[i]; }

private:
	hard::Register *map[AARCH64_REG_COUNT];
};
static RegisterDecoder register_decoder;


// semantics functions
#define _GPR(i)			gpr[i]->platformNumber()
#define _CPSR()			sr.platformNumber()
#define _BRANCH(t)		sem::branch(t)
#define _TRAP()			sem::trap(0)
#define _CONT()			sem::cont()
#define _IF(c, r, o)	sem::_if(c, r, o)
#define _LOAD(d, a, b)	sem::load(d, a, b)
#define _STORE(d, a, b)	sem::store(d, a, b)
#define _SCRATCH(d)		sem::scratch(d)

#include "otawa_sem.h"
#include "otawa_ksem.h"


// platform
class Platform: public hard::Platform {
public:
	static const Identification ID;

	Platform(const PropList& props = PropList::EMPTY): hard::Platform(ID, props)
		{ setBanks(banks_table); }
	Platform(const Platform& platform, const PropList& props = PropList::EMPTY)
		: hard::Platform(platform, props)
		{ setBanks(banks_table); }

	// otawa::Platform overload
	virtual bool accept(const Identification& id) { return id.abi() == "eabi" && id.architecture() == "aarch64"; }
	virtual const hard::Register *getSP(void) const { return sp; }
};
const Platform::Identification Platform::ID("aarch64-eabi-");


/****** Instruction declarations ******/

class Process;

#include "otawa_condition.h"

/* IT support
 *
 * Mask		# conditional instructions
 * 1000		0
 * X100		1
 * XX10		2
 * XXX1		3
 *
 * condition instruction i (in [0, 2]):
 * 	firstcond<3..1>
 * 	firscond<0..0> = firscond<0..0> ^ mask<3-i>
 *
 * cond		Condition
 * 0000		EQ
 * 0001		NE
 * 0010		HS
 * 0011		LO
 * 0100		...
 */

// Inst class
class Inst: public otawa::Inst {
public:

	inline Inst(Process& process, kind_t kind, Address addr, int size)
		: proc(process), _kind(kind), _size(size), _addr(addr.offset()), isRegsDone(false) {
		}

	// Inst overload
	virtual void dump(io::Output& out);
	virtual kind_t kind() { return _kind; }
	virtual address_t address() const { return _addr; }
	virtual t::uint32 size() const { return _size; }
	virtual Process &process() { return proc; }

	virtual const Array<hard::Register *>& readRegs() override {
		if (!isRegsDone) {
			decodeRegs();
			isRegsDone = true;
		}
		return in_regs;
	}

	virtual const Array<hard::Register *>& writtenRegs() override {
		if(!isRegsDone) {
			decodeRegs();
			isRegsDone = true;
		}
		return out_regs;
	}

	void semInsts(sem::Block &block) override;
	void semKernel(sem::Block &block) override;
	Condition condition() override;

	int multiCount() override { return otawa::aarch64::NUM_REGS_LOAD_STORE(this); }
	
protected:
	Process &proc;
	kind_t _kind;
	int _size;

private:
	void decodeRegs(void);
	AllocArray<hard::Register *> in_regs;
	AllocArray<hard::Register *> out_regs;
	aarch64_address_t _addr;
	bool isRegsDone;
};


// BranchInst class
class BranchInst: public Inst {
public:

	inline BranchInst(Process& process, kind_t kind, Address addr, int size)
		: Inst(process, kind & ~IS_CONTROL, addr, size), _target(0), isTargetDone(false)
		{ }

	otawa::Inst *target() override;
	kind_t kind() override;

protected:
	aarch64_address_t decodeTargetAddress(void);

private:
	otawa::Inst *_target;
	bool isTargetDone;
};


// ITInst class
class ITInst: public otawa::Inst {
public:
	ITInst(otawa::Inst *inst, int cond): i(inst), c(cond) { }

	kind_t kind() override { return i->kind() | IS_COND; }
	otawa::Inst *target() override { return i->target(); }

	void dump(io::Output& out) override {
		static cstring conds[16] = {
			"EQ", "NE", "HS", "LO",
			"MI", "PL", "VS", "VC"
			"HI", "LS", "GE", "LT",
			"GT", "LE", "AL", "NV"
		};
		i->dump(out);
		out << "(" << conds[c] << ")";
	}

	address_t address() const override { return i->address(); }
	t::uint32 size() const override { return i->size(); }

	const Array<hard::Register *>& readRegs() override
		{ return i->readRegs(); }

	const Array<hard::Register *>& writtenRegs() override
		{ return i->writtenRegs(); }

	void semInsts(sem::Block &block) override {
		block.add(sem::_if(0, 0, 0));
		i->semKernel(block);
		// block[0] = sem::_if(sem_conds[c], sr.platformNumber(), block.length());
	}

	void semKernel(sem::Block &block) override
		{ i->semKernel(block); }

	// Condition condition() override {
	// 	return Condition(sem_conds[c], &sr);
	// }

private:
	otawa::Inst *i;
	int c;
	static sem::cond_t sem_conds[16];
};

sem::cond_t ITInst::sem_conds[16] = {
	sem::EQ, sem::NE, sem::UGE, sem::ULT,
	sem::ANY_COND, sem::ANY_COND, sem::ANY_COND, sem::ANY_COND,
	sem::UGT, sem::ULE, sem::GE, sem::LT,
	sem::GT, sem::LE, sem::ANY_COND, sem::ANY_COND
};


/****** Segment class ******/
class Process;
class Segment: public otawa::Segment {
	friend class Process;
public:
	Segment(Process& process,
		CString name,
		address_t address,
		t::uint32 size,
		int flags = EXECUTABLE)
	: otawa::Segment(name, address, size, flags), proc(process) { }

protected:
	virtual otawa::Inst *decode(address_t address);

private:
	Process& proc;
};


/****** Process class ******/
typedef enum { NONE = 0, ARM = 1, DATA = 2 } area_t;
io::Output& operator<<(io::Output& out, area_t i) {
    out << "aarch64";
	return out;
}

class Process: public otawa::Process, public aarch64::Info {
public:
	static const t::uint32 IS_BL_0			= 0x08000000,
							 IS_BL_1 		= 0x04000000,
							 IS_BX_IP 		= 0x02000000,
							 IS_THUMB_BX	= 0x01000000;

	Process(Manager *manager, hard::Platform *pf, const PropList& props = PropList::EMPTY)
	:	otawa::Process(manager, props),
	 	_start(0),
	 	oplatform(pf),
	 	_platform(0),
		_memory(0),
		_decoder(0),
		_lines(0),
		_file(0),
		argc(0),
		argv(0),
		envp(0),
		no_stack(true),
		init(false)
#		ifdef AARCH64_MEM_IO
			, io_man(nullptr)
#		endif
	{
		ASSERTP(manager, "manager required");
		ASSERTP(pf, "platform required");

		// gliss2 ppc structs
		_platform = aarch64_new_platform();
		ASSERTP(_platform, "cannot create an aarch64_platform");
		_decoder = aarch64_new_decoder(_platform);
		ASSERTP(_decoder, "cannot create an aarch64_decoder");
		_memory = aarch64_get_memory(_platform, AARCH64_MAIN_MEMORY);
		ASSERTP(_memory, "cannot get main aarch64_memory");
		aarch64_lock_platform(_platform);

		// build arguments
		static char no_name[1] = { 0 };
		static char *default_argv[] = { no_name, 0 };
		static char *default_envp[] = { 0 };
		argc = ARGC(props);
		if (argc < 0)
			argc = 1;
		argv = ARGV(props);
		if (!argv)
			argv = default_argv;
		else
			no_stack = false;
		envp = ENVP(props);
		if (!envp)
			envp = default_envp;
		else
			no_stack = false;

		// handle features
		provide(MEMORY_ACCESS_FEATURE);
		provide(SOURCE_LINE_FEATURE);
		provide(CONTROL_DECODING_FEATURE);
		provide(REGISTER_USAGE_FEATURE);
		provide(MEMORY_ACCESSES);
		provide(CONDITIONAL_INSTRUCTIONS_FEATURE);
		provide(SEMANTICS_INFO);
		Info::ID(this) = this;
	}

	virtual ~Process() {
		aarch64_delete_decoder(_decoder);
		aarch64_unlock_platform(_platform);
		if(_file)
			delete _file;
	}

	// Process overloads
	virtual int instSize(void) const {
        return 4;
	}
	virtual hard::Platform *platform(void) { return oplatform; }
	virtual otawa::Inst *start(void) { return _start; }

	virtual File *loadFile(elm::CString path) {

		// check if there is not an already opened file !
		if(program())
			throw LoadException("loader cannot open multiple files !");

		// make the file
		File *file = new otawa::File(path);
		addFile(file);

		// build the environment
		gel::Parameter genv;
		cstring a[argc];
		for(int i = 0; i < argc; i++)
			a[i] = argv[i];
		genv.arg = Array<cstring>(argc, a);
		int c = 0;
		for(int i = 0; envp[i] != nullptr; i++);
		cstring e[c];
		for(int i = 0; i < c; i++)
			e[i] = envp[i];
		genv.env = Array<cstring>(c, e);
		genv.stack_alloc = !no_stack;

		try {
			// build the GEL image
			_file = gel::Manager::open(path);
			gel::Image* image = _file->make(genv);

			if(! image)
				throw LoadException("gel returned no image");

			// build segments
			stree::SegmentBuilder<t::uint32, bool> builder(false);
			for(gel::ImageSegment *seg: image->segments()) {
				// build the segment
				auto buf = seg->buffer();
				t::uint32 flags = 0;
				if(seg->isExecutable()) {
					flags |= Segment::EXECUTABLE;
					builder.add(seg->baseAddress(), seg->baseAddress() + buf.size(), true);
				}
				if(seg->isWritable())
					flags |= Segment::WRITABLE;
				else if(seg->hasContent())
					flags |= Segment::INITIALIZED;
				
				auto *oseg = new Segment(*this,
					seg->name(),
					seg->baseAddress(),
					seg->size(),
					flags);
				file->addSegment(oseg);

				cerr << "DEBUG - Segment: addr=" << seg->baseAddress() << " / size: " << buf.size() << " / first byte: " << hex << buf.at(0) << endl; 

				// set the memory
				aarch64_mem_write(_memory,
					seg->baseAddress(),
					buf.bytes(),
					buf.size());
			}
			stree::Tree<t::uint32, bool> execs;
			builder.make(execs);

			// Initialize symbols
			for(auto sym: _file->symbols()) {
				// compute kind
				Symbol::kind_t kind = Symbol::NONE;
				t::uint64 val = sym->value();
				string name = sym->name();
				switch(sym->type()) {
					case gel::Symbol::FUNC:
						kind = Symbol::FUNCTION;
						name = sanitize(demangle(sym->name()));
						// cerr << "DEBUG - Symbol: function " << name << " - val " << val << io::endl;
						break;
					case gel::Symbol::OTHER_TYPE:
						continue;
					case gel::Symbol::LABEL:
						kind = Symbol::LABEL;
						// cerr << "DEBUG - Symbol: label " << name << " - val " << val << io::endl;
						break;
					case gel::Symbol::DATA:
						name = demangle(sym->name());
						// cerr << "DEBUG - Symbol: data " << name << io::endl;
						kind = Symbol::DATA;
						// val = tms2otawa(val);
						break;
					case gel::Symbol::NO_TYPE:
						// cerr << "DEBUG - Symbol: NO TYPE " << name << io::endl;
						if(!execs.contains(val))
							continue;
						kind = Symbol::LABEL;
					// 	case STT_OBJECT:
					// 		kind = Symbol::DATA;
					// 		break;
					default:
						cerr << "DEBUG: don't know what to do with " << name << io::endl;
						continue;
				}
				if(name.isEmpty())
					continue;
				// build the symbol
				//cerr << "Adding this symbol to file:" << sym->name().chars() << "\n";
				Symbol *osym = new Symbol(*file, name,
					kind, val, sym->size());
				// cerr << "DEBUG: OTAWA: " << osym << io::endl;
				file->addSymbol(osym);
			}

			// clean up
			delete image;

			// Last initializations
			_start = findInstAt(_file->entry());
			return file;
		}
		catch(gel::Exception& e) {
			throw LoadException(_ << "cannot load \"" << path << "\": " << e.message());
		}
	}

	string demangle(const string & str) {
        int status;
        string demangled = str;
        char *realname = abi::__cxa_demangle(str.toCString(), 0, 0, &status);
        if(status == 0) {
          demangled = realname;
        }
        if(realname != NULL)
          free(realname);

        return demangled;
    }

	//with CPP, we can have -/+ signs in the symb name in case of templates
	// otawa doesn't like that
	string sanitize(const string &str) {
		string res = str;
		res = res.replace("-", "m");
		res = res.replace("+", "p");
		return res;
	}

	// internal work
	void decodeRegs(Inst *oinst,
		AllocArray<hard::Register *>& in,
		AllocArray<hard::Register *>& out)
	{
		// Decode instruction
		aarch64_inst_t *inst = decode_raw(oinst->address());
		if(inst->ident == AARCH64_UNKNOWN) {
			free_inst(inst);
			return;
		}

		// get the registers
		// aarch64_used_regs_read_t rds;
		// aarch64_used_regs_write_t wrs;
		// aarch64_used_regs(inst, rds, wrs);

		// // convert registers to OTAWA
		// Vector<hard::Register *> reg_in;
		// Vector<hard::Register *> reg_out;
		// for (int i = 0; rds[i] != -1; i++ ) {
		// 	hard::Register *r = register_decoder[rds[i]];
		// 	if(r)
		// 		reg_in.add(r);
		// }
		// for (int i = 0; wrs[i] != -1; i++ ) {
		// 	hard::Register *r = register_decoder[wrs[i]];
		// 	if(r)
		// 		reg_out.add(r);
		// }

		// make the in and the out
		// in = AllocArray<hard::Register *>(reg_in.length());
		// for(int i = 0 ; i < reg_in.length(); i++)
		// 	in.set(i, reg_in.get(i));
		// out = AllocArray<hard::Register *>(reg_out.length());
		// for (int i = 0 ; i < reg_out.length(); i++)
		// 	out.set(i, reg_out.get(i));

		// // Free instruction
		free_inst(inst);
	}

	/**
	 * Build instructions depending on the IT.
	 * @param i				IT instruction itself.
	 * @param firstcond		firstcond field of IT.
	 * @param mask			mask field of IT.
	 * @param seg			Container segment of these instructions.
	 */
	void makeIT(otawa::Inst *i, t::uint8 firstcond, t::uint8 mask, Segment *seg) {
		do {
			otawa::Inst *n = decode(i->topAddress(), seg);
			i = new ITInst(n, firstcond ^ ((~mask >> 3) & 0b1));
			seg->insert(i);
			mask <<= 1;
		} while((mask & 0xf) != 0);
	}


	otawa::Inst *decode(Address addr, Segment *seg) {

		// get kind
		aarch64_inst_t *inst = decode_raw(addr);
		Inst::kind_t kind = aarch64_kind(inst);

		// compute size
		int size;
		size = 4;

		// build the instruction
		Inst *i;
		if(kind & Inst::IS_CONTROL)
			i = new BranchInst(*this, kind, addr, size);
		else
			i = new Inst(*this, kind, addr, size);

// cout << "-----> " << addr << " -- ";
// i->dump(cout);
// cout << endl;

		// compute multiple register load/store information
		t::uint16 multi = aarch64_multi(inst);
		if(multi)
			otawa::aarch64::NUM_REGS_LOAD_STORE(i) = elm::ones(multi);

		// special processing for IT
		// TO TEST
		// if(inst->ident == AARCH64_YIELDS) {
		// 	t::uint8 firstcond = AARCH64_YIELDS_i_x_firstcond;
		// 	t::uint8 mask = AARCH64_YIELDS_i_x_mask;
		// 	if(mask != 0)
		// 		makeIT(i, firstcond, mask, seg);
		// }

		// cleanup and return
		free_inst(inst);
		return i;
	}

	// GLISS2 ARM access
	inline int opcode(Inst *inst) const {
		aarch64_inst_t *i = decode_raw(inst->address());
		int code = i->ident;
		free_inst(i);
		return code;
	}

	inline ::aarch64_inst_t *decode_raw(Address addr) const {
        return aarch64_decode(decoder(), ::aarch64_address_t(addr.offset()));
	}

	inline void free_inst(aarch64_inst_t *inst) const { aarch64_free_inst(inst); }
	virtual gel::File *file(void) const { return _file; }
	virtual aarch64_memory_t *memory(void) const { return _memory; }
	inline aarch64_decoder_t *decoder() const { return _decoder; }
	inline void *platform(void) const { return _platform; }

	virtual Option<Pair<cstring, int> > getSourceLine(Address addr) {
		setup_debug();
		if (_lines == nullptr)
			return none;
		auto l = _lines->lineAt(addr.offset());
		if(l == nullptr)
			return none;
		return some(pair(
			l->file()->path().toString().toCString(),
			l->line()));
	}

	virtual void getAddresses(cstring file, int line, Vector<Pair<Address, Address> >& addresses) {
		setup_debug();
		addresses.clear();
		if(_lines == nullptr)
			return;
		auto f = _lines->files().get(file);
		if(!f)
			return;
		Vector<Pair<gel::address_t, gel::address_t>> res;
		(*f)->find(line, res);
		for(auto a: res)
			addresses.add(pair(
				Address(a.fst),
				Address(a.snd)));
	}

	virtual void get(Address at, t::int8& val)
		{ val = aarch64_mem_read8(_memory, at.offset()); }
	virtual void get(Address at, t::uint8& val)
		{ val = aarch64_mem_read8(_memory, at.offset()); }
	virtual void get(Address at, t::int16& val)
		{ val = aarch64_mem_read16(_memory, at.offset()); }
	virtual void get(Address at, t::uint16& val)
		{ val = aarch64_mem_read16(_memory, at.offset()); }
	virtual void get(Address at, t::int32& val)
		{ val = aarch64_mem_read32(_memory, at.offset()); }
	virtual void get(Address at, t::uint32& val)
		{ val = aarch64_mem_read32(_memory, at.offset()); }
	virtual void get(Address at, t::int64& val)
		{ val = aarch64_mem_read64(_memory, at.offset()); }
	virtual void get(Address at, t::uint64& val)
		{ val = aarch64_mem_read64(_memory, at.offset()); }
	virtual void get(Address at, Address& val)
		{ val = aarch64_mem_read32(_memory, at.offset()); }
	virtual void get(Address at, string& str) {
		Address base = at;
		while(!aarch64_mem_read8(_memory, at.offset()))
			at = at + 1;
		int len = at - base;
		char buf[len];
		get(base, buf, len);
		str = String(buf, len);
	}
	virtual void get(Address at, char *buf, int size)
		{ aarch64_mem_read(_memory, at.offset(), buf, size); }
	virtual int maxTemp (void) const { return 3; }

	// otawa::aarch64::Info overload
	virtual void *decode(otawa::Inst *inst) { return decode_raw(inst->address()); }
	virtual void free(void *decoded) { free_inst(static_cast<aarch64_inst_t *>(decoded)); }

	virtual t::uint16 multiMask(otawa::Inst *inst) {
		aarch64_inst_t *i = decode_raw(inst->address());
		t::uint16 r = aarch64_multi(i);
		free_inst(i);
		return r;
	}

	virtual void handleIO(Address addr, t::uint32 size, otawa::aarch64::IOManager& man) {
#		ifndef AARCH64_MEM_IO
			ASSERTP(false, "WITH_MEM_IO not configured in arm GLISS plugin!");
#		else
			//io_man = &man;
			aarch64_set_range_callback(memory(), addr.offset(), addr.offset() + size, io_callback, &man);
#		endif
	}

private:

#	ifdef AARCH64_MEM_IO
	static void io_callback(aarch64_address_t addr, int size, void *data, int type_access, void *cdata) {
		otawa::aarch64::IOManager *man = static_cast<otawa::aarch64::IOManager *>(cdata);
		if(type_access == AARCH64_MEM_READ)
			man->read(addr, size, static_cast<t::uint8 *>(data));
		else if(type_access == AARCH64_MEM_WRITE)
			man->write(addr, size, static_cast<t::uint8 *>(data));
		else
			ASSERT(0);
	}
#	endif

	void setup_debug(void) {
		ASSERT(_file);
		if(init)
			return;
		init = true;
		_lines = _file->debugLines();
	}

	otawa::Inst *_start;
	hard::Platform *oplatform;
	aarch64_platform_t *_platform;
	aarch64_memory_t *_memory;
	aarch64_decoder_t *_decoder;
	gel::File *_file;
	gel::DebugLine *_lines;
	int argc;
	char **argv, **envp;
	bool no_stack;
	bool init;
#	ifdef AARCH64_MEM_IO
		otawa::aarch64::IOManager *io_man;
#	endif
};


/****** Instructions implementation ******/

void Inst::dump(io::Output& out) {
	char out_buffer[200];
	aarch64_inst_t *inst = proc.decode_raw(_addr);
	//aarch64_disasm_ben(out_buffer, inst);
	aarch64_disasm(out_buffer, inst);
	proc.free_inst(inst);
	out << out_buffer;
}

void Inst::decodeRegs(void) {

	// Decode instruction
	aarch64_inst_t *inst = proc.decode_raw(address());
	if(inst->ident == AARCH64_UNKNOWN)
		return;

	// get register infos
	aarch64_used_regs_read_t rds;
	aarch64_used_regs_write_t wrs;
	Vector<hard::Register *> reg_in;
	Vector<hard::Register *> reg_out;
	aarch64_used_regs(inst, rds, wrs);
	for (int i = 0; rds[i] != -1; i++ ) {
		hard::Register *r = register_decoder[rds[i]];
		if(r)
			reg_in.add(r);
	}
	for (int i = 0; wrs[i] != -1; i++ ) {
		hard::Register *r = register_decoder[wrs[i]];
		if(r)
			reg_out.add(r);
	}

	// store results
	in_regs = AllocArray<hard::Register *>(reg_in.length());
	for(int i = 0 ; i < reg_in.length(); i++)
		in_regs.set(i, reg_in.get(i));
	out_regs = AllocArray<hard::Register *>(reg_out.length());
	for (int i = 0 ; i < reg_out.length(); i++)
		out_regs.set(i, reg_out.get(i));

	// Free instruction
	aarch64_free_inst(inst);
}


aarch64_address_t BranchInst::decodeTargetAddress(void) {

	// get the target
	aarch64_inst_t *inst= proc.decode_raw(address());
	aarch64_address_t target_addr = aarch64_target(inst);

	// cleanup
	proc.free_inst(inst);
	return target_addr;
}


/**
 */
BranchInst::kind_t BranchInst::kind(void) {
	if(!(_kind & IS_CONTROL)) {
		_kind |= IS_CONTROL;

		if(size() == 4 && prevInst() != nullptr && prevInst()->topAddress() == address()) {

			// get instruction words
			t::uint32 cword, pword;
			process().get(address(), cword);
			process().get(prevInst()->address(), pword);

			// mov lr, pc; mov pc, ri or bx ...
			if((pword & 0x0fffffff) == 0x01a0e00f				// mov pc, lr
			&& (pword & 0xf0000000) == (cword & 0xf0000000)		// same condition
			// mov pc, ri or bx...
			&& ((cword & 0x0ffff000) == 0x01a0f000 || ((cword & 0x0ff000f0) == 0x01200010)))
				_kind |= IS_CALL;
		}

	}
	return _kind;
}

otawa::Inst *BranchInst::target() {
	if (!isTargetDone) {
		isTargetDone = true;
		aarch64_address_t a = decodeTargetAddress();
		if (a)
			_target = process().findInstAt(a);
	}
	return _target;
}


otawa::Inst *Segment::decode(address_t address) {
	return proc.decode(address, this);
}


/**
 */
void Inst::semInsts (sem::Block &block) {

	// get the block
	aarch64_inst_t *inst = proc.decode_raw(address());
	if(inst->ident == AARCH64_UNKNOWN)
		return;
	block.add(sem::seti(15, address().offset()));
	aarch64_sem(inst, block);
	aarch64_free_inst(inst);

	// fix spurious instructions possibly generated with conditional instructions
	for(int i = 0; i < block.length(); i++)
		if(block[i].op == sem::CONT) {
			block.setLength(i);
			break;
		}
}


/**
 */
void Inst::semKernel(sem::Block &block) {
	aarch64_inst_t *inst = proc.decode_raw(address());
	if(inst->ident == AARCH64_UNKNOWN)
		return;
	block.add(sem::seti(15, address().offset()));
	aarch64_ksem(inst, block);
	aarch64_free_inst(inst);
}


Condition Inst::condition(void) {

	// compute condition
	aarch64_inst_t *inst = proc.decode_raw(address());
	sem::cond_t cond;
	switch (aarch64_condition(inst)) {
	case 0: 	cond = sem::EQ; 		break;
	case 1: 	cond = sem::NE; 		break;
	case 2: 	cond = sem::UGE; 		break;
	case 3: 	cond = sem::ULT; 		break;
	case 8: 	cond = sem::UGT; 		break;
	case 9:		cond = sem::ULE; 		break;
	case 10:	cond = sem::GE; 		break;
	case 11:	cond = sem::LT; 		break;
	case 12:	cond = sem::GT; 		break;
	case 13: 	cond = sem::LE; 		break;
	case 14:	cond = sem::NO_COND; 	break;
	default: 	cond = sem::ANY_COND;	break;
	}
	aarch64_free_inst(inst);

	// make the condition
	return Condition(cond, nullptr);// &sr);
}


/****** loader definition ******/

// loader definition
class Loader: public otawa::Loader {
public:
	Loader(void): otawa::Loader(make("aarch64", OTAWA_LOADER_VERSION)
		.version(VERSION)
		.description("loader for ARM 64-bit architecture")
		.license(Manager::copyright)
		.alias("elf_183")) { }

	virtual CString getName(void) const { return "aarch64"; }

	virtual otawa::Process *load(Manager *man, CString path, const PropList& props) {
		otawa::Process *proc = create(man, props);
		if (!proc->loadProgram(path)) {
			delete proc;
			return 0;
		}
		else
			return proc;
	}

	virtual otawa::Process *create(Manager *man, const PropList& props) {
		return new Process(man, new Platform(props), props);
	}
};


// plugin definition
class Plugin: public otawa::ProcessorPlugin {
public:
	Plugin(void): otawa::ProcessorPlugin(make("otawa/aarch64", OTAWA_PROC_VERSION)
		.version(Version(VERSION))
		.description("plugin providing access to ARM64 specific resources")
		.license(Manager::copyright)) { }
};

} }		// otawa::aarch64_2

otawa::aarch64_2::Loader otawa_aarch64_2_loader;
ELM_PLUGIN(otawa_aarch64_2_loader, OTAWA_LOADER_HOOK);
otawa::aarch64_2::Plugin aarch64_2_plugin;
ELM_PLUGIN(aarch64_2_plugin, OTAWA_PROC_HOOK);

